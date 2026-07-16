package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/rs/zerolog/log"
)

// RelayChannel is the small, consumer-side view of RelayClient that
// P2PSession depends on. P2P offers/results/notifications all ride over
// the *relay* control connection (the server only brokers introductions;
// it never sees P2P traffic itself), so P2PSession needs to open streams
// on that connection and know which tunnel/capabilities are in play — but
// nothing else about RelayClient's registration/heartbeat/reconnect
// machinery. Keeping this interface narrow lets P2PSession be constructed
// and tested independently of RelayClient's full surface.
type RelayChannel interface {
	// Mux returns the current relay multiplexer, or nil if not connected.
	Mux() *tunnel.Mux
	// TunnelID returns this client's single-tunnel-mode tunnel ID (empty
	// in multi-tunnel/connect mode or before registration).
	TunnelID() string
	// ServerSupports reports whether the server advertised the given
	// capability; see relayClient.ServerSupports for the exact
	// "unknown capability list" semantics.
	ServerSupports(capability string) bool
}

// statsRecorder lets RelayClient and P2PSession record traffic counters
// into Client's Stats without either component owning Stats itself —
// traffic flows through both the relay and P2P paths, so the aggregate
// is kept on Client (the composition root).
type statsRecorder interface {
	addBytesIn(n uint64)
	addBytesOut(n uint64)
	addRequest()
	addReconnect()
	setConnectionTime(t time.Time)
}

// P2PSession owns the `wormhole connect` / P2P hole-punching lifecycle:
// NAT discovery, ECDH key exchange, hole punching, the multiplexed P2P
// transport, and (in "connect" mode) the local listener that proxies
// straight into a peer's tunnel — completely bypassing the relay for the
// actual data plane. It's independent of RelayClient's own connection
// state except for the narrow RelayChannel view passed into the methods
// that need it.
type P2PSession interface {
	// Init initializes NAT discovery. Failure is non-fatal — the caller
	// falls back to relay-only mode.
	Init(ctx context.Context) error
	// IsP2PMode reports whether a direct P2P connection is currently active.
	IsP2PMode() bool
	// Manager returns the underlying P2P manager (NAT info, mode, ...).
	Manager() *p2p.Manager
	// MaybeSendOffer attempts to send a P2P offer to the server if P2P is
	// enabled, NAT discovery succeeded, and the server advertised support
	// for it. It's a no-op otherwise, so callers don't need to duplicate
	// the eligibility checks themselves.
	MaybeSendOffer(ctx context.Context, relay RelayChannel)
	// HandleNotification handles an inbound P2POfferResponse pushed by the
	// server (another client wants to reach us) and attempts hole punching.
	HandleNotification(ctx context.Context, relay RelayChannel, resp *proto.P2POfferResponse, candidates []string)
	// Close tears down any active P2P transport/connection.
	Close()
}

// p2pSession is the concrete P2PSession implementation.
type p2pSession struct {
	config    Config
	manager   *p2p.Manager
	forwarder localForwarder
	stats     statsRecorder

	// closeCh is Client's shared shutdown signal (shared, not owned).
	closeCh <-chan struct{}

	mu             sync.Mutex
	conn           net.PacketConn     // UDP connection for P2P
	peer           *net.UDPAddr       // Peer's confirmed UDP address
	peerAddr       string             // Peer's advertised signaling address for duplicate-notification suppression
	udpMux         *p2p.UDPMux        // Multiplexed P2P transport
	sessionCloseCh chan struct{}      // Signal to stop the P2P accept loop for the current session
	keyPair        *p2p.KeyPair       // ECDH key pair for this session
	cipher         *p2p.SessionCipher // Derived session cipher for E2E encryption
	mode           uint32             // 1 if using P2P, 0 for relay (atomic)
	// sessionGen is bumped every time the active session is installed or
	// torn down. A session-scoped goroutine (acceptP2PStreams) captures the
	// generation it belongs to and compares before falling back on error,
	// so an error from an already-replaced/closed session can never tear
	// down a newer one it doesn't actually own.
	sessionGen uint64

	// attempting is a singleflight guard: only one hole-punch attempt runs
	// at a time. Both an outgoing offer response and an inbound
	// notification can call attemptP2P concurrently; without this guard,
	// two simultaneously successful attempts would race to install their
	// session state, orphaning whichever one loses (leaked UDPMux, socket,
	// and accept-loop goroutine).
	attempting atomic.Bool

	// activeStreams counts inbound P2P streams currently being serviced,
	// bounded by config.MaxConcurrentStreams — see acceptP2PStreams.
	activeStreams int32
}

// newP2PSession creates a new P2P session. forwarder is used to hand off
// accepted streams to the local service; stats records traffic counters
// for connect-mode direct proxying (proxyConnectConn).
func newP2PSession(config Config, forwarder localForwarder, stats statsRecorder, closeCh <-chan struct{}) *p2pSession {
	p2pConfig := config.P2PConfig
	p2pConfig.Enabled = config.P2PEnabled
	return &p2pSession{
		config:    config,
		manager:   p2p.NewManager(p2pConfig),
		forwarder: forwarder,
		stats:     stats,
		closeCh:   closeCh,
	}
}

func (p *p2pSession) Init(ctx context.Context) error {
	return p.manager.Init(ctx)
}

func (p *p2pSession) Manager() *p2p.Manager {
	return p.manager
}

func (p *p2pSession) IsP2PMode() bool {
	return atomic.LoadUint32(&p.mode) == 1
}

// MaybeSendOffer sends a P2P offer to the server with this client's NAT
// info, gated on P2P being enabled, NAT discovery having succeeded, and
// the server advertising support for it — an older server that
// sent no Capabilities is treated as "unknown" and still attempted. It
// also generates an ECDH key pair and includes the public key for E2E
// encryption.
func (p *p2pSession) MaybeSendOffer(ctx context.Context, relay RelayChannel) {
	if !p.config.P2PEnabled || !p.manager.IsEnabled() || !relay.ServerSupports("p2p") {
		return
	}

	natInfo := p.manager.NATInfo()
	if natInfo == nil {
		return
	}

	keyPair, keyErr := p2p.GenerateKeyPair()
	if keyErr != nil {
		log.Error().Err(keyErr).Msg("Failed to generate ECDH key pair for P2P")
		return
	}

	p.mu.Lock()
	p.keyPair = keyPair
	p.mu.Unlock()

	mux := relay.Mux()
	if mux == nil {
		return
	}
	tunnelID := relay.TunnelID()

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open stream for P2P offer")
		return
	}
	defer stream.Close()

	pubKeyB64 := base64.StdEncoding.EncodeToString(keyPair.Public)

	req := proto.NewP2POfferRequest(
		tunnelID,
		natInfo.Type.String(),
		natInfo.PublicAddr.String(),
		natInfo.LocalAddr.String(),
		pubKeyB64,
		p.config.ConnectTarget,
	)
	data, err := req.Encode()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to encode P2P offer")
		return
	}

	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Debug().Err(err).Msg("Failed to set P2P offer deadline")
		return
	}

	if _, err := stream.WriteContext(ctx, data); err != nil {
		log.Debug().Err(err).Msg("Failed to send P2P offer")
		return
	}

	// Read response. The server may first send zero or more P2PCandidates
	// messages (Symmetric+Symmetric NAT port prediction, see
	// handleP2POffer server-side) before the terminal P2POfferResponse.
	// Both are length-prefixed via proto.WriteControlMessage, so we
	// loop-read framed messages rather than relying on a single raw
	// stream.Read() to capture the whole exchange.
	resp, candidates, readErr := readP2POfferResponse(stream)
	if readErr != nil {
		log.Debug().Err(readErr).Msg("Failed to read P2P offer response")
		return
	}

	p.handleOfferResponse(ctx, relay, resp, candidates)
}

// readP2POfferResponse loop-reads framed control messages from stream until
// the terminal P2POfferResponse arrives, collecting any P2PCandidates sent
// beforehand.
func readP2POfferResponse(stream io.Reader) (*proto.P2POfferResponse, []string, error) {
	var candidates []string
	for {
		msg, readErr := proto.ReadControlMessage(stream)
		if readErr != nil {
			return nil, nil, readErr
		}
		switch {
		case msg.P2PCandidates != nil:
			candidates = append(candidates, msg.P2PCandidates.Candidates...)
		case msg.P2POfferResponse != nil:
			return msg.P2POfferResponse, candidates, nil
		default:
			return nil, nil, fmt.Errorf("unexpected message type %d in P2P offer response", msg.Type)
		}
	}
}

// handleOfferResponse derives the E2E session cipher (if a peer key was
// returned) and kicks off hole punching, or logs the relay-mode fallback.
func (p *p2pSession) handleOfferResponse(ctx context.Context, relay RelayChannel, resp *proto.P2POfferResponse, candidates []string) {
	if !resp.Success || resp.PeerAddr == "" {
		// errP2PNoTarget is the expected, silent outcome for an "expose"
		// mode client (ConnectTarget == ""): it only registered its P2P
		// reachability info and never asked to reach a peer, so this isn't
		// a failure worth surfacing.
		if p.config.ConnectTarget == "" {
			log.Debug().Str("reason", resp.Error).Msg("P2P offer: no peer available, staying in relay mode")
			return
		}
		fmt.Printf("  ❌ wormhole connect: %s (target %q)\n", resp.Error, p.config.ConnectTarget)
		log.Error().Str("target", p.config.ConnectTarget).Str("reason", resp.Error).
			Msg("wormhole connect: failed to match target peer")
		return
	}

	if resp.PeerPublicKey != "" {
		if derivErr := p.deriveP2PCipher(resp.PeerPublicKey); derivErr != nil {
			log.Error().Err(derivErr).Msg("Failed to derive P2P session cipher")
			return
		}
	}

	log.Info().
		Str("peer_addr", resp.PeerAddr).
		Str("peer_nat", resp.PeerNATType).
		Bool("encrypted", p.currentCipher() != nil).
		Int("predicted_candidates", len(candidates)).
		Msg("P2P peer found, attempting connection")

	// Offer sender is the initiator for stream-ID allocation.
	go p.attemptP2P(ctx, relay, resp.PeerAddr, resp.PeerTunnelID, candidates, true)
}

func (p *p2pSession) currentCipher() *p2p.SessionCipher {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cipher
}

// deriveP2PCipher derives the E2E session cipher from the peer's public key.
func (p *p2pSession) deriveP2PCipher(peerPubKeyB64 string) error {
	peerPubBytes, err := base64.StdEncoding.DecodeString(peerPubKeyB64)
	if err != nil {
		return fmt.Errorf("decode peer public key: %w", err)
	}

	p.mu.Lock()
	keyPair := p.keyPair
	p.mu.Unlock()

	if keyPair == nil {
		return fmt.Errorf("local key pair not generated")
	}

	cipher, err := p2p.DeriveSession(keyPair.Private, peerPubBytes)
	if err != nil {
		return fmt.Errorf("derive session: %w", err)
	}

	p.mu.Lock()
	p.cipher = cipher
	p.mu.Unlock()

	log.Info().Msg("P2P E2E session cipher derived successfully")
	return nil
}

// attemptP2P attempts to establish a P2P connection with the given peer address.
// isInitiator must be true on exactly one side; the other side passes false.
// The initiator allocates odd stream IDs; the acceptor uses even IDs.
// peerTunnelID is the peer's tunnel ID to address outgoing stream requests
// to in "connect" mode (see startConnectListener); it's ignored otherwise.
func (p *p2pSession) attemptP2P(ctx context.Context, relay RelayChannel, peerAddr, peerTunnelID string, candidates []string, isInitiator bool) {
	// Singleflight: an outgoing offer response and an inbound notification
	// can both trigger a hole-punch attempt concurrently. Only let one run
	// at a time — a second concurrent attempt is skipped outright rather
	// than racing the first to install its session (see the attempting
	// field doc comment).
	if !p.attempting.CompareAndSwap(false, true) {
		log.Debug().Str("peer_addr", peerAddr).Msg("P2P hole-punch attempt already in progress, skipping duplicate attempt")
		return
	}
	defer p.attempting.Store(false)

	peerEndpoint, err := parseP2PEndpoint(peerAddr)
	if err != nil {
		log.Error().Err(err).Str("peer_addr", peerAddr).Msg("Failed to parse peer address")
		p.sendP2PResult(ctx, relay, false, "", err.Error())
		return
	}
	if p.hasActiveSessionFor(peerAddr, peerEndpoint) {
		log.Debug().Str("peer_addr", peerAddr).Msg("P2P session already active for peer, skipping duplicate notification")
		return
	}
	candidateEndpoints := parseP2PEndpointCandidates(candidates)

	log.Info().
		Str("peer", peerAddr).
		Bool("initiator", isInitiator).
		Int("candidates", len(candidateEndpoints)).
		Msg("Attempting P2P hole punching")

	cipher := p.currentCipher()

	conn, confirmedPeer, p2pErr := p.manager.AttemptP2PWithCandidates(ctx, peerEndpoint, candidateEndpoints, cipher)
	if p2pErr != nil {
		log.Warn().Err(p2pErr).Msg("P2P hole punching failed")
		p.sendP2PResult(ctx, relay, false, "", p2pErr.Error())
		return
	}

	mux := p2p.NewUDPMux(conn, confirmedPeer, p2p.DefaultTransportConfig(), cipher, isInitiator)
	closeSig := make(chan struct{})

	gen := p.installSession(peerAddr, conn, confirmedPeer, mux, closeSig)

	peerAddrStr := confirmedPeer.String()
	encrypted := cipher != nil
	log.Info().
		Str("peer", peerAddrStr).
		Str("local", conn.LocalAddr().String()).
		Bool("encrypted", encrypted).
		Bool("initiator", isInitiator).
		Msg("P2P connection established (mux)")

	p.sendP2PResult(ctx, relay, true, peerAddrStr, "")

	go p.acceptP2PStreams(ctx, mux, closeSig, gen)

	if encrypted {
		fmt.Printf("  🎉 P2P Mode: Direct connection to %s (encrypted)\n", peerAddrStr)
	} else {
		fmt.Printf("  🎉 P2P Mode: Direct connection to %s\n", peerAddrStr)
	}

	// "Connect" mode: we're the initiator reaching a specific peer tunnel,
	// so also open a local listener that proxies each accepted connection
	// to the peer over this P2P mux (see startConnectListener).
	if isInitiator && p.config.ConnectTarget != "" {
		go p.startConnectListener(ctx, mux, peerTunnelID, closeSig)
	}
}

// installSession replaces the currently active P2P session (if any) with a
// newly established one and returns the new session's generation number
// for the caller to hand to its accept-loop goroutine (see sessionGen).
// A previous session may still be active — e.g. a slow-to-unwind accept
// loop from an earlier attempt, or a deliberate re-punch after the peer's
// address changed — so this always tears it down first via teardownLocked,
// which is what guarantees its UDPMux/socket/accept-loop goroutine is never
// orphaned by the replacement. Split out from attemptP2P so the
// teardown-then-install behavior is unit-testable without a real hole punch.
func (p *p2pSession) installSession(peerAddr string, conn net.PacketConn, peer *net.UDPAddr, mux *p2p.UDPMux, closeSig chan struct{}) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	// teardownLocked already bumps sessionGen, which is all the "new
	// generation" a freshly installed session needs — no other live
	// goroutine can be holding that value yet.
	p.teardownLocked()
	p.conn = conn
	p.peer = peer
	p.peerAddr = peerAddr
	p.udpMux = mux
	p.sessionCloseCh = closeSig
	atomic.StoreUint32(&p.mode, 1)
	return p.sessionGen
}

func (p *p2pSession) hasActiveSessionFor(peerAddr string, peerEndpoint p2p.Endpoint) bool {
	if atomic.LoadUint32(&p.mode) != 1 {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sessionCloseCh == nil || p.conn == nil {
		return false
	}
	select {
	case <-p.sessionCloseCh:
		return false
	default:
	}
	if p.peerAddr != "" {
		return p.peerAddr == peerAddr
	}
	if p.peer == nil || p.peer.Port != peerEndpoint.Port {
		return false
	}
	peerIP := net.ParseIP(peerEndpoint.IP)
	if peerIP == nil {
		return p.peer.IP.String() == peerEndpoint.IP
	}
	return p.peer.IP.Equal(peerIP)
}

// acceptP2PStreams accepts incoming multiplexed P2P streams and proxies each
// one to the local service — exactly like the relay path but over P2P UDP.
// gen is the session generation this loop was spawned for (see
// p2pSession.sessionGen); it's used to avoid falling back on behalf of a
// session that has since been replaced or explicitly closed.
//
// Each accepted stream is serviced by its own goroutine, bounded by
// config.MaxConcurrentStreams exactly like relayClient.acceptStreams — a
// P2P peer is just as capable of opening unbounded streams as a
// compromised relay server would be.
func (p *p2pSession) acceptP2PStreams(ctx context.Context, mux *p2p.UDPMux, closeSig chan struct{}, gen uint64) {
	log.Info().Msg("P2P accept loop started")
	defer log.Info().Msg("P2P accept loop stopped")

	for {
		select {
		case <-closeSig:
			return
		case <-p.closeCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		stream, err := mux.AcceptStream()
		if err != nil {
			if mux.IsClosed() {
				p.fallbackFromStaleSession(gen, "P2P mux closed")
				return
			}
			log.Warn().Err(err).Msg("P2P accept stream error, falling back to relay")
			p.fallbackFromStaleSession(gen, "P2P accept error")
			return
		}

		if p.config.MaxConcurrentStreams > 0 &&
			!tryIncrementBounded32(&p.activeStreams, int32(p.config.MaxConcurrentStreams)) {
			log.Warn().Int("limit", p.config.MaxConcurrentStreams).
				Msg("Concurrent stream limit reached, dropping inbound P2P stream")
			_ = stream.Close()
			continue
		}

		// Each stream carries one logical request: read the StreamRequest
		// header (length-prefixed protobuf) then proxy to local service.
		go func(s *p2p.UDPStream) {
			defer func() {
				_ = s.Close()
				atomic.AddInt32(&p.activeStreams, -1)
			}()

			msg, readErr := proto.ReadControlMessage(s)
			if readErr != nil {
				log.Error().Err(readErr).Uint32("stream_id", s.StreamID()).
					Msg("P2P: read stream request failed")
				return
			}
			if msg.StreamRequest == nil {
				log.Warn().Uint32("stream_id", s.StreamID()).
					Msg("P2P: expected StreamRequest, got other message type")
				return
			}

			p.stats.addRequest()
			p.forwarder.forwardToLocal(ctx, s, msg.StreamRequest)
		}(stream)
	}
}

// startConnectListener implements the client side of `wormhole connect`: it
// opens a local TCP listener on Config.LocalHost:LocalPort and, for every
// accepted connection, proxies it over the P2P mux directly to the peer's
// tunnel identified by peerTunnelID — completely bypassing the server
// relay for the actual traffic (the server was only used for signaling).
// There is intentionally no relay fallback here: connect mode only makes
// sense when a direct P2P path to the peer exists, so a lost P2P mux closes
// the listener rather than silently falling back to a relay path the
// server has no way to support for an unregistered connect-mode session.
func (p *p2pSession) startConnectListener(ctx context.Context, mux *p2p.UDPMux, peerTunnelID string, closeSig chan struct{}) {
	host := p.config.LocalHost
	if host == "" {
		host = defaultLocalHost
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.config.LocalPort))

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, protocolTCP, addr)
	if err != nil {
		log.Error().Err(err).Str("addr", addr).Msg("wormhole connect: failed to open local listener")
		fmt.Printf("  ❌ wormhole connect: failed to listen on %s: %v\n", addr, err)
		return
	}
	defer ln.Close()

	fmt.Printf("  🔗 wormhole connect: forwarding %s -> peer tunnel %s (direct P2P)\n", addr, peerTunnelID)
	log.Info().Str("addr", addr).Str("peer_tunnel_id", peerTunnelID).Msg("wormhole connect: listening for local connections")

	go func() {
		select {
		case <-closeSig:
		case <-p.closeCh:
		case <-ctx.Done():
		}
		_ = ln.Close()
	}()

	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		go p.proxyConnectConn(mux, conn, peerTunnelID)
	}
}

// proxyConnectConn opens one P2P stream per accepted local connection,
// sends a StreamRequest addressed to the peer's tunnel (mirroring what the
// server does for a relay-mode TCP tunnel, see Server.handleTCPConnection),
// and proxies bytes bidirectionally until either side closes.
func (p *p2pSession) proxyConnectConn(mux *p2p.UDPMux, localConn net.Conn, peerTunnelID string) {
	defer localConn.Close()

	stream, err := mux.OpenStream()
	if err != nil {
		log.Error().Err(err).Msg("wormhole connect: failed to open P2P stream")
		return
	}
	defer stream.Close()

	streamReq := proto.NewStreamRequest(peerTunnelID, generateRequestID(), localConn.RemoteAddr().String(), proto.ProtocolTCP)
	if writeErr := proto.WriteControlMessage(stream, streamReq); writeErr != nil {
		log.Error().Err(writeErr).Msg("wormhole connect: failed to send stream request")
		return
	}

	// p2p.UDPStream has no half-close, so — as in Server.handleTCPConnection
	// and ProxyService.handleWebSocket — close both ends as soon as
	// either direction finishes to unblock the other immediately rather
	// than leaving it running until the deferred closes above happen to
	// fire when this function eventually returns.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, copyErr := copyWithPooledBuffer(stream, localConn)
		if n > 0 {
			p.stats.addBytesOut(uint64(n)) // #nosec G115
		}
		if copyErr != nil {
			log.Debug().Err(copyErr).Msg("wormhole connect: copy local->peer failed")
		}
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		n, copyErr := copyWithPooledBuffer(localConn, stream)
		if n > 0 {
			p.stats.addBytesIn(uint64(n))
		}
		if copyErr != nil {
			log.Debug().Err(copyErr).Msg("wormhole connect: copy peer->local failed")
		}
		_ = localConn.Close()
	}()

	wg.Wait()
	p.stats.addRequest()
}

// generateRequestID returns a random hex identifier for a StreamRequest
// originated by this client (only used in "connect" mode — normally the
// server originates StreamRequests and assigns the RequestID itself).
func generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// parseP2PEndpoint parses a string address into a p2p.Endpoint.
func parseP2PEndpoint(addr string) (p2p.Endpoint, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return p2p.Endpoint{}, fmt.Errorf("invalid address: %w", err)
	}
	port := 0
	if _, scanErr := fmt.Sscanf(portStr, "%d", &port); scanErr != nil {
		return p2p.Endpoint{}, fmt.Errorf("invalid port: %w", scanErr)
	}
	return p2p.Endpoint{IP: host, Port: port}, nil
}

func parseP2PEndpointCandidates(candidates []string) []p2p.Endpoint {
	endpoints := make([]p2p.Endpoint, 0, len(candidates))
	for _, candidate := range candidates {
		endpoint, err := parseP2PEndpoint(candidate)
		if err != nil {
			log.Debug().Err(err).Str("candidate", candidate).Msg("Skipping invalid P2P candidate endpoint")
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// sendP2PResult sends the P2P connection result to the server.
func (p *p2pSession) sendP2PResult(ctx context.Context, relay RelayChannel, success bool, peerAddr, errMsg string) {
	mux := relay.Mux()
	if mux == nil || mux.IsClosed() {
		return
	}
	tunnelID := relay.TunnelID()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open stream for P2P result")
		return
	}
	defer stream.Close()

	msg := proto.NewP2PResult(tunnelID, success, peerAddr, errMsg)
	data, err := msg.Encode()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to encode P2P result")
		return
	}

	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Debug().Err(err).Msg("Failed to set P2P result deadline")
		return
	}

	if _, err := stream.WriteContext(ctx, data); err != nil {
		log.Debug().Err(err).Msg("Failed to send P2P result")
		return
	}

	log.Debug().
		Bool("success", success).
		Str("peer_addr", peerAddr).
		Msg("P2P result sent to server")
}

// HandleNotification handles incoming P2P notifications from the server.
// This is called when another client wants to establish a P2P connection
// with us. candidates carries any predicted peer ports received alongside
// the offer response (Symmetric+Symmetric NAT port prediction); they are
// consumed by the hole-punch attempt.
func (p *p2pSession) HandleNotification(ctx context.Context, relay RelayChannel, resp *proto.P2POfferResponse, candidates []string) {
	if !resp.Success || resp.PeerAddr == "" {
		return
	}

	log.Info().
		Str("peer_addr", resp.PeerAddr).
		Str("peer_nat", resp.PeerNATType).
		Bool("has_peer_key", resp.PeerPublicKey != "").
		Int("predicted_candidates", len(candidates)).
		Msg("Received P2P notification from server, attempting connection")

	// Generate our ECDH key pair if not already done.
	p.mu.Lock()
	if p.keyPair == nil {
		keyPair, keyErr := p2p.GenerateKeyPair()
		if keyErr != nil {
			p.mu.Unlock()
			log.Error().Err(keyErr).Msg("Failed to generate ECDH key pair for P2P notification")
			return
		}
		p.keyPair = keyPair
	}
	p.mu.Unlock()

	// Derive session cipher from peer's public key if available.
	if resp.PeerPublicKey != "" {
		if derivErr := p.deriveP2PCipher(resp.PeerPublicKey); derivErr != nil {
			log.Error().Err(derivErr).Msg("Failed to derive P2P session cipher from notification")
			return
		}
	}

	// Notified side is the acceptor for stream-ID allocation; it never
	// initiates outgoing connect-mode streams, so peerTunnelID is unused.
	go p.attemptP2P(ctx, relay, resp.PeerAddr, "", candidates, false)
}

// teardownLocked closes every resource belonging to the currently active
// P2P session (signal channel first so accept loops unblock, then the mux,
// then the raw connection) and bumps sessionGen so any goroutine still
// holding the old generation number knows its session is gone. Callers
// must hold p.mu. It's deliberately idempotent (safe to call on an already-
// torn-down session) so both fallbackToRelayLocked and attemptP2P's
// teardown-before-install can share it unconditionally.
func (p *p2pSession) teardownLocked() {
	if p.sessionCloseCh != nil {
		close(p.sessionCloseCh)
		p.sessionCloseCh = nil
	}
	if p.udpMux != nil {
		_ = p.udpMux.Close()
		p.udpMux = nil
	}
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
	p.peer = nil
	p.peerAddr = ""
	atomic.StoreUint32(&p.mode, 0)
	p.sessionGen++
}

// fallbackToRelay switches from P2P back to relay mode unconditionally.
// Use this for callers that want to abandon P2P regardless of which
// session generation is currently active (explicit shutdown paths, tests).
// A session-scoped goroutine (the P2P accept loop) should instead use
// fallbackFromStaleSession, which checks it still owns the active session
// before tearing anything down.
func (p *p2pSession) fallbackToRelay(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fallbackToRelayLocked(reason)
}

// fallbackFromStaleSession is fallbackToRelay's session-aware counterpart,
// called by acceptP2PStreams when its mux errors. Because attemptP2P tears
// down and replaces the active session before installing a new one (see
// its doc comment), and a concurrent notification/offer can trigger a
// fresh attempt while an old accept loop is still unwinding, gen guards
// against tearing down a session this goroutine doesn't actually own
// anymore: if sessionGen has moved on, the error is stale and ignored.
func (p *p2pSession) fallbackFromStaleSession(gen uint64, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sessionGen != gen {
		log.Debug().Str("reason", reason).Msg("P2P session already replaced or closed, ignoring stale accept-loop error")
		return
	}
	p.fallbackToRelayLocked(reason)
}

// fallbackToRelayLocked is the shared implementation behind fallbackToRelay
// and fallbackFromStaleSession. Callers must hold p.mu.
func (p *p2pSession) fallbackToRelayLocked(reason string) {
	// Only fallback if currently in P2P mode.
	if atomic.LoadUint32(&p.mode) != 1 {
		return
	}

	log.Info().Str("reason", reason).Msg("Falling back to relay mode")

	p.teardownLocked()
	// Clear crypto state so a fresh key pair is generated on next attempt.
	p.keyPair = nil
	p.cipher = nil

	p.manager.FallbackToRelay(reason)

	fmt.Printf("  ⚠️  Switched to Relay mode: %s\n", reason)
}

// Close tears down any active P2P transport/connection.
func (p *p2pSession) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.teardownLocked()
}
