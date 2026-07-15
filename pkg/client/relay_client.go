package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/lucientong/wormhole/pkg/version"
	"github.com/rs/zerolog/log"
)

// RelayClient owns the control-plane connection to the wormhole server:
// dialing (with optional TLS), authentication, tunnel registration
// (single- and multi-tunnel), heartbeating, accepting inbound streams and
// dispatching them to the local service, and the reconnect loop that ties
// it all together for the lifetime of the client process.
type RelayClient interface {
	// Run dials the server and blocks, transparently reconnecting on
	// connection loss, until ctx is done, Close is called, or
	// MaxReconnectAttempts is exhausted.
	Run(ctx context.Context) error
	// Close tears down the current connection (mux + underlying conn).
	Close()

	IsConnected() bool
	// Mux returns the current relay multiplexer, or nil if not connected.
	Mux() *tunnel.Mux
	TunnelID() string
	PublicURL() string
	SessionID() string
	ServerSupports(capability string) bool
	// ResolveLocalAddr returns the local host/port a StreamRequest tagged
	// with tunnelID should be forwarded to (multi-tunnel aware).
	ResolveLocalAddr(tunnelID string) (host string, port int)

	ListActiveTunnels() []ActiveTunnel
	ReloadTunnels(ctx context.Context, newDefs []TunnelDef)
	CreateTunnel(ctx context.Context, def TunnelDef) (*ActiveTunnel, error)
	DeleteTunnel(ctx context.Context, name string) error
	CloseTunnel(ctx context.Context, tunnelID, reason string) error
	// CloseAllTunnels gracefully closes every active tunnel (single- and
	// multi-tunnel mode), best-effort, ahead of a full shutdown.
	CloseAllTunnels(ctx context.Context, reason string)
	RequestStats(ctx context.Context) (*proto.StatsResponse, error)
}

// relayClient is the concrete RelayClient implementation.
type relayClient struct {
	config Config

	forwarder localForwarder
	stats     statsRecorder
	// p2pStatus is read-only, used only to enrich the post-registration
	// status banner with NAT/traversability info — RelayClient otherwise
	// has no dependency on the P2P subsystem.
	p2pStatus *p2p.Manager

	// closeCh is Client's shared shutdown signal (shared, not owned).
	closeCh <-chan struct{}
	// wg is Client's shared goroutine-tracking WaitGroup (shared, not owned).
	wg *sync.WaitGroup

	// afterConnect, if set, is invoked (wg-tracked) once per successful
	// connect+register cycle, right before blocking on the connection —
	// wired by Client to kick off an async P2P offer attempt without
	// RelayClient needing to know P2PSession exists.
	afterConnect func(ctx context.Context)
	// onNotification, if set, is invoked when the server pushes a
	// P2POfferResponse over an inbound stream (another client wants to
	// reach us) — wired by Client to P2PSession.HandleNotification.
	onNotification func(ctx context.Context, relay RelayChannel, resp *proto.P2POfferResponse, candidates []string)

	mu                 sync.Mutex
	conn               net.Conn
	mux                *tunnel.Mux
	connected          uint32
	publicURL          string
	tunnelID           string
	sessionID          string // Server-assigned session ID (for reconnect awareness).
	serverCapabilities []string

	// Multi-tunnel state (populated after registration). Single-tunnel
	// mode uses publicURL/tunnelID directly; multi-tunnel mode populates
	// this map.
	activeTunnels   map[string]*ActiveTunnel // name → active tunnel
	activeTunnelsMu sync.RWMutex

	// activeStreams counts inbound streams currently being serviced by
	// handleStream, bounded by config.MaxConcurrentStreams. Without
	// this, a compromised or misbehaving server could
	// open unbounded streams on the relay Mux and exhaust this client's
	// goroutines/memory.
	activeStreams int32
}

// newRelayClient creates a new relay client. forwarder hands off accepted
// StreamRequests to the local service; stats records traffic/connection
// counters; p2pStatus (optional) is read for the status banner only.
func newRelayClient(config Config, forwarder localForwarder, stats statsRecorder, p2pStatus *p2p.Manager, closeCh <-chan struct{}, wg *sync.WaitGroup) *relayClient {
	return &relayClient{
		config:        config,
		forwarder:     forwarder,
		stats:         stats,
		p2pStatus:     p2pStatus,
		closeCh:       closeCh,
		wg:            wg,
		activeTunnels: make(map[string]*ActiveTunnel),
	}
}

// setAfterConnect wires the post-connect hook (internal composition-root
// wiring, not part of the RelayClient interface).
func (r *relayClient) setAfterConnect(fn func(ctx context.Context)) {
	r.afterConnect = fn
}

// setNotificationHandler wires the inbound-P2P-notification hook
// (internal composition-root wiring, not part of the RelayClient interface).
func (r *relayClient) setNotificationHandler(fn func(ctx context.Context, relay RelayChannel, resp *proto.P2POfferResponse, candidates []string)) {
	r.onNotification = fn
}

// Run connects to the server with automatic reconnection.
func (r *relayClient) Run(ctx context.Context) error {
	interval := r.config.ReconnectInterval
	attempts := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.closeCh:
			return nil
		default:
		}

		if err := r.connect(ctx); err != nil {
			log.Error().Err(err).Msg("Connection failed")

			attempts++
			if r.config.MaxReconnectAttempts > 0 && attempts >= r.config.MaxReconnectAttempts {
				return fmt.Errorf("max reconnection attempts reached")
			}

			r.stats.addReconnect()

			// Exponential backoff
			select {
			case <-time.After(interval):
				interval = time.Duration(float64(interval) * r.config.ReconnectBackoff)
				if interval > r.config.MaxReconnectInterval {
					interval = r.config.MaxReconnectInterval
				}
			case <-ctx.Done():
				return ctx.Err()
			case <-r.closeCh:
				return nil
			}
			continue
		}

		// Connected successfully
		attempts = 0
		interval = r.config.ReconnectInterval

		r.handleConnection(ctx)

		// Connection lost, will reconnect
		log.Warn().
			Str("tunnel_id", r.TunnelID()).
			Msg("Connection lost, reconnecting (tunnel will be re-registered)...")
	}
}

// connect establishes a connection to the server.
func (r *relayClient) connect(ctx context.Context) error {
	// Dial server (plain TCP or TLS).
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	var conn net.Conn
	var err error

	if r.config.TLSEnabled {
		tlsConfig, tlsErr := r.buildTLSConfig()
		if tlsErr != nil {
			return fmt.Errorf("build TLS config: %w", tlsErr)
		}
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, protocolTCP, r.config.ServerAddr)
	} else {
		conn, err = dialer.DialContext(ctx, protocolTCP, r.config.ServerAddr)
	}
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}

	// Create multiplexer
	mux, err := tunnel.Client(conn, r.config.MuxConfig)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create mux: %w", err)
	}

	r.mu.Lock()
	r.conn = conn
	r.mux = mux
	r.mu.Unlock()
	r.stats.setConnectionTime(time.Now())

	atomic.StoreUint32(&r.connected, 1)

	log.Info().Str("server", r.config.ServerAddr).Msg("Connected to server")

	// Phase 5: Authenticate if token is provided.
	if r.config.Token != "" {
		if err := r.authenticateWithRefresh(ctx); err != nil {
			_ = mux.Close()
			_ = conn.Close()
			return fmt.Errorf("authenticate: %w", err)
		}
	}

	// "Connect" mode (`wormhole connect <target>`) doesn't expose a tunnel
	// of its own — it only needs the control connection to exchange P2P
	// signaling with the server, so tunnel registration is skipped entirely.
	if r.config.ConnectTarget != "" {
		return nil
	}

	// Register tunnel(s).
	if len(r.config.Tunnels) > 0 {
		if err := r.registerAllTunnels(ctx); err != nil {
			_ = mux.Close()
			_ = conn.Close()
			return fmt.Errorf("register tunnels: %w", err)
		}
	} else {
		if err := r.registerTunnel(ctx); err != nil {
			_ = mux.Close()
			_ = conn.Close()
			return fmt.Errorf("register tunnel: %w", err)
		}
	}

	return nil
}

// buildTLSConfig builds a *tls.Config from the client configuration.
func (r *relayClient) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if r.config.TLSInsecure {
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- user explicitly opted in via --tls-insecure
	}

	// Load custom CA certificate if specified.
	if r.config.TLSCACert != "" {
		caCert, err := os.ReadFile(r.config.TLSCACert) // #nosec G304 -- path from CLI flag, not untrusted input
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", r.config.TLSCACert)
		}
		tlsConfig.RootCAs = pool
	}

	// Extract hostname from server address for SNI.
	host, _, err := net.SplitHostPort(r.config.ServerAddr)
	if err != nil {
		// If no port in address, use as-is.
		host = r.config.ServerAddr
	}
	tlsConfig.ServerName = host

	return tlsConfig, nil
}

// ServerSupports reports whether the server advertised the given
// capability in its AuthResponse. An empty/nil capabilities list (no
// AuthResponse.Capabilities received yet, or an older server that
// predates this field) is treated as "unknown" and returns true, so
// behavior against older servers is unaffected — this only actively
// gates behavior once a server has explicitly told us its feature set.
func (r *relayClient) ServerSupports(name string) bool {
	r.mu.Lock()
	caps := r.serverCapabilities
	r.mu.Unlock()

	if len(caps) == 0 {
		return true
	}
	for _, capability := range caps {
		if capability == name {
			return true
		}
	}
	return false
}

// capabilities returns the set of optional protocol features this client
// build actually supports/wants, advertised to the server via
// AuthRequest.Capabilities. "multi-tunnel" is unconditional;
// "p2p" reflects whether P2P is enabled in this client's config.
func (r *relayClient) capabilities() []string {
	caps := []string{"multi-tunnel"}
	if r.config.P2PEnabled {
		caps = append(caps, "p2p")
	}
	return caps
}

// authenticateWithRefresh calls authenticate() and, if the server rejects the
// current token and Config.OnAuthFailure is set (e.g. wired to an OAuth2
// refresh_token grant by the CLI layer), attempts to obtain a fresh token
// and retries authentication exactly once. This lets a long-lived client
// survive an OIDC access token expiring mid-session or across a reconnect
// without requiring the user to run `wormhole login` again.
func (r *relayClient) authenticateWithRefresh(ctx context.Context) error {
	err := r.authenticate(ctx)
	if err == nil || r.config.OnAuthFailure == nil {
		return err
	}

	newToken, ok := r.config.OnAuthFailure(ctx)
	if !ok || newToken == "" {
		return err
	}

	log.Info().Msg("Auth token refreshed after rejection, retrying authentication")
	r.mu.Lock()
	r.config.Token = newToken
	r.mu.Unlock()

	return r.authenticate(ctx)
}

// authenticate sends an AuthRequest to the server and validates the response.
func (r *relayClient) authenticate(ctx context.Context) error {
	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()

	if mux == nil {
		return fmt.Errorf("not connected")
	}

	// Open auth stream.
	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()

	// Set timeout for auth handshake.
	if deadlineErr := stream.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
		return fmt.Errorf("set auth deadline: %w", deadlineErr)
	}

	// Send auth request, advertising this client's real feature set
	// rather than leaving Capabilities empty.
	req := proto.NewAuthRequest(r.config.Token, version.Short(), r.config.Subdomain)
	req.AuthRequest.Capabilities = r.capabilities()
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode auth request: %w", err)
	}

	if _, writeErr := stream.WriteContext(ctx, data); writeErr != nil {
		return fmt.Errorf("write auth request: %w", writeErr)
	}

	// Read auth response.
	buf := make([]byte, 4096)
	n, err := stream.ReadContext(ctx, buf)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}

	if msg.AuthResponse == nil {
		return fmt.Errorf("unexpected response type (expected auth response)")
	}

	resp := msg.AuthResponse
	if !resp.Success {
		return fmt.Errorf("server rejected authentication: %s", resp.Error)
	}

	// Use subdomain from auth response if provided.
	if resp.Subdomain != "" {
		r.mu.Lock()
		r.config.Subdomain = resp.Subdomain
		r.mu.Unlock()
	}

	// Save session ID for reconnect awareness.
	if resp.SessionID != "" {
		r.mu.Lock()
		r.sessionID = resp.SessionID
		r.mu.Unlock()
	}

	// Remember what the server actually supports so optional
	// behavior, like attempting a P2P offer, can be gated on it instead
	// of assumed. An empty list means an older server that predates this
	// field — treated as "unknown", not "supports nothing" (see
	// ServerSupports).
	r.mu.Lock()
	r.serverCapabilities = resp.Capabilities
	r.mu.Unlock()

	log.Info().
		Str("session_id", resp.SessionID).
		Str("subdomain", resp.Subdomain).
		Strs("server_capabilities", resp.Capabilities).
		Msg("Authenticated with server")

	return nil
}

// registerTunnel registers a tunnel with the server.
func (r *relayClient) registerTunnel(ctx context.Context) error {
	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()

	if mux == nil {
		return fmt.Errorf("not connected")
	}

	// Open control stream
	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Send register request
	if r.config.LocalPort < 0 || r.config.LocalPort > 65535 {
		return fmt.Errorf("invalid local port: %d", r.config.LocalPort)
	}
	p := parseProtocol(r.config.Protocol)
	req := proto.NewRegisterRequest(uint32(r.config.LocalPort), p, r.config.Subdomain, r.config.Hostname, r.config.PathPrefix) // #nosec G115
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	if _, writeErr := stream.WriteContext(ctx, data); writeErr != nil {
		return fmt.Errorf("write request: %w", writeErr)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := stream.ReadContext(ctx, buf)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if msg.RegisterResponse == nil {
		return fmt.Errorf("unexpected response type")
	}

	resp := msg.RegisterResponse
	if !resp.Success {
		return fmt.Errorf("registration failed: %s", resp.Error)
	}

	r.mu.Lock()
	r.tunnelID = resp.TunnelID
	r.publicURL = resp.PublicURL
	r.mu.Unlock()

	log.Info().
		Str("tunnel_id", resp.TunnelID).
		Str("public_url", resp.PublicURL).
		Msg("Tunnel registered")

	fmt.Printf("\n")
	fmt.Printf("  🕳️  Wormhole is ready!\n")
	fmt.Printf("\n")
	fmt.Printf("  Forwarding:   %s -> http://%s:%d\n", resp.PublicURL, r.config.LocalHost, r.config.LocalPort)
	fmt.Printf("  Version:      %s\n", version.Short())
	switch {
	case r.p2pStatus != nil && r.p2pStatus.NATInfo() != nil:
		info := r.p2pStatus.NATInfo()
		traversable := info.Type.IsTraversable()
		fmt.Printf("  NAT Type:     %s\n", info.Type)
		fmt.Printf("  Public Addr:  %s\n", info.PublicAddr)
		if traversable {
			fmt.Printf("  Traversable:  ✅ Yes (P2P direct connections possible)\n")
		} else {
			fmt.Printf("  Traversable:  ⚠️  Limited (P2P only with non-Symmetric peers)\n")
		}
		fmt.Printf("  P2P Mode:     %s\n", r.p2pStatus.Mode())
	case r.config.P2PEnabled:
		fmt.Printf("  P2P:          ⚠️  NAT discovery failed, using relay mode\n")
	default:
		fmt.Printf("  P2P:          Disabled\n")
	}
	fmt.Printf("\n")
	fmt.Printf("  Tip: Run 'wormhole nat-check' for detailed NAT diagnostics\n")
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop\n")
	fmt.Printf("\n")

	return nil
}

// registerAllTunnels registers all tunnels from Config.Tunnels.
// It is used in multi-tunnel (config file) mode.
func (r *relayClient) registerAllTunnels(ctx context.Context) error {
	r.activeTunnelsMu.Lock()
	// Reset active tunnels map for this connection cycle.
	r.activeTunnels = make(map[string]*ActiveTunnel, len(r.config.Tunnels))
	r.activeTunnelsMu.Unlock()

	for _, def := range r.config.Tunnels {
		at, err := r.registerOneTunnel(ctx, def)
		if err != nil {
			log.Error().Err(err).Str("tunnel", def.Name).Msg("Failed to register tunnel")
			continue // Best effort: skip failed tunnels.
		}
		r.activeTunnelsMu.Lock()
		r.activeTunnels[def.Name] = at
		r.activeTunnelsMu.Unlock()
	}

	r.activeTunnelsMu.RLock()
	count := len(r.activeTunnels)
	r.activeTunnelsMu.RUnlock()

	if count == 0 {
		return fmt.Errorf("all tunnel registrations failed")
	}

	r.printMultiTunnelBanner()
	return nil
}

// registerOneTunnel registers a single tunnel definition and returns its state.
func (r *relayClient) registerOneTunnel(ctx context.Context, def TunnelDef) (*ActiveTunnel, error) {
	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()

	if mux == nil {
		return nil, fmt.Errorf("not connected")
	}

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if def.LocalPort < 0 || def.LocalPort > 65535 {
		return nil, fmt.Errorf("invalid local port: %d", def.LocalPort)
	}

	p := parseProtocol(def.Protocol)
	req := proto.NewRegisterRequest(uint32(def.LocalPort), p, def.Subdomain, def.Hostname, def.PathPrefix) // #nosec G115
	data, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	if _, writeErr := stream.WriteContext(ctx, data); writeErr != nil {
		return nil, fmt.Errorf("write request: %w", writeErr)
	}

	buf := make([]byte, 4096)
	n, err := stream.ReadContext(ctx, buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if msg.RegisterResponse == nil {
		return nil, fmt.Errorf("unexpected response type")
	}

	resp := msg.RegisterResponse
	if !resp.Success {
		return nil, fmt.Errorf("registration failed: %s", resp.Error)
	}

	log.Info().
		Str("name", def.Name).
		Str("tunnel_id", resp.TunnelID).
		Str("public_url", resp.PublicURL).
		Int("local_port", def.LocalPort).
		Msg("Tunnel registered")

	return &ActiveTunnel{
		Def:       def,
		TunnelID:  resp.TunnelID,
		PublicURL: resp.PublicURL,
		TCPPort:   resp.TCPPort,
	}, nil
}

// printMultiTunnelBanner prints a startup banner listing all active tunnels.
func (r *relayClient) printMultiTunnelBanner() {
	r.activeTunnelsMu.RLock()
	defer r.activeTunnelsMu.RUnlock()

	fmt.Printf("\n")
	fmt.Printf("  🕳️  Wormhole is ready! (%d tunnel(s) active)\n", len(r.activeTunnels))
	fmt.Printf("\n")
	for name, at := range r.activeTunnels {
		fmt.Printf("  %-12s %s  →  %s:%d\n", name+":", at.PublicURL, at.Def.LocalHost, at.Def.LocalPort)
	}
	fmt.Printf("\n  Press Ctrl+C to stop\n\n")
}

// ListActiveTunnels returns a copy of the currently active tunnels.
func (r *relayClient) ListActiveTunnels() []ActiveTunnel {
	r.activeTunnelsMu.RLock()
	defer r.activeTunnelsMu.RUnlock()

	out := make([]ActiveTunnel, 0, len(r.activeTunnels))
	for _, at := range r.activeTunnels {
		out = append(out, *at)
	}
	// In single-tunnel mode also expose the main tunnel.
	r.mu.Lock()
	tunnelID, publicURL := r.tunnelID, r.publicURL
	r.mu.Unlock()
	if len(out) == 0 && tunnelID != "" {
		out = append(out, ActiveTunnel{
			Def: TunnelDef{
				Name:      "default",
				LocalPort: r.config.LocalPort,
				LocalHost: r.config.LocalHost,
				Protocol:  r.config.Protocol,
			},
			TunnelID:  tunnelID,
			PublicURL: publicURL,
		})
	}
	return out
}

// ReloadTunnels updates the active tunnel set based on a new list of definitions.
// New tunnels are registered; removed tunnels are closed via CloseRequest.
// This is designed to be called when a SIGHUP reloads the config file.
func (r *relayClient) ReloadTunnels(ctx context.Context, newDefs []TunnelDef) {
	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()
	if mux == nil || mux.IsClosed() {
		log.Warn().Msg("ReloadTunnels: not connected, skipping")
		return
	}

	r.activeTunnelsMu.RLock()
	current := make(map[string]*ActiveTunnel, len(r.activeTunnels))
	for k, v := range r.activeTunnels {
		current[k] = v
	}
	r.activeTunnelsMu.RUnlock()

	newSet := make(map[string]TunnelDef, len(newDefs))
	for _, d := range newDefs {
		newSet[d.Name] = d
	}

	// Close tunnels that are no longer in the new config.
	for name, at := range current {
		if _, exists := newSet[name]; !exists {
			log.Info().Str("tunnel", name).Msg("Closing removed tunnel")
			if err := r.CloseTunnel(ctx, at.TunnelID, "config reload"); err != nil {
				log.Warn().Err(err).Str("tunnel", name).Msg("Failed to close removed tunnel")
			}
			r.activeTunnelsMu.Lock()
			delete(r.activeTunnels, name)
			r.activeTunnelsMu.Unlock()
		}
	}

	// Register tunnels that are new.
	for name, def := range newSet {
		if _, exists := current[name]; !exists {
			log.Info().Str("tunnel", name).Msg("Registering new tunnel from config reload")
			at, err := r.registerOneTunnel(ctx, def)
			if err != nil {
				log.Error().Err(err).Str("tunnel", name).Msg("Failed to register new tunnel")
				continue
			}
			r.activeTunnelsMu.Lock()
			r.activeTunnels[name] = at
			r.activeTunnelsMu.Unlock()
		}
	}
}

// CreateTunnel registers a single new tunnel on an already-connected
// client and adds it to the active tunnel set, for imperative
// tunnel management via the control API (`wormhole tunnels create`) as a
// complement to the declarative config-file + SIGHUP reload path
// (ReloadTunnels). Returns an error if a tunnel with the same name is
// already active or if registration fails.
func (r *relayClient) CreateTunnel(ctx context.Context, def TunnelDef) (*ActiveTunnel, error) {
	r.activeTunnelsMu.RLock()
	_, exists := r.activeTunnels[def.Name]
	r.activeTunnelsMu.RUnlock()
	if exists {
		return nil, fmt.Errorf("tunnel %q already exists", def.Name)
	}

	at, err := r.registerOneTunnel(ctx, def)
	if err != nil {
		return nil, err
	}

	r.activeTunnelsMu.Lock()
	if r.activeTunnels == nil {
		r.activeTunnels = make(map[string]*ActiveTunnel, 1)
	}
	r.activeTunnels[def.Name] = at
	r.activeTunnelsMu.Unlock()

	return at, nil
}

// DeleteTunnel closes and removes a single active tunnel by name,
// the imperative counterpart to CreateTunnel. Returns an error if no
// tunnel with that name is currently active.
func (r *relayClient) DeleteTunnel(ctx context.Context, name string) error {
	r.activeTunnelsMu.RLock()
	at, exists := r.activeTunnels[name]
	r.activeTunnelsMu.RUnlock()
	if !exists {
		return fmt.Errorf("tunnel %q not found", name)
	}

	if err := r.CloseTunnel(ctx, at.TunnelID, "removed via tunnels delete"); err != nil {
		return err
	}

	r.activeTunnelsMu.Lock()
	delete(r.activeTunnels, name)
	r.activeTunnelsMu.Unlock()

	return nil
}

// CloseAllTunnels gracefully closes every active tunnel (single- and
// multi-tunnel mode), best-effort. It's a no-op if not currently connected.
func (r *relayClient) CloseAllTunnels(ctx context.Context, reason string) {
	r.mu.Lock()
	mux := r.mux
	tunnelID := r.tunnelID
	r.mu.Unlock()

	if mux == nil || mux.IsClosed() {
		return
	}

	r.activeTunnelsMu.RLock()
	tunnels := make([]*ActiveTunnel, 0, len(r.activeTunnels))
	for _, at := range r.activeTunnels {
		tunnels = append(tunnels, at)
	}
	r.activeTunnelsMu.RUnlock()

	for _, at := range tunnels {
		if err := r.CloseTunnel(ctx, at.TunnelID, reason); err != nil {
			log.Debug().Err(err).Str("tunnel", at.Def.Name).Msg("Graceful tunnel close failed")
		}
	}
	// Single-tunnel mode fallback.
	if tunnelID != "" {
		if err := r.CloseTunnel(ctx, tunnelID, reason); err != nil {
			log.Debug().Err(err).Msg("Graceful tunnel close failed (proceeding with shutdown)")
		}
	}
}

// handleConnection handles an active connection. It blocks until the
// connection is lost (mux closed, e.g. due to network failure) or the
// application shuts down (ctx.Done() / closeCh), whichever happens
// first. This is what allows Run's reconnection loop to actually run
// after a connection drop — previously this only unblocked on
// application shutdown, so a dead mux never triggered a reconnect.
func (r *relayClient) handleConnection(ctx context.Context) {
	r.wg.Add(2)
	go r.acceptStreams(ctx)
	go r.heartbeatLoop(ctx)

	// Give any wired post-connect hook (P2P offer attempt) a chance to
	// run, tracked by the same WaitGroup this method waits on below —
	// see afterConnect's doc comment for why.
	if r.afterConnect != nil {
		r.wg.Go(func() { r.afterConnect(ctx) })
	}

	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()

	// Wait for whichever comes first: connection loss, app shutdown, or
	// explicit Close(). mux may be nil only in tests that skip connect().
	if mux != nil {
		select {
		case <-mux.CloseNotify():
		case <-ctx.Done():
		case <-r.closeCh:
		}
	} else {
		select {
		case <-ctx.Done():
		case <-r.closeCh:
		}
	}

	r.mu.Lock()
	if r.mux != nil {
		_ = r.mux.Close()
	}
	r.mu.Unlock()

	atomic.StoreUint32(&r.connected, 0)
	r.wg.Wait()
}

// acceptStreams accepts incoming streams from the server.
//
// Each accepted stream is serviced by its own goroutine (handleStream),
// bounded by config.MaxConcurrentStreams: a compromised or misbehaving
// server could otherwise open unbounded streams on this
// client's relay Mux and exhaust its goroutines/memory. A stream that
// arrives while already at the limit is closed immediately rather than
// queued, so the failure is fast and visible instead of adding unbounded
// latency.
func (r *relayClient) acceptStreams(ctx context.Context) {
	defer r.wg.Done()

	for {
		r.mu.Lock()
		mux := r.mux
		r.mu.Unlock()

		if mux == nil || mux.IsClosed() {
			return
		}

		stream, err := mux.AcceptStreamContext(ctx)
		if err != nil {
			if ctx.Err() != nil || mux.IsClosed() {
				return
			}
			log.Error().Err(err).Msg("Accept stream failed")
			continue
		}

		if r.config.MaxConcurrentStreams > 0 &&
			!tryIncrementBounded32(&r.activeStreams, int32(r.config.MaxConcurrentStreams)) {
			log.Warn().Int("limit", r.config.MaxConcurrentStreams).
				Msg("Concurrent stream limit reached, dropping inbound relay stream")
			_ = stream.Close()
			continue
		}

		go func() {
			defer atomic.AddInt32(&r.activeStreams, -1)
			r.handleStream(ctx, stream)
		}()
	}
}

// tryIncrementBounded32 atomically increments *counter and returns true,
// unless it is already >= limit, in which case it leaves *counter
// unchanged and returns false. Shared by relayClient.acceptStreams and
// p2pSession.acceptP2PStreams to bound concurrent inbound streams;
// mirrors the server-side pattern in pkg/server/proxy_service.go.
func tryIncrementBounded32(counter *int32, limit int32) bool {
	for {
		cur := atomic.LoadInt32(counter)
		if cur >= limit {
			return false
		}
		if atomic.CompareAndSwapInt32(counter, cur, cur+1) {
			return true
		}
	}
}

// handleStream handles an incoming stream from the server.
//
// A P2P peer-notification stream (opened by the server's notifyPeerOfP2P)
// may carry a P2PCandidates message — Symmetric+Symmetric NAT port
// prediction — ahead of the terminal P2POfferResponse, both length-prefixed
// via proto.WriteControlMessage. We therefore loop-read until we hit a
// message that concludes the exchange (StreamRequest or P2POfferResponse),
// rather than assuming a single read yields the whole exchange.
func (r *relayClient) handleStream(ctx context.Context, stream *tunnel.Stream) {
	defer stream.Close()

	var p2pCandidates []string

	for {
		msg, err := proto.ReadControlMessage(stream)
		if err != nil {
			if len(p2pCandidates) == 0 {
				log.Error().Err(err).Msg("Read stream request failed")
			}
			return
		}

		switch {
		case msg.StreamRequest != nil:
			req := msg.StreamRequest
			r.stats.addRequest()
			// Forward to local service.
			r.forwarder.forwardToLocal(ctx, stream, req)
			return

		case msg.P2PCandidates != nil:
			// Not yet consumed by the hole-punching algorithm; retained
			// here purely so the exchange doesn't stall or get
			// misclassified while waiting for the offer response.
			p2pCandidates = append(p2pCandidates, msg.P2PCandidates.Candidates...)
			continue

		case msg.P2POfferResponse != nil:
			// Server is notifying us about a peer that wants to connect.
			if r.onNotification != nil {
				r.onNotification(ctx, r, msg.P2POfferResponse, p2pCandidates)
			}
			return

		default:
			log.Warn().Int("type", int(msg.Type)).Msg("Unexpected message type in stream")
			return
		}
	}
}

// ResolveLocalAddr returns the local host/port that a given stream request
// should be forwarded to. In multi-tunnel mode, the server tags each
// StreamRequest with the TunnelID of the tunnel it matched (see
// ProxyService.resolveTunnelID server-side); we look that ID up in
// activeTunnels to find the corresponding ActiveTunnel.Def. When the
// TunnelID is empty or unknown (single-tunnel/legacy mode, or a transient
// mismatch during reconnection), fall back to the top-level config's
// LocalHost/LocalPort so existing single-tunnel behavior is preserved.
func (r *relayClient) ResolveLocalAddr(tunnelID string) (host string, port int) {
	if tunnelID != "" {
		r.activeTunnelsMu.RLock()
		for _, at := range r.activeTunnels {
			if at.TunnelID == tunnelID {
				host, port = at.Def.LocalHost, at.Def.LocalPort
				r.activeTunnelsMu.RUnlock()
				if host == "" {
					host = defaultLocalHost
				}
				return host, port
			}
		}
		r.activeTunnelsMu.RUnlock()
	}

	host = r.config.LocalHost
	if host == "" {
		host = defaultLocalHost
	}
	return host, r.config.LocalPort
}

// maxConsecutiveHeartbeatFailures is the number of consecutive failed
// pings after which the mux is force-closed to trigger reconnection.
// A single failed ping can be a transient hiccup, but repeated failures
// indicate a half-dead connection that will otherwise linger forever
// (acceptStreams/heartbeatLoop keep running against a connection that
// never delivers data).
const maxConsecutiveHeartbeatFailures = 3

// heartbeatLoop sends periodic heartbeats. After several consecutive
// failures it force-closes the mux so handleConnection's CloseNotify
// wait unblocks and Run can re-dial. It also watches the mux's own
// CloseNotify channel directly so it exits promptly if the mux dies for
// any other reason (e.g. the peer closing the connection), rather than
// waiting for the next heartbeat tick — this matters because
// handleConnection blocks on wg.Wait(), which includes this loop.
func (r *relayClient) heartbeatLoop(ctx context.Context) {
	defer r.wg.Done()

	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()
	if mux == nil {
		return
	}

	ticker := time.NewTicker(r.config.HeartbeatInterval)
	defer ticker.Stop()

	var pingID uint64
	var consecutiveFailures int

	for {
		select {
		case <-ticker.C:
			if mux.IsClosed() {
				return
			}

			pingID++
			if err := r.sendPing(ctx, pingID); err != nil {
				consecutiveFailures++
				log.Error().Err(err).Int("consecutive_failures", consecutiveFailures).Msg("Heartbeat failed")
				if consecutiveFailures >= maxConsecutiveHeartbeatFailures {
					log.Warn().Msg("Too many consecutive heartbeat failures, closing connection to trigger reconnect")
					_ = mux.Close()
					return
				}
				continue
			}
			consecutiveFailures = 0

		case <-mux.CloseNotify():
			return
		case <-ctx.Done():
			return
		case <-r.closeCh:
			return
		}
	}
}

// sendPing sends a ping to the server.
func (r *relayClient) sendPing(ctx context.Context, pingID uint64) error {
	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()

	if mux == nil {
		return fmt.Errorf("not connected")
	}

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	req := proto.NewPingRequest(pingID)
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode ping: %w", err)
	}

	if deadlineErr := stream.SetDeadline(time.Now().Add(r.config.HeartbeatTimeout)); deadlineErr != nil {
		return fmt.Errorf("set deadline: %w", deadlineErr)
	}

	if _, writeErr := stream.WriteContext(ctx, data); writeErr != nil {
		return fmt.Errorf("write ping: %w", writeErr)
	}

	// Read pong. The mux's own keep-alive already matches ping/pong IDs at
	// the frame level; this application-level heartbeat must do the same
	// rather than treating any 256 bytes read as success — e.g. a stale
	// response from an earlier, timed-out ping could otherwise be
	// misread as confirming this one.
	buf := make([]byte, 256)
	n, err := stream.ReadContext(ctx, buf)
	if err != nil {
		return fmt.Errorf("read pong: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("decode pong: %w", err)
	}
	if msg.PingResponse == nil {
		return fmt.Errorf("unexpected pong message type: %d", msg.Type)
	}
	if msg.PingResponse.PingID != pingID {
		return fmt.Errorf("pong ID mismatch: sent %d, got %d", pingID, msg.PingResponse.PingID)
	}

	return nil
}

// RequestStats sends a StatsRequest to the server and returns the session statistics.
func (r *relayClient) RequestStats(ctx context.Context) (*proto.StatsResponse, error) {
	r.mu.Lock()
	mux := r.mux
	sessionID := r.sessionID
	r.mu.Unlock()

	if mux == nil || mux.IsClosed() {
		return nil, fmt.Errorf("not connected")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if deadlineErr := stream.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
		return nil, fmt.Errorf("set deadline: %w", deadlineErr)
	}

	req := proto.NewStatsRequest(sessionID)
	data, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode stats request: %w", err)
	}

	if _, writeErr := stream.WriteContext(ctx, data); writeErr != nil {
		return nil, fmt.Errorf("write stats request: %w", writeErr)
	}

	// Read response.
	buf := make([]byte, 4096)
	n, err := stream.ReadContext(ctx, buf)
	if err != nil {
		return nil, fmt.Errorf("read stats response: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("decode stats response: %w", err)
	}

	if msg.StatsResponse == nil {
		return nil, fmt.Errorf("unexpected response type (expected stats response)")
	}

	return msg.StatsResponse, nil
}

// CloseTunnel sends a CloseRequest to the server to gracefully close a tunnel.
func (r *relayClient) CloseTunnel(ctx context.Context, tunnelID, reason string) error {
	r.mu.Lock()
	mux := r.mux
	r.mu.Unlock()

	if mux == nil || mux.IsClosed() {
		return fmt.Errorf("not connected")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if deadlineErr := stream.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
		return fmt.Errorf("set deadline: %w", deadlineErr)
	}

	req := proto.NewCloseRequest(tunnelID, reason)
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode close request: %w", err)
	}

	if _, writeErr := stream.WriteContext(ctx, data); writeErr != nil {
		return fmt.Errorf("write close request: %w", writeErr)
	}

	// Read response.
	buf := make([]byte, 4096)
	n, err := stream.ReadContext(ctx, buf)
	if err != nil {
		return fmt.Errorf("read close response: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return fmt.Errorf("decode close response: %w", err)
	}

	if msg.CloseResponse == nil {
		return fmt.Errorf("unexpected response type (expected close response)")
	}

	if !msg.CloseResponse.Success {
		return fmt.Errorf("server rejected close request")
	}

	log.Info().
		Str("tunnel_id", tunnelID).
		Str("reason", reason).
		Msg("Tunnel closed successfully")

	return nil
}

// IsConnected returns whether the client is currently connected.
func (r *relayClient) IsConnected() bool {
	return atomic.LoadUint32(&r.connected) == 1
}

// Mux returns the current relay multiplexer, or nil if not connected.
func (r *relayClient) Mux() *tunnel.Mux {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mux
}

// TunnelID returns this client's single-tunnel-mode tunnel ID.
func (r *relayClient) TunnelID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tunnelID
}

// PublicURL returns this client's single-tunnel-mode public URL.
func (r *relayClient) PublicURL() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.publicURL
}

// SessionID returns the server-assigned session ID (empty before
// authentication completes).
func (r *relayClient) SessionID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessionID
}

// Close closes the current mux and underlying connection, if any.
func (r *relayClient) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mux != nil {
		_ = r.mux.Close()
	}
	if r.conn != nil {
		_ = r.conn.Close()
	}
}
