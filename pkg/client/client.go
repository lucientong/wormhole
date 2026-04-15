package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/inspector"
	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/lucientong/wormhole/pkg/version"
	"github.com/lucientong/wormhole/pkg/web"
	"github.com/rs/zerolog/log"
)

// defaultLocalHost is the default host for local service binding and inspector UI.
const defaultLocalHost = "127.0.0.1"

// protocolHTTP is the canonical string for HTTP tunnel protocol.
const protocolHTTP = "http"

// Client is the wormhole client.
// ActiveTunnel holds runtime state for a registered tunnel.
type ActiveTunnel struct {
	Def       TunnelDef
	TunnelID  string
	PublicURL string
	TCPPort   uint32
}

type Client struct {
	config Config

	// Connection state
	mux       *tunnel.Mux
	conn      net.Conn
	connected uint32
	publicURL string
	tunnelID  string
	sessionID string // Server-assigned session ID (for reconnect awareness).

	// Multi-tunnel state (populated after registration).
	// Single-tunnel mode uses publicURL/tunnelID directly;
	// multi-tunnel mode populates this map.
	activeTunnels   map[string]*ActiveTunnel // name → active tunnel
	activeTunnelsMu sync.RWMutex

	// Control server (optional; exposes /tunnels for `wormhole tunnels list`).
	ctrlServer *http.Server

	// Inspector
	inspector        *inspector.Inspector
	inspectorHandler *inspector.Handler
	inspectorServer  *http.Server

	// P2P
	p2pManager *p2p.Manager
	p2pConn    net.PacketConn     // UDP connection for P2P
	p2pPeer    *net.UDPAddr       // Peer's confirmed UDP address
	p2pMux     *p2p.UDPMux        // Multiplexed P2P transport (replaces Transport)
	p2pMode    uint32             // 1 if using P2P, 0 for relay
	p2pCloseCh chan struct{}      // Signal to stop P2P accept loop
	p2pKeyPair *p2p.KeyPair       // ECDH key pair for this session
	p2pCipher  *p2p.SessionCipher // Derived session cipher for E2E encryption

	// Statistics
	stats Stats

	// Shutdown
	closed  uint32
	closeCh chan struct{}
	closeWg sync.WaitGroup
	mu      sync.Mutex
}

// Stats contains client statistics.
type Stats struct {
	BytesIn        uint64
	BytesOut       uint64
	Requests       uint64
	Reconnects     uint64
	ConnectionTime time.Time
}

// NewClient creates a new client instance.
func NewClient(config Config) *Client {
	insp := inspector.New(inspector.DefaultConfig())
	p2pConfig := config.P2PConfig
	p2pConfig.Enabled = config.P2PEnabled
	return &Client{
		config:        config,
		inspector:     insp,
		p2pManager:    p2p.NewManager(p2pConfig),
		closeCh:       make(chan struct{}),
		activeTunnels: make(map[string]*ActiveTunnel),
	}
}

// Start starts the client.
func (c *Client) Start(ctx context.Context) error {
	log.Info().
		Str("server", c.config.ServerAddr).
		Int("local_port", c.config.LocalPort).
		Str("local_host", c.config.LocalHost).
		Bool("p2p", c.config.P2PEnabled).
		Msg("Starting Wormhole client")

	// Initialize P2P (non-blocking — failure is acceptable).
	if c.config.P2PEnabled {
		if err := c.p2pManager.Init(ctx); err != nil {
			log.Warn().Err(err).Msg("P2P initialization failed, will use relay mode")
		}
	}

	// Connect with reconnection
	return c.connectWithRetry(ctx)
}

// connectWithRetry connects to the server with automatic reconnection.
func (c *Client) connectWithRetry(ctx context.Context) error {
	interval := c.config.ReconnectInterval
	attempts := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closeCh:
			return nil
		default:
		}

		if err := c.connect(ctx); err != nil {
			log.Error().Err(err).Msg("Connection failed")

			attempts++
			if c.config.MaxReconnectAttempts > 0 && attempts >= c.config.MaxReconnectAttempts {
				return fmt.Errorf("max reconnection attempts reached")
			}

			atomic.AddUint64(&c.stats.Reconnects, 1)

			// Exponential backoff
			select {
			case <-time.After(interval):
				interval = time.Duration(float64(interval) * c.config.ReconnectBackoff)
				if interval > c.config.MaxReconnectInterval {
					interval = c.config.MaxReconnectInterval
				}
			case <-ctx.Done():
				return ctx.Err()
			case <-c.closeCh:
				return nil
			}
			continue
		}

		// Connected successfully
		attempts = 0
		interval = c.config.ReconnectInterval

		// Handle connection
		c.handleConnection(ctx)

		// Connection lost, will reconnect
		log.Warn().
			Str("tunnel_id", c.tunnelID).
			Msg("Connection lost, reconnecting (tunnel will be re-registered)...")
	}
}

// connect establishes a connection to the server.
func (c *Client) connect(ctx context.Context) error {
	// Dial server (plain TCP or TLS).
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	var conn net.Conn
	var err error

	if c.config.TLSEnabled {
		tlsConfig, tlsErr := c.buildTLSConfig()
		if tlsErr != nil {
			return fmt.Errorf("build TLS config: %w", tlsErr)
		}
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	}
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}

	// Create multiplexer
	mux, err := tunnel.Client(conn, c.config.MuxConfig)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create mux: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mux = mux
	c.stats.ConnectionTime = time.Now()
	c.mu.Unlock()

	atomic.StoreUint32(&c.connected, 1)

	log.Info().Str("server", c.config.ServerAddr).Msg("Connected to server")

	// Phase 5: Authenticate if token is provided.
	if c.config.Token != "" {
		if err := c.authenticate(ctx); err != nil {
			_ = mux.Close()
			_ = conn.Close()
			return fmt.Errorf("authenticate: %w", err)
		}
	}

	// Register tunnel(s).
	if len(c.config.Tunnels) > 0 {
		if err := c.registerAllTunnels(ctx); err != nil {
			_ = mux.Close()
			_ = conn.Close()
			return fmt.Errorf("register tunnels: %w", err)
		}
	} else {
		if err := c.registerTunnel(ctx); err != nil {
			_ = mux.Close()
			_ = conn.Close()
			return fmt.Errorf("register tunnel: %w", err)
		}
	}

	return nil
}

// buildTLSConfig builds a *tls.Config from the client configuration.
func (c *Client) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if c.config.TLSInsecure {
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- user explicitly opted in via --tls-insecure
	}

	// Load custom CA certificate if specified.
	if c.config.TLSCACert != "" {
		caCert, err := os.ReadFile(c.config.TLSCACert) // #nosec G304 -- path from CLI flag, not untrusted input
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", c.config.TLSCACert)
		}
		tlsConfig.RootCAs = pool
	}

	// Extract hostname from server address for SNI.
	host, _, err := net.SplitHostPort(c.config.ServerAddr)
	if err != nil {
		// If no port in address, use as-is.
		host = c.config.ServerAddr
	}
	tlsConfig.ServerName = host

	return tlsConfig, nil
}

// authenticate sends an AuthRequest to the server and validates the response.
func (c *Client) authenticate(ctx context.Context) error {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

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

	// Send auth request.
	req := proto.NewAuthRequest(c.config.Token, version.Short(), c.config.Subdomain)
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode auth request: %w", err)
	}

	if _, writeErr := stream.Write(data); writeErr != nil {
		return fmt.Errorf("write auth request: %w", writeErr)
	}

	// Read auth response.
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
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
		c.mu.Lock()
		c.config.Subdomain = resp.Subdomain
		c.mu.Unlock()
	}

	// Save session ID for reconnect awareness.
	if resp.SessionID != "" {
		c.mu.Lock()
		c.sessionID = resp.SessionID
		c.mu.Unlock()
	}

	log.Info().
		Str("session_id", resp.SessionID).
		Str("subdomain", resp.Subdomain).
		Msg("Authenticated with server")

	return nil
}

// registerTunnel registers a tunnel with the server.
func (c *Client) registerTunnel(ctx context.Context) error {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

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
	if c.config.LocalPort < 0 || c.config.LocalPort > 65535 {
		return fmt.Errorf("invalid local port: %d", c.config.LocalPort)
	}
	p := parseProtocol(c.config.Protocol)
	req := proto.NewRegisterRequest(uint32(c.config.LocalPort), p, c.config.Subdomain, c.config.Hostname, c.config.PathPrefix) // #nosec G115
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	if _, writeErr := stream.Write(data); writeErr != nil {
		return fmt.Errorf("write request: %w", writeErr)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
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

	c.mu.Lock()
	c.tunnelID = resp.TunnelID
	c.publicURL = resp.PublicURL
	c.mu.Unlock()

	log.Info().
		Str("tunnel_id", resp.TunnelID).
		Str("public_url", resp.PublicURL).
		Msg("Tunnel registered")

	fmt.Printf("\n")
	fmt.Printf("  🕳️  Wormhole is ready!\n")
	fmt.Printf("\n")
	fmt.Printf("  Forwarding:   %s -> http://%s:%d\n", resp.PublicURL, c.config.LocalHost, c.config.LocalPort)
	fmt.Printf("  Version:      %s\n", version.Short())
	switch {
	case c.p2pManager != nil && c.p2pManager.NATInfo() != nil:
		info := c.p2pManager.NATInfo()
		traversable := info.Type.IsTraversable()
		fmt.Printf("  NAT Type:     %s\n", info.Type)
		fmt.Printf("  Public Addr:  %s\n", info.PublicAddr)
		if traversable {
			fmt.Printf("  Traversable:  ✅ Yes (P2P direct connections possible)\n")
		} else {
			fmt.Printf("  Traversable:  ⚠️  Limited (P2P only with non-Symmetric peers)\n")
		}
		fmt.Printf("  P2P Mode:     %s\n", c.p2pManager.Mode())
	case c.config.P2PEnabled:
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
func (c *Client) registerAllTunnels(ctx context.Context) error {
	c.activeTunnelsMu.Lock()
	// Reset active tunnels map for this connection cycle.
	c.activeTunnels = make(map[string]*ActiveTunnel, len(c.config.Tunnels))
	c.activeTunnelsMu.Unlock()

	for _, def := range c.config.Tunnels {
		at, err := c.registerOneTunnel(ctx, def)
		if err != nil {
			log.Error().Err(err).Str("tunnel", def.Name).Msg("Failed to register tunnel")
			continue // Best effort: skip failed tunnels.
		}
		c.activeTunnelsMu.Lock()
		c.activeTunnels[def.Name] = at
		c.activeTunnelsMu.Unlock()
	}

	c.activeTunnelsMu.RLock()
	count := len(c.activeTunnels)
	c.activeTunnelsMu.RUnlock()

	if count == 0 {
		return fmt.Errorf("all tunnel registrations failed")
	}

	c.printMultiTunnelBanner()
	return nil
}

// registerOneTunnel registers a single tunnel definition and returns its state.
func (c *Client) registerOneTunnel(ctx context.Context, def TunnelDef) (*ActiveTunnel, error) {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

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
	if _, writeErr := stream.Write(data); writeErr != nil {
		return nil, fmt.Errorf("write request: %w", writeErr)
	}

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
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
func (c *Client) printMultiTunnelBanner() {
	c.activeTunnelsMu.RLock()
	defer c.activeTunnelsMu.RUnlock()

	fmt.Printf("\n")
	fmt.Printf("  🕳️  Wormhole is ready! (%d tunnel(s) active)\n", len(c.activeTunnels))
	fmt.Printf("\n")
	for name, at := range c.activeTunnels {
		fmt.Printf("  %-12s %s  →  %s:%d\n", name+":", at.PublicURL, at.Def.LocalHost, at.Def.LocalPort)
	}
	fmt.Printf("\n  Press Ctrl+C to stop\n\n")
}

// ListActiveTunnels returns a copy of the currently active tunnels.
func (c *Client) ListActiveTunnels() []ActiveTunnel {
	c.activeTunnelsMu.RLock()
	defer c.activeTunnelsMu.RUnlock()

	out := make([]ActiveTunnel, 0, len(c.activeTunnels))
	for _, at := range c.activeTunnels {
		out = append(out, *at)
	}
	// In single-tunnel mode also expose the main tunnel.
	if len(out) == 0 && c.tunnelID != "" {
		out = append(out, ActiveTunnel{
			Def: TunnelDef{
				Name:      "default",
				LocalPort: c.config.LocalPort,
				LocalHost: c.config.LocalHost,
				Protocol:  c.config.Protocol,
			},
			TunnelID:  c.tunnelID,
			PublicURL: c.publicURL,
		})
	}
	return out
}

// ReloadTunnels updates the active tunnel set based on a new list of definitions.
// New tunnels are registered; removed tunnels are closed via CloseRequest.
// This is designed to be called when a SIGHUP reloads the config file.
func (c *Client) ReloadTunnels(ctx context.Context, newDefs []TunnelDef) {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()
	if mux == nil || mux.IsClosed() {
		log.Warn().Msg("ReloadTunnels: not connected, skipping")
		return
	}

	c.activeTunnelsMu.RLock()
	current := make(map[string]*ActiveTunnel, len(c.activeTunnels))
	for k, v := range c.activeTunnels {
		current[k] = v
	}
	c.activeTunnelsMu.RUnlock()

	newSet := make(map[string]TunnelDef, len(newDefs))
	for _, d := range newDefs {
		newSet[d.Name] = d
	}

	// Close tunnels that are no longer in the new config.
	for name, at := range current {
		if _, exists := newSet[name]; !exists {
			log.Info().Str("tunnel", name).Msg("Closing removed tunnel")
			if err := c.CloseTunnel(ctx, at.TunnelID, "config reload"); err != nil {
				log.Warn().Err(err).Str("tunnel", name).Msg("Failed to close removed tunnel")
			}
			c.activeTunnelsMu.Lock()
			delete(c.activeTunnels, name)
			c.activeTunnelsMu.Unlock()
		}
	}

	// Register tunnels that are new.
	for name, def := range newSet {
		if _, exists := current[name]; !exists {
			log.Info().Str("tunnel", name).Msg("Registering new tunnel from config reload")
			at, err := c.registerOneTunnel(ctx, def)
			if err != nil {
				log.Error().Err(err).Str("tunnel", name).Msg("Failed to register new tunnel")
				continue
			}
			c.activeTunnelsMu.Lock()
			c.activeTunnels[name] = at
			c.activeTunnelsMu.Unlock()
		}
	}
}

// handleConnection handles an active connection.
func (c *Client) handleConnection(ctx context.Context) {
	c.closeWg.Add(2)
	go c.acceptStreams(ctx)
	go c.heartbeatLoop(ctx)

	// Attempt P2P offer (non-blocking).
	if c.config.P2PEnabled && c.p2pManager.IsEnabled() {
		c.closeWg.Go(func() {
			c.sendP2POffer(ctx)
		})
	}

	// Wait for connection to close
	<-ctx.Done()

	c.mu.Lock()
	if c.mux != nil {
		_ = c.mux.Close()
	}
	c.mu.Unlock()

	atomic.StoreUint32(&c.connected, 0)
	c.closeWg.Wait()
}

// acceptStreams accepts incoming streams from the server.
func (c *Client) acceptStreams(ctx context.Context) {
	defer c.closeWg.Done()

	for {
		c.mu.Lock()
		mux := c.mux
		c.mu.Unlock()

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

		go c.handleStream(ctx, stream)
	}
}

// handleStream handles an incoming stream from the server.
func (c *Client) handleStream(ctx context.Context, stream *tunnel.Stream) {
	defer stream.Close()

	// Read length-prefixed stream request.
	msg, err := proto.ReadControlMessage(stream)
	if err != nil {
		log.Error().Err(err).Msg("Read stream request failed")
		return
	}

	// Handle different message types.
	switch {
	case msg.StreamRequest != nil:
		req := msg.StreamRequest
		atomic.AddUint64(&c.stats.Requests, 1)
		// Forward to local service.
		c.forwardToLocal(ctx, stream, req)

	case msg.P2POfferResponse != nil:
		// Server is notifying us about a peer that wants to connect.
		c.handleP2PNotification(ctx, msg.P2POfferResponse)

	default:
		log.Warn().Int("type", int(msg.Type)).Msg("Unexpected message type in stream")
	}
}

// forwardToLocal forwards a stream to the local service.
// streamConn is implemented by both *tunnel.Stream and *p2p.UDPStream,
// allowing forwardToLocal to handle both relay and P2P data paths.
type streamConn = io.ReadWriteCloser

func (c *Client) forwardToLocal(ctx context.Context, conn streamConn, req *proto.StreamRequest) {
	// Use HTTP-aware forwarding when inspector is active and protocol is HTTP.
	if req.Protocol == proto.ProtocolHTTP && c.inspector.IsEnabled() {
		c.forwardHTTPWithInspect(ctx, conn, req)
		return
	}

	// Fallback: raw TCP bidirectional proxy.
	c.forwardRawTCP(ctx, conn, req)
}

// forwardRawTCP forwards a stream to the local service using raw TCP proxy.
func (c *Client) forwardRawTCP(ctx context.Context, conn streamConn, req *proto.StreamRequest) {
	c.dialAndProxy(ctx, conn, conn, req)
}

// forwardRawTCPWithReader is like forwardRawTCP but uses a custom reader
// for the stream->local direction (used when we've partially consumed the stream).
func (c *Client) forwardRawTCPWithReader(ctx context.Context, reader io.Reader, conn streamConn, sreq *proto.StreamRequest) {
	c.dialAndProxy(ctx, reader, conn, sreq)
}

// dialAndProxy connects to the local service and proxies data bidirectionally
// between the given reader/writer pair and the local connection.
func (c *Client) dialAndProxy(ctx context.Context, inReader io.Reader, outWriter io.Writer, sreq *proto.StreamRequest) {
	localAddr := net.JoinHostPort(c.config.LocalHost, fmt.Sprintf("%d", c.config.LocalPort))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	localConn, err := dialer.DialContext(ctx, "tcp", localAddr)
	if err != nil {
		log.Error().Err(err).Str("addr", localAddr).Msg("Connect to local failed")
		resp := proto.NewStreamResponse(sreq.RequestID, false, "Local service unavailable")
		data, _ := resp.Encode()
		_, _ = outWriter.Write(data)
		return
	}
	defer localConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// InReader -> Local.
	go func() {
		defer wg.Done()
		n, _ := io.Copy(localConn, inReader)
		if n > 0 {
			atomic.AddUint64(&c.stats.BytesIn, uint64(n))
		}
	}()

	// Local -> OutWriter.
	go func() {
		defer wg.Done()
		n, _ := io.Copy(outWriter, localConn)
		if n > 0 {
			atomic.AddUint64(&c.stats.BytesOut, uint64(n)) // #nosec G115
		}
	}()

	wg.Wait()
}

// forwardHTTPWithInspect forwards an HTTP request through the tunnel with
// traffic inspection. It parses the raw HTTP request from the stream,
// forwards it to the local service via http.Transport, captures the
// request/response pair in the inspector, and writes the response back.
func (c *Client) forwardHTTPWithInspect(ctx context.Context, stream streamConn, sreq *proto.StreamRequest) {
	localAddr := net.JoinHostPort(c.config.LocalHost, fmt.Sprintf("%d", c.config.LocalPort))

	start := time.Now()

	// 1. Parse the raw HTTP request from the stream.
	br := bufio.NewReader(stream)
	httpReq, err := http.ReadRequest(br)
	if err != nil {
		log.Debug().Err(err).Msg("HTTP parse failed, falling back to raw TCP")
		// Cannot parse HTTP — write back whatever buffered data plus the
		// rest of the stream through raw TCP. Create a composite reader
		// from buffered data + remaining stream.
		buffered := br.Buffered()
		if buffered > 0 {
			peeked, _ := br.Peek(buffered)
			combined := io.MultiReader(bytes.NewReader(peeked), stream)
			c.forwardRawTCPWithReader(ctx, combined, stream, sreq)
		} else {
			c.forwardRawTCP(ctx, stream, sreq)
		}
		return
	}
	defer httpReq.Body.Close()

	// 2. Read request body for inspection (limited by MaxBodySize).
	var reqBody []byte
	if httpReq.Body != nil {
		reqBody, _ = io.ReadAll(httpReq.Body)
	}

	// Track bytes in.
	atomic.AddUint64(&c.stats.BytesIn, uint64(len(reqBody)))

	// 3. Prepare the request for forwarding to local service.
	httpReq.URL.Scheme = protocolHTTP
	httpReq.URL.Host = localAddr
	httpReq.Body = io.NopCloser(bytes.NewReader(reqBody))
	httpReq.ContentLength = int64(len(reqBody))
	httpReq.RequestURI = "" // Must clear for http.Transport.

	// Use a transport that connects to the local service.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- local service may use self-signed certs
		MaxIdleConnsPerHost:   10,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	defer transport.CloseIdleConnections()

	// 4. Execute the request.
	resp, roundTripErr := transport.RoundTrip(httpReq)
	duration := time.Since(start)

	if roundTripErr != nil {
		// Local service error — send 502 back through the stream.
		log.Error().Err(roundTripErr).Str("addr", localAddr).Msg("Local service request failed")

		errBody := "Local service unavailable"
		errResp := &http.Response{
			StatusCode:    http.StatusBadGateway,
			Status:        "502 Bad Gateway",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewBufferString(errBody)),
			ContentLength: int64(len(errBody)),
		}
		errResp.Header.Set("Content-Type", "text/plain")
		_ = errResp.Write(stream)

		// Capture the failed request.
		c.inspector.Capture(httpReq, reqBody, nil, nil, duration, roundTripErr)
		return
	}
	defer resp.Body.Close()

	// 5. Read response body for inspection.
	respBody, _ := io.ReadAll(resp.Body)

	// Track bytes out.
	atomic.AddUint64(&c.stats.BytesOut, uint64(len(respBody)))

	// 6. Write response back to stream.
	// Reconstruct the response with the body we've read.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	if writeErr := resp.Write(stream); writeErr != nil {
		log.Error().Err(writeErr).Msg("Failed to write response to stream")
	}

	// 7. Capture in inspector.
	c.inspector.Capture(httpReq, reqBody, resp, respBody, duration, nil)
}

// heartbeatLoop sends periodic heartbeats.
func (c *Client) heartbeatLoop(ctx context.Context) {
	defer c.closeWg.Done()

	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	var pingID uint64

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			mux := c.mux
			c.mu.Unlock()

			if mux == nil || mux.IsClosed() {
				return
			}

			pingID++
			if err := c.sendPing(ctx, pingID); err != nil {
				log.Error().Err(err).Msg("Heartbeat failed")
			}

		case <-ctx.Done():
			return
		case <-c.closeCh:
			return
		}
	}
}

// sendPing sends a ping to the server.
func (c *Client) sendPing(ctx context.Context, pingID uint64) error {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

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

	if err := stream.SetDeadline(time.Now().Add(c.config.HeartbeatTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("write ping: %w", err)
	}

	// Read pong
	buf := make([]byte, 256)
	if _, err := stream.Read(buf); err != nil {
		return fmt.Errorf("read pong: %w", err)
	}

	return nil
}

// sendP2POffer sends a P2P offer to the server with this client's NAT info.
// It also generates an ECDH key pair and includes the public key for E2E encryption.
func (c *Client) sendP2POffer(ctx context.Context) {
	natInfo := c.p2pManager.NATInfo()
	if natInfo == nil {
		return
	}

	// Generate ECDH key pair for this P2P session.
	keyPair, keyErr := p2p.GenerateKeyPair()
	if keyErr != nil {
		log.Error().Err(keyErr).Msg("Failed to generate ECDH key pair for P2P")
		return
	}

	c.mu.Lock()
	c.p2pKeyPair = keyPair
	mux := c.mux
	tunnelID := c.tunnelID
	c.mu.Unlock()

	if mux == nil {
		return
	}

	stream, err := mux.OpenStreamContext(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to open stream for P2P offer")
		return
	}
	defer stream.Close()

	// Encode public key as base64 for transmission in JSON.
	pubKeyB64 := base64.StdEncoding.EncodeToString(keyPair.Public)

	req := proto.NewP2POfferRequest(
		tunnelID,
		natInfo.Type.String(),
		natInfo.PublicAddr.String(),
		natInfo.LocalAddr.String(),
		pubKeyB64,
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

	if _, err := stream.Write(data); err != nil {
		log.Debug().Err(err).Msg("Failed to send P2P offer")
		return
	}

	// Read response.
	buf := make([]byte, 4096)
	n, readErr := stream.Read(buf)
	if readErr != nil {
		log.Debug().Err(readErr).Msg("Failed to read P2P offer response")
		return
	}

	msg, decodeErr := proto.DecodeControlMessage(buf[:n])
	if decodeErr != nil || msg.P2POfferResponse == nil {
		log.Debug().Msg("Invalid P2P offer response")
		return
	}

	resp := msg.P2POfferResponse
	if resp.Success && resp.PeerAddr != "" {
		// Derive session cipher from peer's public key.
		if resp.PeerPublicKey != "" {
			if derivErr := c.deriveP2PCipher(resp.PeerPublicKey); derivErr != nil {
				log.Error().Err(derivErr).Msg("Failed to derive P2P session cipher")
				return
			}
		}

		log.Info().
			Str("peer_addr", resp.PeerAddr).
			Str("peer_nat", resp.PeerNATType).
			Bool("encrypted", c.p2pCipher != nil).
			Msg("P2P peer found, attempting connection")

		// Offer sender is the initiator for stream-ID allocation.
		go c.attemptP2P(ctx, resp.PeerAddr, true)
	} else {
		log.Debug().
			Str("reason", resp.Error).
			Msg("P2P offer: no peer available, staying in relay mode")
	}
}

// deriveP2PCipher derives the E2E session cipher from the peer's public key.
func (c *Client) deriveP2PCipher(peerPubKeyB64 string) error {
	peerPubBytes, err := base64.StdEncoding.DecodeString(peerPubKeyB64)
	if err != nil {
		return fmt.Errorf("decode peer public key: %w", err)
	}

	c.mu.Lock()
	keyPair := c.p2pKeyPair
	c.mu.Unlock()

	if keyPair == nil {
		return fmt.Errorf("local key pair not generated")
	}

	cipher, err := p2p.DeriveSession(keyPair.Private, peerPubBytes)
	if err != nil {
		return fmt.Errorf("derive session: %w", err)
	}

	c.mu.Lock()
	c.p2pCipher = cipher
	c.mu.Unlock()

	log.Info().Msg("P2P E2E session cipher derived successfully")
	return nil
}

// attemptP2P attempts to establish a P2P connection with the given peer address.
// isInitiator must be true on exactly one side; the other side passes false.
// The initiator allocates odd stream IDs; the acceptor uses even IDs.
func (c *Client) attemptP2P(ctx context.Context, peerAddr string, isInitiator bool) {
	// Parse peer endpoint.
	peerEndpoint, err := c.parseEndpoint(peerAddr)
	if err != nil {
		log.Error().Err(err).Str("peer_addr", peerAddr).Msg("Failed to parse peer address")
		c.sendP2PResult(ctx, false, "", err.Error())
		return
	}

	log.Info().
		Str("peer", peerAddr).
		Bool("initiator", isInitiator).
		Msg("Attempting P2P hole punching")

	// Get cipher for authenticated hole punching.
	c.mu.Lock()
	cipher := c.p2pCipher
	c.mu.Unlock()

	// Attempt P2P connection through the manager (with optional cipher for authenticated probes).
	conn, confirmedPeer, p2pErr := c.p2pManager.AttemptP2P(ctx, peerEndpoint, cipher)
	if p2pErr != nil {
		log.Warn().Err(p2pErr).Msg("P2P hole punching failed")
		c.sendP2PResult(ctx, false, "", p2pErr.Error())
		return
	}

	// Create multiplexed UDP transport over the P2P connection.
	mux := p2p.NewUDPMux(conn, confirmedPeer, p2p.DefaultTransportConfig(), cipher, isInitiator)

	// Create P2P close channel for graceful shutdown.
	p2pCloseCh := make(chan struct{})

	// P2P connection established!
	c.mu.Lock()
	c.p2pConn = conn
	c.p2pPeer = confirmedPeer
	c.p2pMux = mux
	c.p2pCloseCh = p2pCloseCh
	atomic.StoreUint32(&c.p2pMode, 1)
	c.mu.Unlock()

	peerAddrStr := confirmedPeer.String()
	encrypted := cipher != nil
	log.Info().
		Str("peer", peerAddrStr).
		Str("local", conn.LocalAddr().String()).
		Bool("encrypted", encrypted).
		Bool("initiator", isInitiator).
		Msg("P2P connection established (mux)")

	// Notify server of successful P2P connection.
	c.sendP2PResult(ctx, true, peerAddrStr, "")

	// Accept incoming P2P streams and proxy them to local service.
	go c.acceptP2PStreams(ctx, mux, p2pCloseCh)

	if encrypted {
		fmt.Printf("  🎉 P2P Mode: Direct connection to %s (encrypted)\n", peerAddrStr)
	} else {
		fmt.Printf("  🎉 P2P Mode: Direct connection to %s\n", peerAddrStr)
	}
}

// acceptP2PStreams accepts incoming multiplexed P2P streams and proxies each
// one to the local service — exactly like the relay path but over P2P UDP.
func (c *Client) acceptP2PStreams(ctx context.Context, mux *p2p.UDPMux, closeCh chan struct{}) {
	log.Info().Msg("P2P accept loop started")
	defer log.Info().Msg("P2P accept loop stopped")

	for {
		select {
		case <-closeCh:
			return
		case <-c.closeCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		stream, err := mux.AcceptStream()
		if err != nil {
			if mux.IsClosed() {
				c.fallbackToRelay("P2P mux closed")
				return
			}
			log.Warn().Err(err).Msg("P2P accept stream error, falling back to relay")
			c.fallbackToRelay("P2P accept error")
			return
		}

		// Each stream carries one logical request: read the StreamRequest
		// header (length-prefixed protobuf) then proxy to local service.
		go func(s *p2p.UDPStream) {
			defer s.Close()

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

			atomic.AddUint64(&c.stats.Requests, 1)
			c.forwardToLocal(ctx, s, msg.StreamRequest)
		}(stream)
	}
}

// parseEndpoint parses a string address into a p2p.Endpoint.
func (c *Client) parseEndpoint(addr string) (p2p.Endpoint, error) {
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

// sendP2PResult sends the P2P connection result to the server.
func (c *Client) sendP2PResult(ctx context.Context, success bool, peerAddr, errMsg string) {
	c.mu.Lock()
	mux := c.mux
	tunnelID := c.tunnelID
	c.mu.Unlock()

	if mux == nil || mux.IsClosed() {
		return
	}

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

	if _, err := stream.Write(data); err != nil {
		log.Debug().Err(err).Msg("Failed to send P2P result")
		return
	}

	log.Debug().
		Bool("success", success).
		Str("peer_addr", peerAddr).
		Msg("P2P result sent to server")
}

// IsP2PMode returns whether the client is using P2P mode.
func (c *Client) IsP2PMode() bool {
	return atomic.LoadUint32(&c.p2pMode) == 1
}

// handleP2PNotification handles incoming P2P notifications from the server.
// This is called when another client wants to establish a P2P connection with us.
func (c *Client) handleP2PNotification(ctx context.Context, resp *proto.P2POfferResponse) {
	if !resp.Success || resp.PeerAddr == "" {
		return
	}

	log.Info().
		Str("peer_addr", resp.PeerAddr).
		Str("peer_nat", resp.PeerNATType).
		Bool("has_peer_key", resp.PeerPublicKey != "").
		Msg("Received P2P notification from server, attempting connection")

	// Generate our ECDH key pair if not already done.
	c.mu.Lock()
	if c.p2pKeyPair == nil {
		keyPair, keyErr := p2p.GenerateKeyPair()
		if keyErr != nil {
			c.mu.Unlock()
			log.Error().Err(keyErr).Msg("Failed to generate ECDH key pair for P2P notification")
			return
		}
		c.p2pKeyPair = keyPair
	}
	c.mu.Unlock()

	// Derive session cipher from peer's public key if available.
	if resp.PeerPublicKey != "" {
		if derivErr := c.deriveP2PCipher(resp.PeerPublicKey); derivErr != nil {
			log.Error().Err(derivErr).Msg("Failed to derive P2P session cipher from notification")
			return
		}
	}

	// Notified side is the acceptor for stream-ID allocation.
	go c.attemptP2P(ctx, resp.PeerAddr, false)
}

// fallbackToRelay switches from P2P back to relay mode.
func (c *Client) fallbackToRelay(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Only fallback if currently in P2P mode.
	if atomic.LoadUint32(&c.p2pMode) != 1 {
		return
	}

	log.Info().Str("reason", reason).Msg("Falling back to relay mode")

	// Close P2P resources.
	if c.p2pMux != nil {
		_ = c.p2pMux.Close()
		c.p2pMux = nil
	}
	if c.p2pConn != nil {
		_ = c.p2pConn.Close()
		c.p2pConn = nil
	}
	c.p2pPeer = nil
	if c.p2pCloseCh != nil {
		close(c.p2pCloseCh)
		c.p2pCloseCh = nil
	}
	// Clear crypto state so a fresh key pair is generated on next attempt.
	c.p2pKeyPair = nil
	c.p2pCipher = nil

	// Set mode back to relay.
	atomic.StoreUint32(&c.p2pMode, 0)

	// Notify manager.
	c.p2pManager.FallbackToRelay(reason)

	fmt.Printf("  ⚠️  Switched to Relay mode: %s\n", reason)
}

// GetP2PManager returns the P2P manager instance.
func (c *Client) GetP2PManager() *p2p.Manager {
	return c.p2pManager
}

// Close closes the client.
// It performs graceful shutdown by sending a CloseRequest to the server
// before tearing down the connection.
//
//nolint:gocyclo // shutdown must coordinate all subsystems in one place
func (c *Client) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	// Graceful shutdown: send CloseRequest to server before closing.
	c.mu.Lock()
	mux := c.mux
	tunnelID := c.tunnelID
	c.mu.Unlock()

	if mux != nil && !mux.IsClosed() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// In multi-tunnel mode, close all active tunnels.
		c.activeTunnelsMu.RLock()
		for _, at := range c.activeTunnels {
			if err := c.CloseTunnel(ctx, at.TunnelID, "client shutting down"); err != nil {
				log.Debug().Err(err).Str("tunnel", at.Def.Name).Msg("Graceful tunnel close failed")
			}
		}
		c.activeTunnelsMu.RUnlock()
		// Single-tunnel mode fallback.
		if tunnelID != "" {
			if err := c.CloseTunnel(ctx, tunnelID, "client shutting down"); err != nil {
				log.Debug().Err(err).Msg("Graceful tunnel close failed (proceeding with shutdown)")
			}
		}
		cancel()
	}

	// Stop control server.
	if c.ctrlServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = c.ctrlServer.Shutdown(shutdownCtx)
		cancel()
	}

	close(c.closeCh)

	c.mu.Lock()
	if c.mux != nil {
		_ = c.mux.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	// Close P2P resources in correct order.
	if c.p2pCloseCh != nil {
		close(c.p2pCloseCh)
		c.p2pCloseCh = nil
	}
	if c.p2pMux != nil {
		_ = c.p2pMux.Close()
		c.p2pMux = nil
	}
	if c.p2pConn != nil {
		_ = c.p2pConn.Close()
		c.p2pConn = nil
	}
	c.p2pPeer = nil
	if c.inspectorServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = c.inspectorServer.Shutdown(shutdownCtx)
		shutdownCancel()
	}
	if c.inspectorHandler != nil {
		c.inspectorHandler.Close()
	}
	if c.inspector != nil {
		c.inspector.Close()
	}
	c.mu.Unlock()

	c.closeWg.Wait()
	return nil
}

// IsConnected returns whether the client is connected.
func (c *Client) IsConnected() bool {
	return atomic.LoadUint32(&c.connected) == 1
}

// GetStats returns client statistics.
func (c *Client) GetStats() Stats {
	return Stats{
		BytesIn:        atomic.LoadUint64(&c.stats.BytesIn),
		BytesOut:       atomic.LoadUint64(&c.stats.BytesOut),
		Requests:       atomic.LoadUint64(&c.stats.Requests),
		Reconnects:     atomic.LoadUint64(&c.stats.Reconnects),
		ConnectionTime: c.stats.ConnectionTime,
	}
}

// RequestStats sends a StatsRequest to the server and returns the session statistics.
func (c *Client) RequestStats(ctx context.Context) (*proto.StatsResponse, error) {
	c.mu.Lock()
	mux := c.mux
	sessionID := c.sessionID
	c.mu.Unlock()

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

	if _, writeErr := stream.Write(data); writeErr != nil {
		return nil, fmt.Errorf("write stats request: %w", writeErr)
	}

	// Read response.
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
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
func (c *Client) CloseTunnel(ctx context.Context, tunnelID, reason string) error {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

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

	if _, writeErr := stream.Write(data); writeErr != nil {
		return fmt.Errorf("write close request: %w", writeErr)
	}

	// Read response.
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
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

// StartInspector starts the inspector UI server.
func (c *Client) StartInspector(port int) error {
	if port == 0 {
		return nil
	}

	host := c.config.InspectorHost
	if host == "" {
		host = defaultLocalHost
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Info().Str("addr", addr).Msg("Starting inspector UI")

	// Create inspector handler.
	c.inspectorHandler = inspector.NewHandler(c.inspector)

	// Create web server with API and static file serving.
	handler := web.NewServer(web.ServerConfig{
		APIHandler:      c.inspectorHandler,
		FallbackToIndex: true,
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // Disable for WebSocket long-lived connections.
		IdleTimeout:  60 * time.Second,
	}
	c.inspectorServer = server
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Inspector server error")
		}
	}()

	fmt.Printf("  Inspector: http://localhost:%d\n", port)
	return nil
}

// GetInspector returns the inspector instance.
func (c *Client) GetInspector() *inspector.Inspector {
	return c.inspector
}

// parseProtocol converts a protocol string to a proto.Protocol value.
// Returns proto.ProtocolHTTP if the input is empty or unrecognized.
func parseProtocol(s string) proto.Protocol {
	switch strings.ToLower(s) {
	case "http", "":
		return proto.ProtocolHTTP
	case "https":
		return proto.ProtocolHTTPS
	case "tcp":
		return proto.ProtocolTCP
	case "udp":
		return proto.ProtocolUDP
	case "ws", "websocket":
		return proto.ProtocolWebSocket
	case "grpc":
		return proto.ProtocolGRPC
	default:
		return proto.ProtocolHTTP
	}
}
