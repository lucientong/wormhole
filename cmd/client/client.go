package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wormhole-tunnel/wormhole/pkg/inspector"
	"github.com/wormhole-tunnel/wormhole/pkg/p2p"
	"github.com/wormhole-tunnel/wormhole/pkg/proto"
	"github.com/wormhole-tunnel/wormhole/pkg/tunnel"
	"github.com/wormhole-tunnel/wormhole/pkg/version"
	"github.com/wormhole-tunnel/wormhole/pkg/web"
)

// Client is the wormhole client.
type Client struct {
	config Config

	// Connection state
	mux       *tunnel.Mux
	conn      net.Conn
	connected uint32
	publicURL string
	tunnelID  string

	// Inspector
	inspector        *inspector.Inspector
	inspectorHandler *inspector.Handler
	inspectorServer  *http.Server

	// P2P
	p2pManager *p2p.Manager

	// Statistics
	stats ClientStats

	// Shutdown
	closed  uint32
	closeCh chan struct{}
	closeWg sync.WaitGroup
	mu      sync.Mutex
}

// ClientStats contains client statistics.
type ClientStats struct {
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
		config:     config,
		inspector:  insp,
		p2pManager: p2p.NewManager(p2pConfig),
		closeCh:    make(chan struct{}),
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
		log.Warn().Msg("Connection lost, reconnecting...")
	}
}

// connect establishes a connection to the server.
func (c *Client) connect(ctx context.Context) error {
	// Dial server
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
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

	// Register tunnel
	if err := c.registerTunnel(ctx); err != nil {
		_ = mux.Close()
		_ = conn.Close()
		return fmt.Errorf("register tunnel: %w", err)
	}

	return nil
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
	req := proto.NewRegisterRequest(uint32(c.config.LocalPort), proto.ProtocolHTTP, c.config.Subdomain) // #nosec G115
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
	fmt.Printf("  Forwarding: %s -> http://%s:%d\n", resp.PublicURL, c.config.LocalHost, c.config.LocalPort)
	fmt.Printf("  Version:    %s\n", version.Short())
	if c.p2pManager != nil && c.p2pManager.NATInfo() != nil {
		info := c.p2pManager.NATInfo()
		fmt.Printf("  NAT Type:   %s\n", info.Type)
		fmt.Printf("  Public:     %s\n", info.PublicAddr)
		fmt.Printf("  P2P Mode:   %s\n", c.p2pManager.Mode())
	}
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop\n")
	fmt.Printf("\n")

	return nil
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

		go c.handleStream(stream) //nolint:contextcheck // stream handling runs as background goroutine
	}
}

// handleStream handles an incoming stream from the server.
func (c *Client) handleStream(stream *tunnel.Stream) {
	defer stream.Close()

	// Read stream request
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		log.Error().Err(err).Msg("Read stream request failed")
		return
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		log.Error().Err(err).Msg("Decode stream request failed")
		return
	}

	if msg.StreamRequest == nil {
		log.Warn().Msg("Expected stream request")
		return
	}

	req := msg.StreamRequest
	atomic.AddUint64(&c.stats.Requests, 1)

	// Forward to local service
	c.forwardToLocal(stream, req)
}

// forwardToLocal forwards a stream to the local service.
func (c *Client) forwardToLocal(stream *tunnel.Stream, req *proto.StreamRequest) {
	// Use HTTP-aware forwarding when inspector is active and protocol is HTTP.
	if req.Protocol == proto.ProtocolHTTP && c.inspector.IsEnabled() {
		c.forwardHTTPWithInspect(stream, req)
		return
	}

	// Fallback: raw TCP bidirectional proxy.
	c.forwardRawTCP(stream, req)
}

// forwardRawTCP forwards a stream to the local service using raw TCP proxy.
func (c *Client) forwardRawTCP(stream *tunnel.Stream, req *proto.StreamRequest) {
	c.dialAndProxy(stream, stream, req)
}

// forwardRawTCPWithReader is like forwardRawTCP but uses a custom reader
// for the stream->local direction (used when we've partially consumed the stream).
func (c *Client) forwardRawTCPWithReader(reader io.Reader, stream *tunnel.Stream, sreq *proto.StreamRequest) {
	c.dialAndProxy(reader, stream, sreq)
}

// dialAndProxy connects to the local service and proxies data bidirectionally
// between the given reader/writer pair and the local connection.
func (c *Client) dialAndProxy(inReader io.Reader, outWriter io.Writer, sreq *proto.StreamRequest) {
	localAddr := net.JoinHostPort(c.config.LocalHost, fmt.Sprintf("%d", c.config.LocalPort))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	localConn, err := dialer.DialContext(context.Background(), "tcp", localAddr)
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
func (c *Client) forwardHTTPWithInspect(stream *tunnel.Stream, sreq *proto.StreamRequest) {
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
			c.forwardRawTCPWithReader(combined, stream, sreq)
		} else {
			c.forwardRawTCP(stream, sreq)
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
	httpReq.URL.Scheme = "http"
	httpReq.URL.Host = localAddr
	httpReq.Body = io.NopCloser(bytes.NewReader(reqBody))
	httpReq.ContentLength = int64(len(reqBody))
	httpReq.RequestURI = "" // Must clear for http.Transport.

	// Use a transport that connects to the local service.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local service may use self-signed certs
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

		errResp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("Local service unavailable")),
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
func (c *Client) sendP2POffer(ctx context.Context) {
	natInfo := c.p2pManager.NATInfo()
	if natInfo == nil {
		return
	}

	c.mu.Lock()
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

	req := proto.NewP2POfferRequest(
		tunnelID,
		natInfo.Type.String(),
		natInfo.PublicAddr.String(),
		natInfo.LocalAddr.String(),
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
		log.Info().
			Str("peer_addr", resp.PeerAddr).
			Str("peer_nat", resp.PeerNATType).
			Msg("P2P peer found, attempting connection")
		// TODO: Initiate hole punching with the peer endpoint.
	} else {
		log.Debug().
			Str("reason", resp.Error).
			Msg("P2P offer: no peer available, staying in relay mode")
	}
}

// GetP2PManager returns the P2P manager instance.
func (c *Client) GetP2PManager() *p2p.Manager {
	return c.p2pManager
}

// Close closes the client.
func (c *Client) Close() error { //nolint:unparam // satisfies io.Closer interface
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	close(c.closeCh)

	c.mu.Lock()
	if c.mux != nil {
		_ = c.mux.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
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
func (c *Client) GetStats() ClientStats {
	return ClientStats{
		BytesIn:        atomic.LoadUint64(&c.stats.BytesIn),
		BytesOut:       atomic.LoadUint64(&c.stats.BytesOut),
		Requests:       atomic.LoadUint64(&c.stats.Requests),
		Reconnects:     atomic.LoadUint64(&c.stats.Reconnects),
		ConnectionTime: c.stats.ConnectionTime,
	}
}

// StartInspector starts the inspector UI server.
func (c *Client) StartInspector(port int) error { //nolint:unparam // error return reserved for future use
	if port == 0 {
		return nil
	}

	addr := net.JoinHostPort("", fmt.Sprintf("%d", port))
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
