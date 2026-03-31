package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wormhole-tunnel/wormhole/pkg/proto"
	"github.com/wormhole-tunnel/wormhole/pkg/tunnel"
	"github.com/wormhole-tunnel/wormhole/pkg/version"
)

// Client is the wormhole client.
type Client struct {
	config Config

	// Connection state
	mux        *tunnel.Mux
	conn       net.Conn
	connected  uint32
	sessionID  string
	subdomain  string
	publicURL  string
	tunnelID   string

	// Statistics
	stats ClientStats

	// Shutdown
	closed   uint32
	closeCh  chan struct{}
	closeWg  sync.WaitGroup
	mu       sync.Mutex
}

// ClientStats contains client statistics.
type ClientStats struct {
	BytesIn         uint64
	BytesOut        uint64
	Requests        uint64
	Reconnects      uint64
	ConnectionTime  time.Time
}

// NewClient creates a new client instance.
func NewClient(config Config) *Client {
	return &Client{
		config:  config,
		closeCh: make(chan struct{}),
	}
}

// Start starts the client.
func (c *Client) Start(ctx context.Context) error {
	log.Info().
		Str("server", c.config.ServerAddr).
		Int("local_port", c.config.LocalPort).
		Str("local_host", c.config.LocalHost).
		Msg("Starting Wormhole client")

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
		conn.Close()
		return fmt.Errorf("create mux: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mux = mux
	c.stats.ConnectionTime = time.Now()
	c.mu.Unlock()

	atomic.StoreUint32(&c.connected, 1)

	log.Info().Str("server", c.config.ServerAddr).Msg("Connected to server")

	// Register tunnel
	if err := c.registerTunnel(); err != nil {
		mux.Close()
		conn.Close()
		return fmt.Errorf("register tunnel: %w", err)
	}

	return nil
}

// registerTunnel registers a tunnel with the server.
func (c *Client) registerTunnel() error {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

	if mux == nil {
		return fmt.Errorf("not connected")
	}

	// Open control stream
	stream, err := mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Send register request
	req := proto.NewRegisterRequest(uint32(c.config.LocalPort), proto.ProtocolHTTP, c.config.Subdomain)
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("write request: %w", err)
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

	// Wait for connection to close
	<-ctx.Done()

	c.mu.Lock()
	if c.mux != nil {
		c.mux.Close()
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

		go c.handleStream(stream)
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
	// Connect to local service
	localAddr := fmt.Sprintf("%s:%d", c.config.LocalHost, c.config.LocalPort)
	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		log.Error().Err(err).Str("addr", localAddr).Msg("Connect to local failed")
		// Send error response
		resp := proto.NewStreamResponse(req.RequestID, false, "Local service unavailable")
		data, _ := resp.Encode()
		stream.Write(data)
		return
	}
	defer localConn.Close()

	// For HTTP, the stream already contains the HTTP request
	// Just proxy the data bidirectionally

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> Local
	go func() {
		defer wg.Done()
		n, _ := io.Copy(localConn, stream)
		atomic.AddUint64(&c.stats.BytesIn, uint64(n))
	}()

	// Local -> Stream
	go func() {
		defer wg.Done()
		n, _ := io.Copy(stream, localConn)
		atomic.AddUint64(&c.stats.BytesOut, uint64(n))
	}()

	wg.Wait()
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
			if err := c.sendPing(pingID); err != nil {
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
func (c *Client) sendPing(pingID uint64) error {
	c.mu.Lock()
	mux := c.mux
	c.mu.Unlock()

	if mux == nil {
		return fmt.Errorf("not connected")
	}

	stream, err := mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	req := proto.NewPingRequest(pingID)
	data, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode ping: %w", err)
	}

	stream.SetDeadline(time.Now().Add(c.config.HeartbeatTimeout))

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

// Close closes the client.
func (c *Client) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	close(c.closeCh)

	c.mu.Lock()
	if c.mux != nil {
		c.mux.Close()
	}
	if c.conn != nil {
		c.conn.Close()
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
func (c *Client) StartInspector(port int) error {
	if port == 0 {
		return nil
	}

	addr := fmt.Sprintf(":%d", port)
	log.Info().Str("addr", addr).Msg("Starting inspector UI")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Inspector UI - Coming soon!"))
	})

	go http.ListenAndServe(addr, nil)
	return nil
}
