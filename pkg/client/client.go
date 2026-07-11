package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/inspector"
	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/web"
	"github.com/rs/zerolog/log"
)

// defaultLocalHost is the default host for local service binding and inspector UI.
const defaultLocalHost = "127.0.0.1"

// protocolHTTP is the canonical string for HTTP tunnel protocol.
const protocolHTTP = "http"

// protocolTCP is the canonical string for TCP dialing and the TCP tunnel protocol.
const protocolTCP = "tcp"

// protocolHTTPS, protocolWebSocket, and protocolGRPC are the canonical
// strings for the remaining supported tunnel protocols (see parseProtocol
// and validProtocolStrings).
const (
	protocolHTTPS     = "https"
	protocolWebSocket = "websocket"
	protocolGRPC      = "grpc"
)

// protocolUDP is the (rejected) tunnel protocol string checked by
// ValidateProtocolString — see validProtocolStrings' doc for why it's not
// in that list (V1: the server has no UDP dataplane).
const protocolUDP = "udp"

// copyBufSize matches the buffer size io.Copy allocates internally by
// default, so pooling it (DP-11) preserves throughput while avoiding a
// fresh 32KB allocation on every proxied local<->tunnel connection.
const copyBufSize = 32 * 1024

// copyBufPool recycles the buffers dialAndProxy and proxyConnectConn use
// for bidirectional proxying (DP-11), reducing steady-state memory
// footprint under many concurrent tunnel connections.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

// copyWithPooledBuffer is a drop-in replacement for io.Copy that borrows
// its scratch buffer from copyBufPool instead of letting io.Copy allocate
// its own default 32KB buffer on every call.
func copyWithPooledBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

// ActiveTunnel holds runtime state for a registered tunnel.
type ActiveTunnel struct {
	Def       TunnelDef
	TunnelID  string
	PublicURL string
	TCPPort   uint32
}

// Client is the wormhole client.
//
// It is a composition root (P3-6 batch D): the actual control-plane
// connection lifecycle (dial/auth/register/heartbeat/reconnect) lives in
// RelayClient, and the `wormhole connect` P2P hole-punching lifecycle
// lives in P2PSession. Client wires the two together — relay's inbound
// P2P notifications are routed to the session, and the session's offers
// are sent over relay's control connection (see RelayChannel) — and owns
// the cross-cutting concerns that don't belong to either: aggregate
// Stats, the inspector, and the optional local control/inspector HTTP
// servers.
type Client struct {
	config Config

	relay *relayClient
	p2p   *p2pSession

	// Statistics, aggregated across both the relay and P2P data paths.
	stats   Stats
	statsMu sync.Mutex

	// Control server (optional; exposes /tunnels for `wormhole tunnels list`).
	ctrlServer *http.Server

	// Inspector
	inspector        *inspector.Inspector
	inspectorHandler *inspector.Handler
	inspectorServer  *http.Server

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
	c := &Client{
		config:    config,
		inspector: insp,
		closeCh:   make(chan struct{}),
	}

	p2pSess := newP2PSession(config, c, c, c.closeCh)
	relay := newRelayClient(config, c, c, p2pSess.manager, c.closeCh, &c.closeWg)
	// Wire the two components together without either depending on the
	// other's concrete type (see RelayClient/P2PSession doc comments).
	relay.setAfterConnect(func(ctx context.Context) {
		p2pSess.MaybeSendOffer(ctx, relay)
	})
	relay.setNotificationHandler(func(ctx context.Context, rc RelayChannel, resp *proto.P2POfferResponse, candidates []string) {
		p2pSess.HandleNotification(ctx, rc, resp, candidates)
	})

	c.relay = relay
	c.p2p = p2pSess
	return c
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
		if err := c.p2p.Init(ctx); err != nil {
			log.Warn().Err(err).Msg("P2P initialization failed, will use relay mode")
		}
	}

	// Connect with reconnection.
	return c.relay.Run(ctx)
}

// localForwarder is the interface RelayClient and P2PSession use to hand
// off an accepted stream carrying a StreamRequest to be proxied to the
// local service. It's implemented by *Client and injected at
// construction time so neither component needs to know about the
// inspector, multi-tunnel routing, or aggregate Stats — all of which are
// identical regardless of whether the stream arrived over the relay or a
// direct P2P connection.
type localForwarder interface {
	forwardToLocal(ctx context.Context, conn streamConn, req *proto.StreamRequest)
}

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
	localHost, localPort := c.relay.ResolveLocalAddr(sreq.TunnelID)
	localAddr := net.JoinHostPort(localHost, fmt.Sprintf("%d", localPort))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	localConn, err := dialer.DialContext(ctx, protocolTCP, localAddr)
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

	// InReader -> Local. When the remote side is done sending (EOF/error
	// on inReader), half-close localConn's write side so the local
	// service sees EOF and can finish responding, instead of leaving it
	// blocked waiting for more input that will never arrive (DP-04):
	// without this, the "Local -> OutWriter" goroutine below could block
	// forever on a local service that never closes its own connection,
	// leaking both goroutines and localConn past dialAndProxy's return.
	go func() {
		defer wg.Done()
		n, copyErr := copyWithPooledBuffer(localConn, inReader)
		if n > 0 {
			c.addBytesIn(uint64(n))
		}
		if copyErr != nil {
			log.Debug().Err(copyErr).Msg("Copy tunnel->local failed")
		}
		if cw, ok := localConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = localConn.Close()
		}
	}()

	// Local -> OutWriter. When the local service is done responding,
	// there's nothing left to proxy from it, so fully close localConn to
	// unblock the InReader -> Local direction above (e.g. a blocked
	// Write to a half-closed peer) instead of leaving it dangling until
	// the remote side happens to close on its own.
	go func() {
		defer wg.Done()
		n, copyErr := copyWithPooledBuffer(outWriter, localConn)
		if n > 0 {
			c.addBytesOut(uint64(n)) // #nosec G115
		}
		if copyErr != nil {
			log.Debug().Err(copyErr).Msg("Copy local->tunnel failed")
		}
		_ = localConn.Close()
	}()

	wg.Wait()
}

// forwardHTTPWithInspect forwards an HTTP request through the tunnel with
// traffic inspection. It parses the raw HTTP request from the stream,
// forwards it to the local service via http.Transport, captures the
// request/response pair in the inspector, and writes the response back.
func (c *Client) forwardHTTPWithInspect(ctx context.Context, stream streamConn, sreq *proto.StreamRequest) {
	localHost, localPort := c.relay.ResolveLocalAddr(sreq.TunnelID)
	localAddr := net.JoinHostPort(localHost, fmt.Sprintf("%d", localPort))

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

	// 2. Read request body for inspection, capped at MaxBodySize+1 (DP-12):
	// this also becomes the body forwarded to the local service below, so
	// enabling the inspector trades unbounded body size for a bounded
	// memory footprint — consistent with Inspector.Wrap's same trade-off
	// and with the "limited by MaxBodySize" comment this code already
	// claimed to implement (previously untrue: io.ReadAll had no cap and
	// could OOM on a large upload).
	maxBody := c.inspector.MaxBodySize()
	var reqBody []byte
	if httpReq.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(httpReq.Body, maxBody+1))
	}

	// Track bytes in.
	c.addBytesIn(uint64(len(reqBody)))

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

	// 5. Read response body for inspection, same MaxBodySize+1 cap as the
	// request body above (DP-12) — it also becomes the body written back
	// to the stream in step 6, so this bounds memory for large downloads
	// too, not just uploads.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))

	// Track bytes out.
	c.addBytesOut(uint64(len(respBody)))

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

// addBytesIn, addBytesOut, addRequest, addReconnect, and setConnectionTime
// implement statsRecorder, letting RelayClient/P2PSession record traffic
// into Client's aggregate Stats without owning it themselves.
func (c *Client) addBytesIn(n uint64)  { atomic.AddUint64(&c.stats.BytesIn, n) }
func (c *Client) addBytesOut(n uint64) { atomic.AddUint64(&c.stats.BytesOut, n) }
func (c *Client) addRequest()          { atomic.AddUint64(&c.stats.Requests, 1) }
func (c *Client) addReconnect()        { atomic.AddUint64(&c.stats.Reconnects, 1) }

func (c *Client) setConnectionTime(t time.Time) {
	c.statsMu.Lock()
	c.stats.ConnectionTime = t
	c.statsMu.Unlock()
}

// IsP2PMode returns whether the client is using P2P mode.
func (c *Client) IsP2PMode() bool {
	return c.p2p.IsP2PMode()
}

// GetP2PManager returns the P2P manager instance.
func (c *Client) GetP2PManager() *p2p.Manager {
	return c.p2p.Manager()
}

// IsConnected returns whether the client is connected.
func (c *Client) IsConnected() bool {
	return c.relay.IsConnected()
}

// GetStats returns client statistics.
func (c *Client) GetStats() Stats {
	c.statsMu.Lock()
	connTime := c.stats.ConnectionTime
	c.statsMu.Unlock()

	return Stats{
		BytesIn:        atomic.LoadUint64(&c.stats.BytesIn),
		BytesOut:       atomic.LoadUint64(&c.stats.BytesOut),
		Requests:       atomic.LoadUint64(&c.stats.Requests),
		Reconnects:     atomic.LoadUint64(&c.stats.Reconnects),
		ConnectionTime: connTime,
	}
}

// RequestStats sends a StatsRequest to the server and returns the session statistics.
func (c *Client) RequestStats(ctx context.Context) (*proto.StatsResponse, error) {
	return c.relay.RequestStats(ctx)
}

// CloseTunnel sends a CloseRequest to the server to gracefully close a tunnel.
func (c *Client) CloseTunnel(ctx context.Context, tunnelID, reason string) error {
	return c.relay.CloseTunnel(ctx, tunnelID, reason)
}

// ListActiveTunnels returns a copy of the currently active tunnels.
func (c *Client) ListActiveTunnels() []ActiveTunnel {
	return c.relay.ListActiveTunnels()
}

// ReloadTunnels updates the active tunnel set based on a new list of
// definitions. See RelayClient.ReloadTunnels.
func (c *Client) ReloadTunnels(ctx context.Context, newDefs []TunnelDef) {
	c.relay.ReloadTunnels(ctx, newDefs)
}

// CreateTunnel registers a single new tunnel on an already-connected
// client (U1). See RelayClient.CreateTunnel.
func (c *Client) CreateTunnel(ctx context.Context, def TunnelDef) (*ActiveTunnel, error) {
	return c.relay.CreateTunnel(ctx, def)
}

// DeleteTunnel closes and removes a single active tunnel by name (U1).
// See RelayClient.DeleteTunnel.
func (c *Client) DeleteTunnel(ctx context.Context, name string) error {
	return c.relay.DeleteTunnel(ctx, name)
}

// Close closes the client.
// It performs graceful shutdown by sending a CloseRequest to the server
// before tearing down the connection.
func (c *Client) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	// Graceful shutdown: close all active tunnels before tearing down
	// the connection (no-op if not currently connected).
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c.relay.CloseAllTunnels(closeCtx, "client shutting down")
	cancel()

	// Stop control server.
	c.mu.Lock()
	if c.ctrlServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = c.ctrlServer.Shutdown(shutdownCtx)
		shutdownCancel()
	}
	c.mu.Unlock()

	close(c.closeCh)

	c.relay.Close()
	c.p2p.Close()

	c.mu.Lock()
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
// Returns proto.ProtocolHTTP if the input is empty or unrecognized. Callers
// that need to surface a real error for an invalid --protocol/config value
// should call ValidateProtocolString first — this function is intentionally
// total (never errors) since it also backs runtime dispatch, which must
// have some deterministic fallback if validation is ever bypassed.
func parseProtocol(s string) proto.Protocol {
	switch strings.ToLower(s) {
	case protocolHTTP, "":
		return proto.ProtocolHTTP
	case protocolHTTPS:
		return proto.ProtocolHTTPS
	case protocolTCP:
		return proto.ProtocolTCP
	case "ws", protocolWebSocket:
		return proto.ProtocolWebSocket
	case protocolGRPC:
		return proto.ProtocolGRPC
	default:
		return proto.ProtocolHTTP
	}
}

// validProtocolStrings lists the tunnel protocol values accepted by
// --protocol / the YAML config file's protocol field. UDP is deliberately
// excluded (V1): the server has no UDP dataplane handling at all — it would
// silently register the tunnel as if it were HTTP, which is broken and
// misleading rather than merely unsupported. Once the server implements a
// real UDP tunnel path, add it back here alongside the server-side work.
var validProtocolStrings = []string{protocolHTTP, protocolHTTPS, protocolTCP, "ws", protocolWebSocket, protocolGRPC}

// ValidateProtocolString returns an error if s isn't empty and isn't one of
// validProtocolStrings — in particular, it rejects "udp" with a specific,
// actionable message instead of the generic "invalid protocol" error, since
// that's the one value most likely to be tried based on stale docs/habit
// from other tunnel tools.
func ValidateProtocolString(s string) error {
	if s == "" {
		return nil
	}
	lower := strings.ToLower(s)
	if lower == protocolUDP {
		return fmt.Errorf("protocol %q is not supported: the server has no UDP dataplane implementation yet (tracked as a future enhancement); use tcp for a raw byte-stream tunnel instead", s)
	}
	if slices.Contains(validProtocolStrings, lower) {
		return nil
	}
	return fmt.Errorf("invalid protocol %q: must be one of %s", s, strings.Join(validProtocolStrings, ", "))
}
