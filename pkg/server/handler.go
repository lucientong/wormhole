package server

import (
	"bufio"
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/rs/zerolog/log"
)

// HTTPHandler handles incoming HTTP requests and routes them through tunnels.
type HTTPHandler struct {
	router *Router
	server *Server
}

// NewHTTPHandler creates a new HTTP handler.
func NewHTTPHandler(router *Router, server *Server) *HTTPHandler {
	return &HTTPHandler{
		router: router,
		server: server,
	}
}

// ServeHTTP implements http.Handler.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Route request to client.
	client := h.router.Route(r.Host, r.URL.Path)
	if client == nil {
		h.notFound(w, r)
		// Record metrics for unrouted requests.
		if h.server.metrics != nil {
			h.server.metrics.RequestsTotal.WithLabelValues("http", "not_found").Inc()
			h.server.metrics.RequestDurationSeconds.Observe(time.Since(start).Seconds())
		}
		return
	}

	// Check if this is a WebSocket upgrade request.
	if isWebSocketUpgrade(r) {
		h.handleWebSocket(client, w, r)
		return
	}

	// Forward HTTP request.
	fwdErr := h.forwardHTTP(client, w, r, start)
	if fwdErr != nil {
		log.Error().
			Err(fwdErr).
			Str("host", r.Host).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg("Forward HTTP failed")
		http.Error(w, "Tunnel error", http.StatusBadGateway)
	}

	// Record metrics.
	if h.server.metrics != nil {
		status := "success"
		if fwdErr != nil {
			status = "error"
		}
		h.server.metrics.RequestsTotal.WithLabelValues("http", status).Inc()
		h.server.metrics.RequestDurationSeconds.Observe(time.Since(start).Seconds())
	}

	atomic.AddUint64(&h.server.stats.Requests, 1)
}

// forwardHTTP forwards an HTTP request through the tunnel to the client.
func (h *HTTPHandler) forwardHTTP(client *ClientSession, w http.ResponseWriter, r *http.Request, start time.Time) error {
	// Open stream to client.
	stream, err := client.Mux.OpenStreamContext(r.Context())
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Send stream request metadata.
	if sendErr := h.sendStreamRequest(stream, client, r); sendErr != nil {
		return sendErr
	}

	// Write raw HTTP request to stream.
	if writeErr := r.Write(stream); writeErr != nil {
		return fmt.Errorf("write http request: %w", writeErr)
	}

	// Read response from stream and write back to client.
	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	// Copy response headers.
	copyHeaders(w.Header(), resp.Header)

	// Add tunnel headers.
	w.Header().Set("X-Wormhole-Tunnel", client.Subdomain)
	w.Header().Set("X-Wormhole-Duration", time.Since(start).String())

	// Write status code and body.
	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, resp.Body)

	// Update stats.
	atomic.AddUint64(&client.BytesOut, uint64(written)) // #nosec G115 -- written from io.Copy is always non-negative
	if h.server.metrics != nil {
		h.server.metrics.BytesTransferredTotal.WithLabelValues("out").Add(float64(written))
	}

	return nil
}

// handleWebSocket upgrades the connection to WebSocket and proxies bidirectionally.
func (h *HTTPHandler) handleWebSocket(client *ClientSession, w http.ResponseWriter, r *http.Request) {
	// Hijack the connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		log.Error().Err(err).Msg("Hijack failed")
		return
	}
	defer clientConn.Close()

	// Open stream to tunnel client.
	stream, streamErr := client.Mux.OpenStreamContext(r.Context())
	if streamErr != nil {
		log.Error().Err(streamErr).Msg("Open stream for WebSocket failed")
		return
	}
	defer stream.Close()

	// Send stream request.
	if sendErr := h.sendStreamRequest(stream, client, r); sendErr != nil {
		log.Error().Err(sendErr).Msg("Send stream request for WebSocket failed")
		return
	}

	// Write the original HTTP upgrade request to the tunnel stream.
	if writeErr := r.Write(stream); writeErr != nil {
		log.Error().Err(writeErr).Msg("Write WebSocket upgrade request failed")
		return
	}

	// Flush any buffered data.
	if buf.Reader.Buffered() > 0 {
		buffered := make([]byte, buf.Reader.Buffered())
		if _, readErr := buf.Read(buffered); readErr == nil {
			_, _ = stream.Write(buffered)
		}
	}

	// Bidirectional proxy.
	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(clientConn, stream)
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(stream, clientConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish.
	<-done
}

// sendStreamRequest sends the stream metadata to the tunnel client.
func (h *HTTPHandler) sendStreamRequest(stream *tunnel.Stream, client *ClientSession, r *http.Request) error {
	_ = client // client is available for future use (e.g., selecting tunnel ID)

	streamReq := proto.NewStreamRequest("", generateID(), r.RemoteAddr, proto.ProtocolHTTP)
	streamReq.StreamRequest.HTTPMetadata = &proto.HTTPMetadata{
		Method:        r.Method,
		URI:           r.RequestURI,
		Host:          r.Host,
		ContentType:   r.Header.Get("Content-Type"),
		ContentLength: r.ContentLength,
	}

	return proto.WriteControlMessage(stream, streamReq)
}

// notFound returns a styled 404 page.
func (h *HTTPHandler) notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	safeHost := html.EscapeString(r.Host)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Wormhole - Tunnel Not Found</title></head>
<body style="font-family:system-ui;text-align:center;padding:50px;background:#0d1117;color:#f0f6fc">
<h1>🕳️ Tunnel Not Found</h1>
<p>No tunnel is currently serving <strong>%s</strong></p>
<p style="color:#8b949e;font-size:14px">Make sure your Wormhole client is running.</p>
</body>
</html>`, safeHost)
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// copyHeaders copies HTTP headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		// Skip hop-by-hop headers.
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// isHopByHop checks if the header is a hop-by-hop header that should not be forwarded.
func isHopByHop(header string) bool {
	switch strings.ToLower(header) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailers", "transfer-encoding":
		return true
	default:
		return false
	}
}

// TCPPortAllocator manages TCP port allocation for raw TCP tunnels.
type TCPPortAllocator struct {
	start    int
	end      int
	nextPort int
	used     map[int]net.Listener
	mu       sync.Mutex
}

// NewTCPPortAllocator creates a new port allocator for the given range.
func NewTCPPortAllocator(start, end int) *TCPPortAllocator {
	return &TCPPortAllocator{
		start:    start,
		end:      end,
		nextPort: start,
		used:     make(map[int]net.Listener),
	}
}

// Allocate allocates a TCP port and starts listening on it.
// Returns the port number and the listener.
func (a *TCPPortAllocator) Allocate(ctx context.Context) (int, net.Listener, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Search for an available port.
	checked := 0
	for checked < (a.end - a.start) {
		port := a.nextPort
		a.nextPort++
		if a.nextPort >= a.end {
			a.nextPort = a.start
		}
		checked++

		if _, exists := a.used[port]; exists {
			continue
		}

		// Try to listen on this port.
		lc := net.ListenConfig{}
		ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue // Port in use by OS, try next.
		}

		a.used[port] = ln
		return port, ln, nil
	}

	return 0, nil, fmt.Errorf("no available ports in range %d-%d", a.start, a.end)
}

// Release releases a previously allocated port.
func (a *TCPPortAllocator) Release(port int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ln, exists := a.used[port]; exists {
		_ = ln.Close()
		delete(a.used, port)
	}
}

// CloseAll closes all allocated port listeners.
func (a *TCPPortAllocator) CloseAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for port, ln := range a.used {
		_ = ln.Close()
		delete(a.used, port)
	}
}

// AllocatedPorts returns the count of currently allocated ports.
func (a *TCPPortAllocator) AllocatedPorts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}
