package server

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/rs/zerolog/log"
)

// clusterSecretHeader carries the shared cluster secret on requests
// forwarded between nodes by ServeHTTP's cross-node proxy path (S1), so a
// receiving node can tell a genuine peer hop apart from an external
// caller that happens to reach ClusterNodeAddr directly.
const clusterSecretHeader = "X-Wormhole-Cluster-Secret" // #nosec G101 -- header name, not a credential

// schemeHTTP is the scheme wormhole speaks internally: to tunnel clients
// (proxyToNode), between cluster peers, and for unencrypted public URLs.
// TLS termination (when Config.TLSEnabled) happens at the edge listener,
// not on these internal/public-URL-string call sites.
const schemeHTTP = "http"

// errStreamSlotSaturated is returned by tryAcquireStreamSlot when either
// the global or per-client data-plane stream cap (DP-03/DP-27) is full.
var errStreamSlotSaturated = errors.New("server: concurrent stream limit reached")

// copyBufSize matches the buffer size io.Copy would allocate internally by
// default when neither side of a copy implements WriterTo/ReaderFrom, so
// pooling it (DP-11) preserves the existing throughput characteristics
// while avoiding a fresh 32KB allocation on every proxied HTTP response,
// WebSocket connection, and TCP tunnel connection.
const copyBufSize = 32 * 1024

// copyBufPool recycles the buffers copyWithPooledBuffer and
// handleTCPConnection use for proxying (DP-11): forwarding paths are the
// hottest allocation site under concurrent connections (bounded by
// MaxConcurrentStreams, see DP-03/27), so reusing buffers instead of
// allocating fresh ones per connection meaningfully reduces steady-state
// memory footprint and GC pressure.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

// copyWithPooledBuffer is a drop-in replacement for io.Copy that borrows its
// scratch buffer from copyBufPool instead of letting io.Copy allocate its
// own default 32KB buffer on every call.
func copyWithPooledBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

// ProxyService owns the data plane: forwarding HTTP requests, WebSocket
// connections and raw TCP tunnel connections through to the tunnel client
// that owns the target route, plus the concurrent-stream budget (DP-03/27)
// that bounds how many such forwards may be in flight at once.
//
// Extracted from the former HTTPHandler and several Server methods
// (P3-6 Batch D) so the data-forwarding logic — the hottest, most
// performance-sensitive code in the server — has a single owner
// independent of client/route bookkeeping (TunnelRegistry) and P2P
// signaling (P2PBroker).
type ProxyService interface {
	http.Handler
	// ServeTCPTunnel accepts raw TCP connections on ln and proxies each
	// one through to client via the given tunnelID, until ln is closed.
	ServeTCPTunnel(ln net.Listener, client *ClientSession, tunnelID string)
}

// proxyService is ProxyService's concrete, unexported implementation.
type proxyService struct {
	// router is intentionally independent of registry's own router
	// reference (mirrors the pre-Batch-D design, where HTTPHandler held
	// its own *Router rather than reaching through Server): most callers
	// construct both from the same *Router, but tests may inject a
	// different one to exercise routing in isolation.
	router   *Router
	registry TunnelRegistry
	cfg      Config
	metrics  *Metrics
	stats    *Stats

	// serverCtx returns the root lifecycle context to use for operations
	// that should be interrupted by server shutdown (DP-05). Falls back
	// to context.Background() if nil (unit tests constructing a
	// proxyService directly, without a live Server).
	serverCtx func() context.Context

	// activeDataStreams counts data-plane streams currently proxying
	// (HTTP forward, WebSocket, TCP tunnel) across all clients, bounded
	// by cfg.MaxConcurrentStreams (DP-03). Manipulated only via
	// tryAcquireStreamSlot/the release func it returns.
	activeDataStreams int64
}

// newProxyService constructs a ProxyService. ctxFn may be nil, in which
// case operations that would otherwise observe shutdown cancellation
// (DP-05) just use context.Background() instead.
func newProxyService(router *Router, registry TunnelRegistry, cfg Config, metrics *Metrics, stats *Stats, ctxFn func() context.Context) *proxyService {
	return &proxyService{
		router:    router,
		registry:  registry,
		cfg:       cfg,
		metrics:   metrics,
		stats:     stats,
		serverCtx: ctxFn,
	}
}

// ctx returns ps.serverCtx() if set, else context.Background().
func (ps *proxyService) ctx() context.Context {
	if ps.serverCtx != nil {
		return ps.serverCtx()
	}
	return context.Background()
}

// ServeHTTP implements http.Handler.
func (ps *proxyService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// S1: reject requests forged with an invalid cluster-peer secret
	// before doing anything else with them.
	if !ps.verifyClusterSecret(w, r) {
		return
	}

	// Route request to client.
	client := ps.router.Route(r.Host, r.URL.Path)
	if client == nil {
		// Try cluster-wide lookup: maybe the client is on another node.
		// H3: checks hostname/subdomain/path routes, not just subdomain.
		if route := ps.registry.ResolveRemote(r.Host, r.URL.Path); route != nil {
			if !ps.registry.IsLocalNode(route.NodeID) && route.NodeAddr != "" {
				log.Debug().
					Str("node", route.NodeAddr).
					Msg("Cluster: proxying HTTP request to remote node")
				ps.proxyToNode(route.NodeAddr, w, r)
				return
			}
		}

		ps.notFound(w, r)
		// Record metrics for unrouted requests.
		if ps.metrics != nil {
			ps.metrics.RequestsTotal.WithLabelValues("http", "not_found").Inc()
			ps.metrics.RequestDurationSeconds.Observe(time.Since(start).Seconds())
		}
		return
	}

	// DP-03/DP-27: bound concurrent data-plane streams (global and
	// per-client) before opening one for this request, so a saturated
	// server/client fails fast with 503 instead of spawning an unbounded
	// number of proxy goroutines.
	release, slotErr := ps.tryAcquireStreamSlot(client)
	if slotErr != nil {
		http.Error(w, "Server busy: too many concurrent streams", http.StatusServiceUnavailable)
		if ps.metrics != nil {
			ps.metrics.RequestsTotal.WithLabelValues("http", "rejected_saturated").Inc()
		}
		return
	}
	defer release()

	// Check if this is a WebSocket upgrade request.
	if isWebSocketUpgrade(r) {
		ps.handleWebSocket(client, w, r)
		return
	}

	// Forward HTTP request.
	fwdErr := ps.forwardHTTP(client, w, r, start)
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
	if ps.metrics != nil {
		status := "success"
		if fwdErr != nil {
			status = "error"
		}
		ps.metrics.RequestsTotal.WithLabelValues("http", status).Inc()
		ps.metrics.RequestDurationSeconds.Observe(time.Since(start).Seconds())
	}

	if ps.stats != nil {
		atomic.AddUint64(&ps.stats.Requests, 1)
	}
}

// forwardHTTP forwards an HTTP request through the tunnel to the client.
func (ps *proxyService) forwardHTTP(client *ClientSession, w http.ResponseWriter, r *http.Request, start time.Time) error {
	// Open stream to client.
	stream, err := client.Mux.OpenStreamContext(r.Context())
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Send stream request metadata.
	if sendErr := ps.sendStreamRequest(stream, client, r); sendErr != nil {
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
	written, copyErr := copyWithPooledBuffer(w, resp.Body)
	if copyErr != nil {
		// Most commonly a client that disconnected mid-response; not
		// actionable, but worth a debug trace rather than silently
		// discarding it (DP-11).
		log.Debug().Err(copyErr).Str("host", r.Host).Msg("Copy response body to client failed")
	}

	// Update stats.
	atomic.AddUint64(&client.BytesOut, uint64(written)) // #nosec G115 -- written from io.Copy is always non-negative
	if ps.metrics != nil {
		ps.metrics.BytesTransferredTotal.WithLabelValues("out").Add(float64(written))
	}

	return nil
}

// handleWebSocket upgrades the connection to WebSocket and proxies bidirectionally.
func (ps *proxyService) handleWebSocket(client *ClientSession, w http.ResponseWriter, r *http.Request) {
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
	if sendErr := ps.sendStreamRequest(stream, client, r); sendErr != nil {
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
			_, _ = stream.WriteContext(r.Context(), buffered)
		}
	}

	// Bidirectional proxy. As in handleTCPConnection (DP-04), close the
	// *write* side of each direction as soon as its io.Copy finishes, so
	// the other direction's blocked Read unblocks immediately instead of
	// leaking a goroutine until the deferred closes above happen to run.
	// (Closing what a direction *read* from — instead of what it *wrote*
	// to — would leave the peer goroutine's Read with nothing to wake it
	// up, deadlocking both.)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, copyErr := copyWithPooledBuffer(clientConn, stream); copyErr != nil {
			log.Debug().Err(copyErr).Msg("WebSocket copy stream->client failed")
		}
		_ = clientConn.Close()
	}()

	go func() {
		defer wg.Done()
		if _, copyErr := copyWithPooledBuffer(stream, clientConn); copyErr != nil {
			log.Debug().Err(copyErr).Msg("WebSocket copy client->stream failed")
		}
		_ = stream.Close()
	}()

	wg.Wait()
}

// sendStreamRequest sends the stream metadata to the tunnel client.
func (ps *proxyService) sendStreamRequest(stream *tunnel.Stream, client *ClientSession, r *http.Request) error {
	tunnelID := ps.resolveTunnelID(client, r.Host, r.URL.Path)

	streamReq := proto.NewStreamRequest(tunnelID, generateID(), r.RemoteAddr, proto.ProtocolHTTP)
	streamReq.StreamRequest.HTTPMetadata = &proto.HTTPMetadata{
		Method:        r.Method,
		URI:           r.RequestURI,
		Host:          r.Host,
		ContentType:   r.Header.Get("Content-Type"),
		ContentLength: r.ContentLength,
	}

	return proto.WriteControlMessage(stream, streamReq)
}

// resolveTunnelID determines which of the client's registered tunnels a
// given request targets, so the client can dispatch to the correct local
// backend in multi-tunnel mode. Matching precedence mirrors Router.Route:
// custom hostname > subdomain > longest path prefix. When the client has
// registered exactly one tunnel, that tunnel is used unconditionally
// (covers the common single-tunnel case without requiring exact route
// bookkeeping). Returns "" when no unambiguous match is found, in which
// case the client falls back to its single configured local port.
func (ps *proxyService) resolveTunnelID(client *ClientSession, host, path string) string {
	client.mu.Lock()
	tunnels := make([]*TunnelInfo, len(client.Tunnels))
	copy(tunnels, client.Tunnels)
	client.mu.Unlock()

	if len(tunnels) == 0 {
		return ""
	}
	if len(tunnels) == 1 {
		return tunnels[0].ID
	}

	host = strings.ToLower(host)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	if id := matchTunnelByHostname(tunnels, host); id != "" {
		return id
	}
	if id := matchTunnelBySubdomain(tunnels, host, ps.cfg.Domain); id != "" {
		return id
	}
	return matchTunnelByPathPrefix(tunnels, path)
}

// matchTunnelByHostname returns the ID of the tunnel whose custom Hostname
// exactly matches host, or "" if none match.
func matchTunnelByHostname(tunnels []*TunnelInfo, host string) string {
	for _, t := range tunnels {
		if t.Hostname != "" && strings.EqualFold(t.Hostname, host) {
			return t.ID
		}
	}
	return ""
}

// matchTunnelBySubdomain returns the ID of the tunnel whose Subdomain
// matches the label of host under domain, or "" if host isn't a subdomain
// of domain or no tunnel claims that label.
func matchTunnelBySubdomain(tunnels []*TunnelInfo, host, domain string) string {
	suffix := "." + strings.ToLower(domain)
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	sub := host[:len(host)-len(suffix)]
	for _, t := range tunnels {
		if t.Subdomain != "" && strings.EqualFold(t.Subdomain, sub) {
			return t.ID
		}
	}
	return ""
}

// matchTunnelByPathPrefix returns the ID of the tunnel with the longest
// PathPrefix that prefixes path, or "" if no tunnel has a matching prefix.
func matchTunnelByPathPrefix(tunnels []*TunnelInfo, path string) string {
	normPath := normalizePath(path)
	var best *TunnelInfo
	bestLen := 0
	for _, t := range tunnels {
		if t.PathPrefix == "" {
			continue
		}
		p := normalizePath(t.PathPrefix)
		if strings.HasPrefix(normPath, p) && len(p) > bestLen {
			best = t
			bestLen = len(p)
		}
	}
	if best != nil {
		return best.ID
	}
	return ""
}

// notFound returns a styled 404 page.
func (ps *proxyService) notFound(w http.ResponseWriter, r *http.Request) {
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

// validateClusterNodeAddr rejects anything that isn't a bare "host:port"
// pair before it's used to build a proxy target. nodeAddr always
// originates from this cluster's own state store (Config.ClusterNodeAddr,
// announced by other nodes — the same trust boundary verifyClusterSecret
// authenticates, S1) rather than from request content, but validating its
// shape here is cheap defense in depth: it rules out a corrupted or
// malicious state-store entry smuggling a scheme, userinfo, path, or query
// component into the outbound request (e.g. "trusted.internal@evil.com").
// The URL gosec's G704 rule cares about is subsequently rebuilt from the
// validated host/port only, never from the raw string.
func validateClusterNodeAddr(nodeAddr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(nodeAddr)
	if err != nil {
		return "", "", fmt.Errorf("not a host:port pair: %w", err)
	}
	if host == "" {
		return "", "", errors.New("empty host")
	}
	if strings.ContainsAny(host, "/@?#") {
		return "", "", errors.New("host contains disallowed characters")
	}
	return host, port, nil
}

// proxyToNode forwards an HTTP request to the node that owns the route entry.
// It is used for cross-node routing when the target client is connected to a
// different cluster member. When Config.ClusterSecret is set, the forwarded
// request carries it in clusterSecretHeader (S1) so the receiving node can
// distinguish a genuine peer hop from an external caller that reaches
// ClusterNodeAddr directly.
func (ps *proxyService) proxyToNode(nodeAddr string, w http.ResponseWriter, r *http.Request) {
	host, port, err := validateClusterNodeAddr(nodeAddr)
	if err != nil {
		log.Error().Err(err).Str("node_addr", nodeAddr).Msg("Cluster: invalid node address for proxying")
		http.Error(w, "cluster routing error", http.StatusBadGateway)
		return
	}
	// nodeAddr is validated above to be a bare host:port pair announced by
	// a trusted cluster peer (see validateClusterNodeAddr); gosec's G704
	// taint rule has no concept of sanitizers for this check (its own
	// sanitizer list is empty by design — see securego/gosec
	// analyzers/ssrf.go) so it cannot recognize that validation and always
	// flags any *http.Request-derived value reaching NewSingleHostReverseProxy.
	target := &url.URL{Scheme: schemeHTTP, Host: net.JoinHostPort(host, port)} // #nosec G704 -- nodeAddr validated above; see comment
	proxy := httputil.NewSingleHostReverseProxy(target)
	if ps.cfg.ClusterSecret != "" {
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Header.Set(clusterSecretHeader, ps.cfg.ClusterSecret)
		}
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
		log.Error().Err(proxyErr).Str("node_addr", nodeAddr).Msg("Cluster: cross-node proxy error")
		http.Error(rw, "cluster proxy error", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

// verifyClusterSecret implements the receiving side of S1: when
// cfg.ClusterSecret is configured and an inbound request carries
// clusterSecretHeader, the value must match — a present-but-wrong secret
// means someone is trying to impersonate a cluster peer and the request is
// rejected outright. A request with no such header at all is ordinary
// external traffic and is unaffected (most requests never carry it).
// Returns false (having already written a response) if the request should
// be rejected.
func (ps *proxyService) verifyClusterSecret(w http.ResponseWriter, r *http.Request) bool {
	if ps.cfg.ClusterSecret == "" {
		return true
	}
	got := r.Header.Get(clusterSecretHeader)
	if got == "" {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(ps.cfg.ClusterSecret)) != 1 {
		log.Warn().Str("remote", r.RemoteAddr).Msg("Cluster: rejected request with invalid cluster secret")
		http.Error(w, "invalid cluster credentials", http.StatusForbidden)
		return false
	}
	return true
}

// tryAcquireStreamSlot reserves one concurrent data-plane stream slot for
// client, enforcing both cfg.MaxConcurrentStreams (global) and
// cfg.MaxStreamsPerClient (per-client). On success it returns a release
// func that MUST be called exactly once when the stream finishes. On
// failure it returns errStreamSlotSaturated and a nil release func; the
// caller should reject the request (503 for HTTP, drop for raw TCP)
// instead of queuing, so a saturated server fails fast rather than piling
// up unbounded goroutines/memory behind the limit.
func (ps *proxyService) tryAcquireStreamSlot(client *ClientSession) (release func(), err error) {
	if ps.cfg.MaxConcurrentStreams > 0 && !tryIncrementBounded64(&ps.activeDataStreams, int64(ps.cfg.MaxConcurrentStreams)) {
		return nil, errStreamSlotSaturated
	}
	if ps.cfg.MaxStreamsPerClient > 0 && !tryIncrementBounded32(&client.activeDataStreams, int32(ps.cfg.MaxStreamsPerClient)) {
		if ps.cfg.MaxConcurrentStreams > 0 {
			atomic.AddInt64(&ps.activeDataStreams, -1)
		}
		return nil, errStreamSlotSaturated
	}

	var released atomic.Bool
	return func() {
		if !released.CompareAndSwap(false, true) {
			return
		}
		if ps.cfg.MaxStreamsPerClient > 0 {
			atomic.AddInt32(&client.activeDataStreams, -1)
		}
		if ps.cfg.MaxConcurrentStreams > 0 {
			atomic.AddInt64(&ps.activeDataStreams, -1)
		}
	}, nil
}

// tryIncrementBounded64 atomically increments *counter and returns true,
// unless it is already >= limit, in which case it leaves *counter
// unchanged and returns false.
func tryIncrementBounded64(counter *int64, limit int64) bool {
	for {
		cur := atomic.LoadInt64(counter)
		if cur >= limit {
			return false
		}
		if atomic.CompareAndSwapInt64(counter, cur, cur+1) {
			return true
		}
	}
}

// tryIncrementBounded32 is tryIncrementBounded64 for int32 counters.
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

// ServeTCPTunnel handles raw TCP connections for a tunnel.
func (ps *proxyService) ServeTCPTunnel(ln net.Listener, client *ClientSession, tunnelID string) {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error().Err(err).Msg("Accept TCP tunnel connection failed")
			continue
		}

		go ps.handleTCPConnection(conn, client, tunnelID)
	}
}

// handleTCPConnection handles a single raw TCP connection by proxying it through the tunnel.
func (ps *proxyService) handleTCPConnection(conn net.Conn, client *ClientSession, tunnelID string) {
	defer conn.Close()

	// DP-03/DP-27: bound concurrent TCP tunnel streams before opening one.
	release, slotErr := ps.tryAcquireStreamSlot(client)
	if slotErr != nil {
		log.Warn().Str("client", client.ID).Msg("TCP tunnel connection rejected: concurrent stream limit reached")
		return
	}
	defer release()

	// Open stream to client.
	stream, err := client.Mux.OpenStreamContext(ps.ctx())
	if err != nil {
		log.Error().Err(err).Msg("Open stream for TCP tunnel failed")
		return
	}
	defer stream.Close()

	// Send stream request. TunnelID lets the client dispatch to the
	// correct local port in multi-tunnel mode (see Client.resolveLocalAddr).
	streamReq := proto.NewStreamRequest(tunnelID, generateID(), conn.RemoteAddr().String(), proto.ProtocolTCP)
	if err := proto.WriteControlMessage(stream, streamReq); err != nil {
		return
	}

	// Bidirectional proxy. tunnel.Stream has no CloseWrite/CloseRead, so
	// the only way to unblock a still-running direction once its peer
	// direction has errored out is to close both ends (DP-04): waiting
	// on just the first-to-finish direction and relying on the deferred
	// conn.Close()/stream.Close() at function return left the other
	// direction's io loop running (and its goroutine leaked past this
	// function's scope) until that deferred close happened to land.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufPtr := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, readErr := conn.Read(buf)
			if readErr != nil {
				break
			}
			if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		_ = stream.Close()
	}()

	go func() {
		defer wg.Done()
		bufPtr := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, readErr := stream.Read(buf)
			if readErr != nil {
				break
			}
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		_ = conn.Close()
	}()

	wg.Wait()
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
