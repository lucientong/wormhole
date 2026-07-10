package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClusterTestServer builds a minimal, directly-constructed *Server (no
// listeners started) wired to the given shared state store and cluster
// identity, mirroring newTestServer's pattern but with cluster fields set.
func newClusterTestServer(nodeID, nodeAddr string, store StateStore) *Server {
	config := DefaultConfig()
	config.Domain = "test.example.com"
	config.ClusterNodeID = nodeID
	config.ClusterNodeAddr = nodeAddr

	s := &Server{
		config:  config,
		clients: make(map[string]*ClientSession),
		closeCh: make(chan struct{}),
		stats:   Stats{StartTime: time.Now()},
	}
	s.router = NewRouter(config.Domain)
	s.portAllocator = NewTCPPortAllocator(10000, 10100)
	s.stateStore = store
	return s
}

// newSharedRedisStateStores returns two independent RedisStateStore
// instances (each with its own *redis.Client, as separate node processes
// would have) backed by the same in-process miniredis, simulating a real
// multi-node deployment sharing one Redis cluster.
func newSharedRedisStateStores(t *testing.T) (*RedisStateStore, *RedisStateStore) {
	t.Helper()
	mr := miniredis.RunT(t)

	newClient := func() *redis.Client {
		c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	return newRedisStateStoreWithClient(newClient()), newRedisStateStoreWithClient(newClient())
}

// tunnelBackend wires a mux pair representing a real client connection and
// serves canned HTTP responses on it, so an HTTPHandler can exercise the
// full stream-open → StreamRequest → HTTP round trip, not just routing.
type tunnelBackend struct {
	session   *ClientSession
	clientMux *tunnel.Mux
	serverMux *tunnel.Mux
}

func newTunnelBackend(t *testing.T, sessionID, subdomain, body string) *tunnelBackend {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0

	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverMux.Close() })

	clientMux, err := tunnel.Client(clientConn, muxCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientMux.Close() })

	tb := &tunnelBackend{
		session: &ClientSession{
			ID:        sessionID,
			Subdomain: subdomain,
			Mux:       serverMux,
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
		},
		clientMux: clientMux,
		serverMux: serverMux,
	}

	// Serve every stream opened on this mux with a canned 200 response,
	// for the lifetime of the test (mirrors TestHTTPHandler_ForwardHTTP's
	// single-shot version, generalized to a loop since the cross-node
	// test issues its request through an extra proxy hop).
	go func() {
		for {
			stream, acceptErr := clientMux.AcceptStream()
			if acceptErr != nil {
				return
			}
			go func() {
				defer stream.Close()
				br := bufio.NewReader(stream)
				msg, decErr := proto.ReadControlMessage(br)
				if decErr != nil || msg.StreamRequest == nil {
					return
				}
				httpReq, parseErr := http.ReadRequest(br)
				if parseErr != nil {
					return
				}
				_ = httpReq.Body.Close()

				resp := &http.Response{
					StatusCode:    http.StatusOK,
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        http.Header{"Content-Type": {"text/plain"}},
					Body:          io.NopCloser(strings.NewReader(body)),
					ContentLength: int64(len(body)),
				}
				_ = resp.Write(stream)
			}()
		}
	}()

	return tb
}

// TestCrossNodeRouting_HTTP is H11's integration test: two independent
// *Server instances share cluster state via Redis (miniredis-backed).
// Node A owns the real tunnel connection for subdomain "myapp"; node B has
// no local client at all for it. A request that arrives at node B's HTTP
// handler must be recognized as cluster-remote (H3's lookupRemoteRoute),
// reverse-proxied to node A over a real HTTP connection (proxyToNode), and
// come back with node A's tunneled response — end to end, not just a
// state-store-level lookup.
func TestCrossNodeRouting_HTTP(t *testing.T) {
	storeA, storeB := newSharedRedisStateStores(t)

	serverA := newClusterTestServer("node-a", "", storeA)
	handlerA := NewHTTPHandler(serverA.router, serverA)

	backend := newTunnelBackend(t, "session-1", "myapp", "hello from node A")
	require.NoError(t, serverA.router.RegisterSubdomain("myapp", backend.session))

	// Node A's real HTTP listener — proxyToNode dials this address.
	tsA := httptest.NewServer(handlerA)
	defer tsA.Close()
	serverA.config.ClusterNodeAddr = strings.TrimPrefix(tsA.URL, "http://")

	ok, err := serverA.registerClusterRoute(backend.session, RouteEntry{ClientID: backend.session.ID, Subdomain: "myapp"})
	require.NoError(t, err)
	require.True(t, ok)

	// Node B: no local client for "myapp" at all.
	serverB := newClusterTestServer("node-b", "", storeB)
	handlerB := NewHTTPHandler(serverB.router, serverB)

	req := httptest.NewRequest(http.MethodGet, "/test-path", nil)
	req.Host = "myapp.test.example.com"
	rec := httptest.NewRecorder()

	handlerB.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "hello from node A")
	assert.Equal(t, "myapp", rec.Header().Get("X-Wormhole-Tunnel"))
}

// TestCrossNodeRouting_Hostname is TestCrossNodeRouting_HTTP's counterpart
// for custom-hostname routes (H3): previously only subdomains were ever
// pushed to the shared state store, so a hostname-routed tunnel was
// invisible to every node except the one the client happened to be
// connected to.
func TestCrossNodeRouting_Hostname(t *testing.T) {
	storeA, storeB := newSharedRedisStateStores(t)

	serverA := newClusterTestServer("node-a", "", storeA)
	handlerA := NewHTTPHandler(serverA.router, serverA)

	backend := newTunnelBackend(t, "session-1", "", "hello via custom hostname")
	require.NoError(t, serverA.router.RegisterHostname("app.customer.com", backend.session))

	tsA := httptest.NewServer(handlerA)
	defer tsA.Close()
	serverA.config.ClusterNodeAddr = strings.TrimPrefix(tsA.URL, "http://")

	ok, err := serverA.registerClusterRoute(backend.session, RouteEntry{
		RouteID: "tunnel-1:host", ClientID: backend.session.ID, Hostname: "app.customer.com",
	})
	require.NoError(t, err)
	require.True(t, ok)

	serverB := newClusterTestServer("node-b", "", storeB)
	handlerB := NewHTTPHandler(serverB.router, serverB)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app.customer.com"
	rec := httptest.NewRecorder()

	handlerB.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "hello via custom hostname")
}

// TestCrossNodeRouting_ClusterSecretRejectsForgedPeer verifies S1: when
// Config.ClusterSecret is set, a request carrying the wrong secret is
// rejected outright rather than being treated as a trusted peer hop.
func TestCrossNodeRouting_ClusterSecretRejectsForgedPeer(t *testing.T) {
	serverB := newClusterTestServer("node-b", "", nil)
	serverB.config.ClusterSecret = "correct-secret"
	handlerB := NewHTTPHandler(serverB.router, serverB)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "myapp.test.example.com"
	req.Header.Set(clusterSecretHeader, "wrong-secret")
	rec := httptest.NewRecorder()

	handlerB.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestCrossNodeRouting_ClusterSecretAllowsGenuinePeer verifies the
// complementary S1 case: a request carrying the correct secret is not
// rejected and proceeds through normal routing (falling through to 404
// here since no client is registered).
func TestCrossNodeRouting_ClusterSecretAllowsGenuinePeer(t *testing.T) {
	serverB := newClusterTestServer("node-b", "", nil)
	serverB.config.ClusterSecret = "correct-secret"
	handlerB := NewHTTPHandler(serverB.router, serverB)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "myapp.test.example.com"
	req.Header.Set(clusterSecretHeader, "correct-secret")
	rec := httptest.NewRecorder()

	handlerB.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestServer_RefreshClusterRoutes verifies H1: a connected client's
// registered cluster routes are re-registered (TTL-refreshed) by
// refreshClusterRoutes without needing the client to do anything, and a
// disconnected/never-registered node is a no-op.
func TestServer_RefreshClusterRoutes(t *testing.T) {
	storeA, _ := newSharedRedisStateStores(t)
	serverA := newClusterTestServer("node-a", "node-a:7000", storeA)

	backend := newTunnelBackend(t, "session-1", "myapp", "irrelevant")
	require.NoError(t, serverA.router.RegisterSubdomain("myapp", backend.session))

	ok, err := serverA.registerClusterRoute(backend.session, RouteEntry{ClientID: backend.session.ID, Subdomain: "myapp"})
	require.NoError(t, err)
	require.True(t, ok)

	serverA.clientLock.Lock()
	serverA.clients[backend.session.ID] = backend.session
	serverA.clientLock.Unlock()

	// Simulate the entry being close to expiry, then refresh and verify
	// it's still resolvable (a real TTL check would require manipulating
	// miniredis's clock; here we just verify the refresh call itself
	// doesn't error and the route remains lookupable — the TTL mechanics
	// are covered directly in state_redis_test.go).
	serverA.refreshClusterRoutes()

	entry, err := storeA.LookupBySubdomain("myapp")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, backend.session.ID, entry.ClientID)
}

// TestServer_RegisterClientRoute_ReclaimsStaleLocalSession verifies H10: a
// reconnecting client whose previous session's mux has already died (but
// wasn't cleaned up yet) can immediately reclaim its subdomain instead of
// being rejected as "already registered" by its own stale former self.
func TestServer_RegisterClientRoute_ReclaimsStaleLocalSession(t *testing.T) {
	s := newClusterTestServer("node-a", "node-a:7000", nil)

	oldBackend := newTunnelBackend(t, "old-session", "myapp", "old")
	require.True(t, s.registerClientRoute(oldBackend.session, "127.0.0.1"))

	// Simulate the old connection dying without a clean disconnect.
	_ = oldBackend.serverMux.Close()

	newSession := &ClientSession{ID: "new-session", Subdomain: "myapp", CreatedAt: time.Now(), LastSeen: time.Now()}
	assert.True(t, s.registerClientRoute(newSession, "127.0.0.1"), "reconnect should reclaim the stale subdomain")

	assert.Same(t, newSession, s.router.LookupSubdomain("myapp"))
}

// TestServer_RegisterClientRoute_RejectsLiveConflict is
// TestServer_RegisterClientRoute_ReclaimsStaleLocalSession's negative
// counterpart: a still-live session's subdomain must not be reclaimable.
func TestServer_RegisterClientRoute_RejectsLiveConflict(t *testing.T) {
	s := newClusterTestServer("node-a", "node-a:7000", nil)

	liveBackend := newTunnelBackend(t, "live-session", "myapp", "live")
	require.True(t, s.registerClientRoute(liveBackend.session, "127.0.0.1"))

	newSession := &ClientSession{ID: "new-session", Subdomain: "myapp", CreatedAt: time.Now(), LastSeen: time.Now()}
	assert.False(t, s.registerClientRoute(newSession, "127.0.0.1"))
	assert.Same(t, liveBackend.session, s.router.LookupSubdomain("myapp"))
}
