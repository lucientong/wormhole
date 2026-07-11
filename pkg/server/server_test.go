package server

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)
	require.NotNil(t, s)

	assert.NotNil(t, s.router)
	assert.NotNil(t, s.httpHandler)
	assert.NotNil(t, s.tlsManager)
	assert.NotNil(t, s.adminAPI)
	assert.NotNil(t, s.portAllocator)
	assert.NotNil(t, s.clients)
	assert.NotNil(t, s.closeCh)
	assert.Nil(t, s.authenticator) // RequireAuth is false by default.
	assert.Nil(t, s.rateLimiter)   // Rate limiter needs RequireAuth.
}

func TestNewServer_WithAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"test-token-1", "test-token-2"}
	cfg.RateLimitEnabled = true

	s := NewServer(cfg)
	require.NotNil(t, s)

	// Simple token mode should be initialized.
	assert.NotNil(t, s.authenticator)
	assert.NotNil(t, s.rateLimiter)
}

func TestNewServer_WithHMACAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthSecret = "supersecretkey1234567890"
	cfg.AuthTokens = []string{"token1"}
	cfg.RateLimitEnabled = false

	s := NewServer(cfg)
	require.NotNil(t, s)

	assert.NotNil(t, s.authenticator)
	assert.Nil(t, s.rateLimiter)
}

func TestNewServer_NoAuthConfigured(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	// No tokens and no secret — authenticator should be nil.
	cfg.RateLimitEnabled = false

	s := NewServer(cfg)
	require.NotNil(t, s)
	assert.Nil(t, s.authenticator)
}

// TestNewServer_OIDCWiredToAuthenticator is a regression test for a bug
// found while working on P3-4: OIDC validator initialization ran before
// s.authenticator was constructed, so the `s.authenticator != nil` guard
// was always false and --oidc-issuer silently had no effect server-side.
// This builds a real signed RS256 JWT and confirms it validates
// successfully through s.authenticator — which is only possible if the
// OIDC validator was actually attached.
func TestNewServer_OIDCWiredToAuthenticator(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var oidcSrv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   oidcSrv.URL,
			"jwks_uri": oidcSrv.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := &key.PublicKey
		nB64 := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": "key-1", "alg": "RS256", "use": "sig", "n": nB64, "e": eB64},
			},
		})
	})
	oidcSrv = httptest.NewServer(mux)
	defer oidcSrv.Close()

	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthSecret = "supersecretkey1234567890"
	cfg.OIDCIssuer = oidcSrv.URL
	cfg.OIDCClientID = "test-client"

	s := NewServer(cfg)
	require.NotNil(t, s.authenticator)

	hdr := map[string]string{"alg": "RS256", "kid": "key-1", "typ": "JWT"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]interface{}{
		"iss":   oidcSrv.URL,
		"aud":   "test-client",
		"sub":   "user@example.com",
		"email": "user@example.com",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sigInput := hdrB64 + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	require.NoError(t, err)
	jwt := sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	claims, err := s.authenticator.ValidateToken(jwt)
	require.NoError(t, err, "OIDC-issued JWT must validate — this fails if OIDC was never wired to the authenticator")
	assert.Equal(t, "user@example.com", claims.TeamName)
}

// TestApplyClusterNodeIDDefault verifies H4: ClusterNodeID falls back to
// the machine hostname when clustering is enabled but no ID was set, and
// is left untouched otherwise (explicit value, or clustering disabled).
func TestApplyClusterNodeIDDefault(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)

	cfg := Config{ClusterStateBackend: ClusterBackendMemory}
	applyClusterNodeIDDefault(&cfg)
	assert.Equal(t, hostname, cfg.ClusterNodeID, "should default to hostname when clustering is enabled")

	cfg = Config{ClusterStateBackend: ClusterBackendMemory, ClusterNodeID: "explicit-id"}
	applyClusterNodeIDDefault(&cfg)
	assert.Equal(t, "explicit-id", cfg.ClusterNodeID, "explicit ID must not be overwritten")

	cfg = Config{}
	applyClusterNodeIDDefault(&cfg)
	assert.Empty(t, cfg.ClusterNodeID, "single-node (no cluster backend) must not get a hostname leaked in")
}

func TestInitStateStore(t *testing.T) {
	assert.Nil(t, initStateStore(Config{}), "no backend configured -> single-node, nil store")

	memStore := initStateStore(Config{ClusterStateBackend: ClusterBackendMemory})
	require.NotNil(t, memStore)
	_, ok := memStore.(*MemoryStateStore)
	assert.True(t, ok)
	_ = memStore.Close()
}

func TestInitAuthStore(t *testing.T) {
	memStore := initAuthStore(Config{})
	_, ok := memStore.(*auth.MemoryStore)
	assert.True(t, ok, "default persistence should be in-memory")

	tmpDir := t.TempDir()
	sqliteStore := initAuthStore(Config{Persistence: PersistenceSQLite, PersistencePath: tmpDir + "/auth.db"})
	_, ok = sqliteStore.(*auth.SQLiteStore)
	assert.True(t, ok)
	_ = sqliteStore.Close()
}

// TestInitAuthStore_Redis verifies H5's config wiring: --persistence redis
// uses AuthRedisAddr when set, and otherwise falls back to
// ClusterRedisAddr so a single --cluster-redis-addr is enough to share one
// Redis instance for both cluster routing state and auth/revocation state.
func TestInitAuthStore_Redis(t *testing.T) {
	mr := miniredis.RunT(t)

	store := initAuthStore(Config{Persistence: PersistenceRedis, AuthRedisAddr: mr.Addr()})
	_, ok := store.(*auth.RedisStore)
	assert.True(t, ok)
	_ = store.Close()

	// Falls back to ClusterRedisAddr when AuthRedisAddr is unset.
	store = initAuthStore(Config{Persistence: PersistenceRedis, ClusterRedisAddr: mr.Addr()})
	_, ok = store.(*auth.RedisStore)
	assert.True(t, ok)
	_ = store.Close()
}

func TestServer_IsP2PCompatible(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	tests := []struct {
		name     string
		nat1     string
		nat2     string
		expected bool
	}{
		{"Both Full Cone", natTypeFullCone, natTypeFullCone, true},
		{"Full Cone and Restricted", natTypeFullCone, natTypeRestrictedCone, true},
		{"Symmetric and Full Cone", natTypeSymmetric, natTypeFullCone, true},
		// Both Symmetric is now attempted with port prediction instead of rejected.
		{"Both Symmetric", natTypeSymmetric, natTypeSymmetric, true},
		{"Port Restricted and Symmetric", natTypePortRestrictedCone, natTypeSymmetric, true},
		// Unknown/empty NAT type has priority 0 — incompatible.
		{"Empty and Full Cone", "", natTypeFullCone, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.isP2PCompatible(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServer_FindPeerBySubdomain_NotFound(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)
	initiator := &ClientSession{ID: "client-1"}

	peer, tunnelID, reason := s.findPeerBySubdomain("myapp", initiator)
	assert.Nil(t, peer)
	assert.Empty(t, tunnelID)
	assert.Equal(t, errP2PTargetNotFound, reason)
}

func TestServer_FindPeerBySubdomain_Success(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	target := &ClientSession{
		ID:            "client-2",
		P2PPublicAddr: "1.2.3.4:5000",
		Tunnels:       []*TunnelInfo{{ID: "tunnel-2", Subdomain: "myapp"}},
	}
	require.NoError(t, s.router.RegisterSubdomain("myapp", target))

	initiator := &ClientSession{ID: "client-1"}
	peer, tunnelID, reason := s.findPeerBySubdomain("myapp", initiator)
	require.NotNil(t, peer)
	assert.Equal(t, "client-2", peer.ID)
	assert.Equal(t, "tunnel-2", tunnelID)
	assert.Empty(t, reason)
}

func TestServer_FindPeerBySubdomain_RejectsSelf(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	initiator := &ClientSession{
		ID:            "client-1",
		P2PPublicAddr: "1.2.3.4:5000",
		Tunnels:       []*TunnelInfo{{ID: "tunnel-1", Subdomain: "myapp"}},
	}
	require.NoError(t, s.router.RegisterSubdomain("myapp", initiator))

	peer, tunnelID, reason := s.findPeerBySubdomain("myapp", initiator)
	assert.Nil(t, peer)
	assert.Empty(t, tunnelID)
	assert.Equal(t, errP2PTargetIsSelf, reason)
}

func TestServer_FindPeerBySubdomain_NoP2PInfo(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Registered but never sent a P2P offer, so it has no reachability info.
	target := &ClientSession{
		ID:      "client-2",
		Tunnels: []*TunnelInfo{{ID: "tunnel-2", Subdomain: "myapp"}},
	}
	require.NoError(t, s.router.RegisterSubdomain("myapp", target))

	initiator := &ClientSession{ID: "client-1"}
	peer, _, reason := s.findPeerBySubdomain("myapp", initiator)
	assert.Nil(t, peer)
	assert.Equal(t, errP2PTargetNotFound, reason)
}

func TestServer_FindPeerBySubdomain_MissingTunnelMetadata(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Registered and reachable, but its Tunnels slice doesn't (yet) carry
	// an entry for this subdomain — a transient state that shouldn't happen
	// in practice, but must fail cleanly rather than returning a blank ID.
	target := &ClientSession{
		ID:            "client-2",
		P2PPublicAddr: "1.2.3.4:5000",
	}
	require.NoError(t, s.router.RegisterSubdomain("myapp", target))

	initiator := &ClientSession{ID: "client-1"}
	peer, tunnelID, reason := s.findPeerBySubdomain("myapp", initiator)
	assert.Nil(t, peer)
	assert.Empty(t, tunnelID)
	assert.Equal(t, errP2PTargetTunnelMeta, reason)
}

func TestServer_GetStats(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Initial stats.
	stats := s.getStats()
	assert.Equal(t, uint64(0), stats.ActiveClients)
	assert.Equal(t, uint64(0), stats.TotalClients)
	assert.Equal(t, uint64(0), stats.ActiveTunnels)
	assert.Equal(t, uint64(0), stats.BytesIn)
	assert.Equal(t, uint64(0), stats.BytesOut)
	assert.Equal(t, uint64(0), stats.Requests)
	assert.False(t, stats.StartTime.IsZero())
}

func TestServer_GetStats_AfterActivity(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Simulate activity.
	atomic.AddUint64(&s.stats.ActiveClients, 5)
	atomic.AddUint64(&s.stats.TotalClients, 10)
	atomic.AddUint64(&s.stats.ActiveTunnels, 3)
	atomic.AddUint64(&s.stats.BytesIn, 1024)
	atomic.AddUint64(&s.stats.BytesOut, 2048)
	atomic.AddUint64(&s.stats.Requests, 100)

	stats := s.getStats()
	assert.Equal(t, uint64(5), stats.ActiveClients)
	assert.Equal(t, uint64(10), stats.TotalClients)
	assert.Equal(t, uint64(3), stats.ActiveTunnels)
	assert.Equal(t, uint64(1024), stats.BytesIn)
	assert.Equal(t, uint64(2048), stats.BytesOut)
	assert.Equal(t, uint64(100), stats.Requests)
}

func TestServer_IsClosed(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	assert.False(t, s.isClosed())

	atomic.StoreUint32(&s.closed, 1)
	assert.True(t, s.isClosed())
}

func TestGenerateID(t *testing.T) {
	// Generate multiple IDs and check uniqueness.
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID()
		assert.Len(t, id, 16) // 8 bytes = 16 hex chars.
		assert.False(t, ids[id], "duplicate ID generated: %s", id)
		ids[id] = true
	}
}

func TestGenerateSubdomain(t *testing.T) {
	// Generate multiple subdomains and check uniqueness.
	subs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		sub := generateSubdomain()
		assert.Len(t, sub, 16) // 8 bytes = 16 hex chars.
		assert.False(t, subs[sub], "duplicate subdomain generated: %s", sub)
		subs[sub] = true
	}
}

func TestExtractIP_IPv6FullAddr(t *testing.T) {
	// IPv6 full format test (supplements cases in admin_test.go).
	result := extractIP("[2001:db8::1]:443")
	assert.Equal(t, "2001:db8::1", result)

	// Edge case: empty string.
	result = extractIP("")
	assert.Equal(t, "", result)
}

func TestClientSession_Struct(t *testing.T) {
	now := time.Now()
	session := &ClientSession{
		ID:        "session-1",
		Subdomain: "myapp",
		TeamName:  "engineering",
		Role:      auth.RoleAdmin,
		CreatedAt: now,
		LastSeen:  now,
	}

	assert.Equal(t, "session-1", session.ID)
	assert.Equal(t, "myapp", session.Subdomain)
	assert.Equal(t, "engineering", session.TeamName)
	assert.Equal(t, auth.RoleAdmin, session.Role)
	assert.Equal(t, now, session.CreatedAt)
	assert.Equal(t, now, session.LastSeen)
}

func TestTunnelInfo_Struct(t *testing.T) {
	now := time.Now()
	tun := &TunnelInfo{
		ID:        "tunnel-1",
		LocalPort: 8080,
		Protocol:  proto.ProtocolHTTP,
		PublicURL: "https://myapp.example.com",
		TCPPort:   0,
		CreatedAt: now,
	}

	assert.Equal(t, "tunnel-1", tun.ID)
	assert.Equal(t, uint32(8080), tun.LocalPort)
	assert.Equal(t, proto.ProtocolHTTP, tun.Protocol)
	assert.Equal(t, "https://myapp.example.com", tun.PublicURL)
	assert.Equal(t, uint32(0), tun.TCPPort)
	assert.Equal(t, now, tun.CreatedAt)
}

func TestServer_ClientManagement(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Add clients.
	client1 := &ClientSession{ID: "c1", Subdomain: "app1"}
	client2 := &ClientSession{ID: "c2", Subdomain: "app2"}

	s.clientLock.Lock()
	s.clients["c1"] = client1
	s.clients["c2"] = client2
	s.clientLock.Unlock()

	s.clientLock.RLock()
	assert.Len(t, s.clients, 2)
	s.clientLock.RUnlock()

	// Remove one client manually from map.
	s.clientLock.Lock()
	delete(s.clients, "c1")
	s.clientLock.Unlock()

	s.clientLock.RLock()
	assert.Len(t, s.clients, 1)
	_, exists := s.clients["c2"]
	assert.True(t, exists)
	s.clientLock.RUnlock()
}

func TestServer_PortAllocator(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Port allocator should be initialized.
	assert.NotNil(t, s.portAllocator)
	assert.Equal(t, 0, s.portAllocator.AllocatedPorts())
}

func TestStats_StartTime(t *testing.T) {
	before := time.Now()
	cfg := DefaultConfig()
	s := NewServer(cfg)
	after := time.Now()

	stats := s.getStats()
	assert.True(t, stats.StartTime.After(before) || stats.StartTime.Equal(before))
	assert.True(t, stats.StartTime.Before(after) || stats.StartTime.Equal(after))
}

// --- Helper: create a mux pair for integration tests ---

func newMuxPair(t *testing.T) (*tunnel.Mux, *tunnel.Mux) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	cfg := tunnel.DefaultMuxConfig()
	cfg.KeepAliveInterval = 0 // Disable keep-alive for tests.

	clientMux, err := tunnel.Client(clientConn, cfg)
	require.NoError(t, err)
	serverMux, err := tunnel.Server(serverConn, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = clientMux.Close()
		_ = serverMux.Close()
	})
	return clientMux, serverMux
}

// newTestServerForIntegration creates a Server with default config for integration tests.
func newTestServerForIntegration() *Server {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	return NewServer(cfg)
}

// --- Integration Tests ---

func TestServer_AuthenticateClient_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-token"}
	cfg.AuthTimeout = 5 * time.Second
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	sessionID := "test-session-id"

	// Client goroutine: open stream, send AuthRequest, read response.
	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewAuthRequest("valid-token", "1.0.0", "myapp")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.AuthResponse == nil || !msg.AuthResponse.Success {
			errCh <- errors.New("expected successful auth response")
			return
		}
		errCh <- nil
	}()

	// Server side: authenticate.
	claims, subdomain, err := s.authenticateClient(serverMux, sessionID)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.NotEmpty(t, subdomain)

	// Verify client received successful response.
	require.NoError(t, <-errCh)
}

// TestServer_AuthenticateClient_ServerCtxCancelUnblocks verifies DP-05/
// DP-06 together: authenticateClient derives its timeout from
// s.serverCtx(), and the auth-request Read uses ReadContext, so canceling
// the server's root context (as Shutdown does) unblocks an in-flight
// handshake immediately instead of only after the full AuthTimeout.
func TestServer_AuthenticateClient_ServerCtxCancelUnblocks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-token"}
	cfg.AuthTimeout = 30 * time.Second // deliberately long; cancellation should still be fast.
	s := NewServer(cfg)

	// Simulate what Start does, without going through the full listener
	// setup, so authenticateClient's s.serverCtx() picks this up.
	s.rootCtx, s.rootCancel = context.WithCancel(context.Background())

	clientMux, serverMux := newMuxPair(t)

	// Client opens the auth stream but never writes an AuthRequest, so
	// the server blocks in stream.ReadContext waiting for data.
	clientStream, openErr := clientMux.OpenStream()
	require.NoError(t, openErr)
	defer clientStream.Close()

	resultCh := make(chan error, 1)
	go func() {
		_, _, authErr := s.authenticateClient(serverMux, "test-session-id")
		resultCh <- authErr
	}()

	// Give authenticateClient time to reach the blocking Read.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	s.rootCancel()

	select {
	case authErr := <-resultCh:
		assert.Error(t, authErr)
		assert.ErrorIs(t, authErr, context.Canceled)
		assert.Less(t, time.Since(start), 2*time.Second,
			"authenticateClient should unblock on server ctx cancellation, not wait out AuthTimeout")
	case <-time.After(5 * time.Second):
		t.Fatal("authenticateClient did not unblock after server ctx cancellation")
	}
}

// TestServer_AuthenticateClient_ReturnsRealCapabilities verifies DP-33:
// a successful AuthResponse carries the server's actual feature set
// rather than an empty/placeholder Capabilities list.
func TestServer_AuthenticateClient_ReturnsRealCapabilities(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-token"}
	cfg.AuthTimeout = 5 * time.Second
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)
	sessionID := "test-session-id"

	respCh := make(chan *proto.AuthResponse, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			return
		}
		defer stream.Close()

		req := proto.NewAuthRequest("valid-token", "1.0.0", "myapp")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil || msg.AuthResponse == nil {
			return
		}
		respCh <- msg.AuthResponse
	}()

	_, _, err := s.authenticateClient(serverMux, sessionID)
	require.NoError(t, err)

	resp := <-respCh
	require.NotNil(t, resp)
	assert.Contains(t, resp.Capabilities, "p2p")
	assert.Contains(t, resp.Capabilities, "multi-tunnel")
}

// TestServer_CheckClientVersion covers DP-30's version-gating logic
// directly, including the "unparseable version is never rejected" rule.
func TestServer_CheckClientVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinClientVersion = "0.6.4"
	s := NewServer(cfg)

	assert.Empty(t, s.checkClientVersion("0.6.4"), "equal version should be allowed")
	assert.Empty(t, s.checkClientVersion("0.7.0"), "newer version should be allowed")
	assert.Empty(t, s.checkClientVersion("dev"), "unparseable version should never be rejected")
	assert.Empty(t, s.checkClientVersion(""), "empty version should never be rejected")
	assert.NotEmpty(t, s.checkClientVersion("0.6.3"), "older version should be rejected")
}

// TestServer_Capabilities_ReflectsConfig verifies DP-33's capability
// list grows with optional features actually wired up on this instance,
// rather than being a static/hardcoded list.
func TestServer_Capabilities_ReflectsConfig(t *testing.T) {
	base := NewServer(DefaultConfig())
	baseCaps := base.capabilities()
	assert.Contains(t, baseCaps, "p2p")
	assert.Contains(t, baseCaps, "multi-tunnel")
	assert.NotContains(t, baseCaps, "cluster")
	assert.NotContains(t, baseCaps, "audit")

	auditCfg := DefaultConfig()
	auditCfg.AuditEnabled = true
	auditSrv := NewServer(auditCfg)
	assert.Contains(t, auditSrv.capabilities(), "audit")
}

func TestServer_CheckClientVersion_Disabled(t *testing.T) {
	cfg := DefaultConfig() // MinClientVersion left empty.
	s := NewServer(cfg)

	assert.Empty(t, s.checkClientVersion("0.0.1"), "check should be a no-op when MinClientVersion is unset")
}

// TestServer_AuthenticateClient_RejectsOldVersion verifies the full
// handshake path: a client older than MinClientVersion gets a failure
// AuthResponse and authenticateClient returns an error, without ever
// reaching token validation.
func TestServer_AuthenticateClient_RejectsOldVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-token"}
	cfg.AuthTimeout = 5 * time.Second
	cfg.MinClientVersion = "0.6.4"
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)
	sessionID := "test-session-id"

	respCh := make(chan *proto.AuthResponse, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			return
		}
		defer stream.Close()

		req := proto.NewAuthRequest("valid-token", "0.6.0", "myapp")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil || msg.AuthResponse == nil {
			return
		}
		respCh <- msg.AuthResponse
	}()

	_, _, err := s.authenticateClient(serverMux, sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected")

	resp := <-respCh
	require.NotNil(t, resp)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Error, "0.6.4")
}

func TestServer_AuthenticateClient_InvalidToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-token"}
	cfg.AuthTimeout = 5 * time.Second
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)
	sessionID := "test-session-id"

	// Client sends invalid token.
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewAuthRequest("wrong-token", "1.0.0", "")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		// Read response (will get failure).
		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)
	}()

	_, _, err := s.authenticateClient(serverMux, sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate token")
}

func TestServer_AuthenticateClient_WrongMessageType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-token"}
	cfg.AuthTimeout = 5 * time.Second
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)
	sessionID := "test-session-id"

	// Client sends a PingRequest instead of AuthRequest.
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewPingRequest(42)
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)
	}()

	_, _, err := s.authenticateClient(serverMux, sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected auth request")
}

func TestServer_HandleRegister_HTTP(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "test-client",
		Subdomain: "myapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Register subdomain in router so handleRegister can work.
	_ = s.router.RegisterSubdomain("myapp", client)

	// Client goroutine: open stream, send RegisterRequest, read response.
	errCh := make(chan error, 1)
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "myapp", "", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.RegisterResponse == nil {
			errCh <- errors.New("expected register response")
			return
		}
		if !msg.RegisterResponse.Success {
			errCh <- errors.New("expected successful registration")
			return
		}
		if msg.RegisterResponse.PublicURL == "" {
			errCh <- errors.New("expected non-empty public URL")
			return
		}
		errCh <- nil
	}()

	// Server side: accept stream and handle registration.
	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream, msg.RegisterRequest)

	// Verify client received response.
	require.NoError(t, <-errCh)

	// Verify tunnel info was added.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	assert.Equal(t, uint32(8080), client.Tunnels[0].LocalPort)
	assert.Equal(t, proto.ProtocolHTTP, client.Tunnels[0].Protocol)
	assert.Contains(t, client.Tunnels[0].PublicURL, "myapp.localhost")
	client.mu.Unlock()

	// Verify stats.
	assert.Equal(t, uint64(1), atomic.LoadUint64(&s.stats.ActiveTunnels))
}

// TestServer_HandleRegister_RBAC_ViewerRejected verifies S2: a client
// authenticated with RoleViewer (read-only) must not be able to register a
// tunnel once RequireAuth is enabled, even though it already has an open,
// authenticated connection.
func TestServer_HandleRegister_RBAC_ViewerRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	cfg.RequireAuth = true
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "viewer-client",
		Subdomain: "myapp",
		Mux:       serverMux,
		Role:      auth.RoleViewer,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "myapp", "", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.RegisterResponse == nil {
			errCh <- errors.New("expected register response")
			return
		}
		if msg.RegisterResponse.Success {
			errCh <- errors.New("expected registration to be rejected for viewer role")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream, msg.RegisterRequest)
	require.NoError(t, <-errCh)

	// No tunnel should have been added.
	client.mu.Lock()
	assert.Empty(t, client.Tunnels)
	client.mu.Unlock()
}

// TestServer_HandleRegister_RBAC_MemberAllowed verifies that RoleMember
// (the default authenticated role) is unaffected by the S2 RBAC check.
func TestServer_HandleRegister_RBAC_MemberAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	cfg.RequireAuth = true
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "member-client",
		Subdomain: "myapp2",
		Mux:       serverMux,
		Role:      auth.RoleMember,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("myapp2", client)

	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "myapp2", "", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.RegisterResponse == nil || !msg.RegisterResponse.Success {
			errCh <- errors.New("expected registration to succeed for member role")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream, msg.RegisterRequest)
	require.NoError(t, <-errCh)

	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	client.mu.Unlock()
}

func TestServer_HandlePing(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:       "test-client",
		LastSeen: time.Now().Add(-5 * time.Minute),
	}

	// Client goroutine: send ping, receive pong.
	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewPingRequest(12345)
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.PingResponse == nil {
			errCh <- errors.New("expected ping response")
			return
		}
		if msg.PingResponse.PingID != 12345 {
			errCh <- errors.New("ping ID mismatch")
			return
		}
		errCh <- nil
	}()

	// Server side: accept stream, read ping, handle it.
	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.PingRequest)

	beforePing := client.LastSeen
	s.handlePing(client, stream, msg.PingRequest)

	// LastSeen should be updated.
	client.mu.Lock()
	assert.True(t, client.LastSeen.After(beforePing))
	client.mu.Unlock()

	// Verify client received pong.
	require.NoError(t, <-errCh)
}

func TestServer_HandleP2PResult_Success(_ *testing.T) {
	s := newTestServerForIntegration()

	client := &ClientSession{ID: "test-client"}

	result := &proto.P2PResult{
		TunnelID: "tunnel-1",
		Success:  true,
		PeerAddr: "1.2.3.4:5000",
	}

	// Should not panic.
	s.handleP2PResult(client, result)
}

func TestServer_HandleP2PResult_Failure(_ *testing.T) {
	s := newTestServerForIntegration()

	client := &ClientSession{ID: "test-client"}

	result := &proto.P2PResult{
		TunnelID: "tunnel-1",
		Success:  false,
		Error:    "NAT traversal failed",
	}

	// Should not panic.
	s.handleP2PResult(client, result)
}

func TestServer_HandleClientStream_Register(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "test-client",
		Subdomain: "testapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("testapp", client)

	// Client sends a register request on a new stream.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(3000, proto.ProtocolHTTP, "testapp", "", "")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		// Read response.
		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)
	}()

	// Server accepts and dispatches.
	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	s.handleClientStream(client, stream)
	<-done

	// Verify tunnel was registered.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	client.mu.Unlock()
}

func TestServer_HandleClientStream_Ping(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:       "test-client",
		LastSeen: time.Now().Add(-1 * time.Minute),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewPingRequest(9999)
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	s.handleClientStream(client, stream)
	<-done

	// LastSeen should be updated.
	client.mu.Lock()
	assert.WithinDuration(t, time.Now(), client.LastSeen, 2*time.Second)
	client.mu.Unlock()
}

func TestServer_HandleP2POffer_NoTarget(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:  "initiator",
		Mux: serverMux,
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Client sends a P2P offer with no TargetSubdomain — this is the
	// normal case for a client that's only exposing a tunnel: the server
	// records its reachability info but doesn't search for a match.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", natTypeFullCone, "1.2.3.4:5000", "192.168.1.1:5000", "", "")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		msg, readErr := proto.ReadControlMessage(stream)
		if readErr != nil {
			return
		}

		if msg != nil && msg.P2POfferResponse != nil {
			assert.False(t, msg.P2POfferResponse.Success)
			assert.Equal(t, errP2PNoTarget, msg.P2POfferResponse.Error)
		}
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.P2POfferRequest)

	s.handleP2POffer(client, stream, msg.P2POfferRequest)
	<-done

	// The offer still registered the client's reachability info even
	// though no match was requested.
	client.mu.Lock()
	assert.Equal(t, "1.2.3.4:5000", client.P2PPublicAddr)
	client.mu.Unlock()
}

func TestServer_HandleP2POffer_TargetNotFound(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:  "initiator",
		Mux: serverMux,
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Client requests a target subdomain that isn't currently connected.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", natTypeFullCone, "1.2.3.4:5000", "192.168.1.1:5000", "", "nonexistent")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		msg, readErr := proto.ReadControlMessage(stream)
		if readErr != nil {
			return
		}

		if msg != nil && msg.P2POfferResponse != nil {
			assert.False(t, msg.P2POfferResponse.Success)
			assert.Equal(t, errP2PTargetNotFound, msg.P2POfferResponse.Error)
		}
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.P2POfferRequest)

	s.handleP2POffer(client, stream, msg.P2POfferRequest)
	<-done
}

func TestServer_RemoveClient(t *testing.T) {
	s := newTestServerForIntegration()

	clientConn, serverConn := net.Pipe()
	cfg := tunnel.DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, cfg)
	require.NoError(t, err)

	client := &ClientSession{
		ID:        "remove-me",
		Subdomain: "removeapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Register client.
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("removeapp", client)
	atomic.AddUint64(&s.stats.ActiveClients, 1)

	// Remove client.
	s.removeClient(client)

	// Verify client is removed.
	s.clientLock.RLock()
	_, exists := s.clients["remove-me"]
	s.clientLock.RUnlock()
	assert.False(t, exists)

	// ActiveClients should be decremented.
	assert.Equal(t, uint64(0), atomic.LoadUint64(&s.stats.ActiveClients))

	// Mux should be closed.
	assert.True(t, serverMux.IsClosed())

	_ = clientConn.Close()
}

// TestServer_ServerCtx_FallsBackBeforeStart verifies serverCtx() (DP-05)
// returns a usable, non-nil context.Background() before Start has run —
// e.g. for unit tests that invoke handlers directly, as most of this
// file's tests do.
func TestServer_ServerCtx_FallsBackBeforeStart(t *testing.T) {
	s := NewServer(DefaultConfig())
	ctx := s.serverCtx()
	require.NotNil(t, ctx)
	assert.NoError(t, ctx.Err())
	assert.Nil(t, ctx.Done())
}

// TestServer_ServerCtx_CanceledByShutdown verifies that Start populates
// s.rootCtx and Shutdown cancels it (DP-05), so any operation still
// blocked on serverCtx() deep in the handler tree unblocks as soon as
// Shutdown begins rather than waiting on its own fixed timeout.
func TestServer_ServerCtx_CanceledByShutdown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.MuxConfig.KeepAliveInterval = 0

	s := NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	<-s.listenersReady
	serverCtx := s.serverCtx()
	require.NotNil(t, serverCtx)
	assert.NoError(t, serverCtx.Err())

	cancel()
	require.NoError(t, <-errCh)

	assert.ErrorIs(t, serverCtx.Err(), context.Canceled,
		"serverCtx should be canceled once Shutdown (triggered by Start's ctx.Done) completes")
}

func TestServer_StartAndShutdown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.MuxConfig.KeepAliveInterval = 0

	s := NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	// Give server time to start and bind listeners.
	time.Sleep(300 * time.Millisecond)

	// Verify the server is running by confirming it's not in the closed state.
	assert.False(t, s.isClosed())

	// Trigger shutdown.
	cancel()

	err := <-errCh
	assert.NoError(t, err)
	assert.True(t, s.isClosed())
}

// TestServer_Start_TunnelTLSRequiredFailsClosed verifies S4: if
// RequireAuth is set and the tunnel control channel's TLS config can't be
// built (e.g. bad manual cert paths), Start must fail rather than silently
// continue serving the control channel in plaintext.
func TestServer_Start_TunnelTLSRequiredFailsClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"tok"}
	cfg.TunnelTLSEnabled = true
	cfg.AutoTLS = false
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"

	s := NewServer(cfg)
	err := s.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel control channel TLS required")
}

// TestServer_Start_TunnelTLSOptionalFallsBackToPlaintext verifies that,
// without RequireAuth, a broken tunnel TLS config degrades to plaintext
// with a logged error instead of failing the whole server (matching the
// pre-S4 WrapListener behavior for the HTTP listener).
func TestServer_Start_TunnelTLSOptionalFallsBackToPlaintext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.MuxConfig.KeepAliveInterval = 0
	cfg.RequireAuth = false
	cfg.TunnelTLSEnabled = true
	cfg.AutoTLS = false
	cfg.TLSCertFile = "/nonexistent/cert.pem"
	cfg.TLSKeyFile = "/nonexistent/key.pem"

	s := NewServer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	assert.False(t, s.isClosed())

	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestServer_Shutdown_Idempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.MuxConfig.KeepAliveInterval = 0

	s := NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-errCh

	// Second shutdown should be no-op.
	err := s.Shutdown()
	assert.NoError(t, err)
}

func TestServer_Shutdown_WithClients(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.MuxConfig.KeepAliveInterval = 0

	s := NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Add a fake client with a mux.
	_, serverConn := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)

	s.clientLock.Lock()
	s.clients["shutdown-client"] = &ClientSession{
		ID:  "shutdown-client",
		Mux: serverMux,
	}
	s.clientLock.Unlock()

	cancel()
	<-errCh

	// Mux should be closed.
	assert.True(t, serverMux.IsClosed())
}

func TestServer_HandleClient_NoAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = false
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	// Create a connection pair for the client.
	clientConn, serverConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleClient(serverConn)
	}()

	// Client side: create mux and then close to disconnect.
	clientMux, err := tunnel.Client(clientConn, cfg.MuxConfig)
	require.NoError(t, err)

	// Give server time to register client.
	time.Sleep(100 * time.Millisecond)

	// Verify client was registered.
	s.clientLock.RLock()
	clientCount := len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 1, clientCount)

	// Close client mux to trigger disconnect.
	_ = clientMux.Close()
	<-done

	// Verify client was removed.
	s.clientLock.RLock()
	clientCount = len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 0, clientCount)
}

func TestServer_HandleClient_WithAuth_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"mytoken"}
	cfg.AuthTimeout = 5 * time.Second
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientConn, serverConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleClient(serverConn)
	}()

	// Client side: create mux, authenticate, then disconnect.
	clientMux, err := tunnel.Client(clientConn, cfg.MuxConfig)
	require.NoError(t, err)

	// Send auth request.
	authStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	req := proto.NewAuthRequest("mytoken", "1.0.0", "")
	data, err := req.Encode()
	require.NoError(t, err)
	_, err = authStream.Write(data)
	require.NoError(t, err)

	// Read auth response.
	buf := make([]byte, 4096)
	n, err := authStream.Read(buf)
	require.NoError(t, err)
	authStream.Close()

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.AuthResponse)
	assert.True(t, msg.AuthResponse.Success)

	// Give server time to register client.
	time.Sleep(100 * time.Millisecond)

	s.clientLock.RLock()
	clientCount := len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 1, clientCount)

	_ = clientMux.Close()
	<-done
}

func TestServer_HandleClient_WithAuth_RateLimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = true
	cfg.AuthTokens = []string{"valid-only"}
	cfg.AuthTimeout = 5 * time.Second
	cfg.RateLimitEnabled = true
	cfg.RateLimitMaxFailures = 3
	cfg.RateLimitWindow = 1 * time.Minute
	cfg.RateLimitBlockDuration = 1 * time.Minute
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	// Fail auth 3 times to trigger rate limiting (MaxFailures=3).
	for i := 0; i < 3; i++ {
		cConn, sConn := net.Pipe()

		done := make(chan struct{})
		go func() {
			defer close(done)
			s.handleClient(sConn)
		}()

		cMux, err := tunnel.Client(cConn, cfg.MuxConfig)
		require.NoError(t, err)

		authStream, err := cMux.OpenStream()
		if err != nil {
			_ = cMux.Close()
			<-done
			continue
		}
		req := proto.NewAuthRequest("wrong-token", "1.0.0", "")
		data, _ := req.Encode()
		_, _ = authStream.Write(data)
		buf := make([]byte, 4096)
		_, _ = authStream.Read(buf)
		_ = authStream.Close()

		_ = cMux.Close()
		<-done
	}

	// Now the IP should be blocked. A new connection should be rejected immediately.
	cConn, sConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleClient(sConn)
	}()

	// The server should close the connection immediately due to rate limiting.
	// Any read should return an error.
	buf := make([]byte, 1)
	_ = cConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, readErr := cConn.Read(buf)
	// Connection should be closed or hit deadline.
	assert.Error(t, readErr)
	_ = cConn.Close()
	<-done
}

// TestServer_HandleTCPConnection verifies the TCP tunnel proxy: an external TCP
// client connects to the allocated port, the server opens a stream to the tunnel
// client, sends a StreamRequest, and bidirectionally proxies data.
func TestServer_HandleTCPConnection(t *testing.T) {
	s := newTestServerForIntegration()

	// Create mux pair simulating tunnel client <-> server.
	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "tcp-test-client",
		Subdomain: "tcpapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Simulate an external TCP connection using net.Pipe.
	extConn, proxyConn := net.Pipe()
	defer extConn.Close()

	// Tunnel client goroutine: accept stream, read StreamRequest, echo data back.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		stream, err := clientMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		// Read length-prefixed StreamRequest.
		msg, err := proto.ReadControlMessage(stream)
		if err != nil || msg.StreamRequest == nil {
			return
		}

		// Verify it's a TCP protocol request.
		require.Equal(t, proto.ProtocolTCP, msg.StreamRequest.Protocol)
		require.NotEmpty(t, msg.StreamRequest.RequestID)

		// Echo: read data from stream and write it back.
		data := make([]byte, 4096)
		dn, readErr := stream.Read(data)
		if readErr != nil {
			return
		}
		_, _ = stream.Write(data[:dn])
	}()

	// Run handleTCPConnection in background.
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		s.handleTCPConnection(proxyConn, client, "test-tunnel")
	}()

	// External TCP client sends data.
	testPayload := []byte("hello through TCP tunnel")
	_, err := extConn.Write(testPayload)
	require.NoError(t, err)

	// Read echoed data back.
	echoBuf := make([]byte, 4096)
	n, err := extConn.Read(echoBuf)
	require.NoError(t, err)
	assert.Equal(t, testPayload, echoBuf[:n])

	// Close external conn to unblock proxy.
	_ = extConn.Close()
	<-handlerDone
	<-clientDone
}

// TestServer_TryAcquireStreamSlot_GlobalLimit verifies DP-03: once the
// global cap is reached, further acquisitions fail regardless of client,
// and releasing frees the slot back up.
func TestServer_TryAcquireStreamSlot_GlobalLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentStreams = 2
	cfg.MaxStreamsPerClient = 0
	s := NewServer(cfg)

	clientA := &ClientSession{ID: "a"}
	clientB := &ClientSession{ID: "b"}

	release1, err := s.tryAcquireStreamSlot(clientA)
	require.NoError(t, err)
	release2, err := s.tryAcquireStreamSlot(clientB)
	require.NoError(t, err)

	// Third acquisition (any client) must fail: global budget is exhausted.
	_, err = s.tryAcquireStreamSlot(clientA)
	assert.ErrorIs(t, err, errStreamSlotSaturated)

	// Releasing one slot frees capacity back up.
	release1()
	release3, err := s.tryAcquireStreamSlot(clientB)
	require.NoError(t, err)

	release2()
	release3()
	assert.Equal(t, int64(0), s.activeDataStreams)
}

// TestServer_TryAcquireStreamSlot_PerClientLimit verifies DP-27: a single
// client can be capped independently of the global budget, and a
// different client is unaffected by the first client's saturation.
func TestServer_TryAcquireStreamSlot_PerClientLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentStreams = 0
	cfg.MaxStreamsPerClient = 1
	s := NewServer(cfg)

	noisy := &ClientSession{ID: "noisy"}
	quiet := &ClientSession{ID: "quiet"}

	release, err := s.tryAcquireStreamSlot(noisy)
	require.NoError(t, err)

	// Same client, second stream: rejected by its own per-client cap.
	_, err = s.tryAcquireStreamSlot(noisy)
	assert.ErrorIs(t, err, errStreamSlotSaturated)

	// A different client still has its own independent budget.
	quietRelease, err := s.tryAcquireStreamSlot(quiet)
	require.NoError(t, err)

	release()
	quietRelease()
	assert.Equal(t, int32(0), noisy.activeDataStreams)
	assert.Equal(t, int32(0), quiet.activeDataStreams)
}

// TestServer_TryAcquireStreamSlot_ReleaseIsIdempotent guards against a
// double-release double-decrementing the counters below zero, which
// would silently widen the effective limit over time.
func TestServer_TryAcquireStreamSlot_ReleaseIsIdempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentStreams = 1
	cfg.MaxStreamsPerClient = 1
	s := NewServer(cfg)

	client := &ClientSession{ID: "c"}
	release, err := s.tryAcquireStreamSlot(client)
	require.NoError(t, err)

	release()
	release() // second call must be a no-op.

	assert.Equal(t, int64(0), s.activeDataStreams)
	assert.Equal(t, int32(0), client.activeDataStreams)
}

// TestServer_HandleTCPConnection_RejectsWhenSaturated verifies DP-03/DP-27
// apply to the raw TCP tunnel path too, not just HTTP: once the stream
// budget is exhausted, handleTCPConnection must not open a stream to the
// tunnel client at all, and must simply drop the external connection.
func TestServer_HandleTCPConnection_RejectsWhenSaturated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentStreams = 1
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()

	client := &ClientSession{ID: "tcp-saturated-client", Mux: serverMux}

	// Occupy the only slot.
	occupierRelease, err := s.tryAcquireStreamSlot(client)
	require.NoError(t, err)

	// The tunnel client must never see a stream open attempt.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		_, acceptErr := clientMux.AcceptStream()
		assert.Error(t, acceptErr, "no stream should have been opened while saturated")
	}()

	extConn, proxyConn := net.Pipe()
	defer extConn.Close()

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		s.handleTCPConnection(proxyConn, client, "test-tunnel")
	}()

	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTCPConnection should return immediately when saturated")
	}

	// Now free the slot and close the mux so the AcceptStream goroutine
	// above unblocks with an error instead of hanging forever.
	occupierRelease()
	_ = clientMux.Close()
	_ = serverMux.Close()
	<-acceptDone
}

// TestServer_HandleTCPConnection_ClientMuxClosed verifies that when the
// tunnel client's mux is closed, handleTCPConnection returns gracefully.
func TestServer_HandleTCPConnection_ClientMuxClosed(t *testing.T) {
	s := newTestServerForIntegration()

	clientConn, serverConn := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)

	// Close server mux immediately so OpenStream will fail.
	_ = serverMux.Close()

	client := &ClientSession{
		ID:  "closed-mux-client",
		Mux: serverMux,
	}

	extConn, proxyConn := net.Pipe()
	defer extConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleTCPConnection(proxyConn, client, "test-tunnel")
	}()

	// Should return quickly since mux is closed.
	select {
	case <-done:
		// ok
	case <-time.After(5 * time.Second):
		t.Fatal("handleTCPConnection should return when mux is closed")
	}

	_ = clientConn.Close()
}

// TestServer_ServeTCPTunnel verifies the accept loop for TCP tunnels:
// connections to the allocated TCP listener are proxied through the tunnel.
func TestServer_ServeTCPTunnel(t *testing.T) {
	s := newTestServerForIntegration()

	// Create a TCP listener for the tunnel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:  "tcp-tunnel-client",
		Mux: serverMux,
	}

	// Tunnel client goroutine: accept stream, read control msg, then
	// run a bidirectional echo by reading all data and echoing it back.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		stream, acceptErr := clientMux.AcceptStream()
		if acceptErr != nil {
			return
		}
		defer stream.Close()

		// Read length-prefixed StreamRequest.
		msg, readErr := proto.ReadControlMessage(stream)
		if readErr != nil || msg.StreamRequest == nil {
			return
		}
		_ = msg

		// Read one message and echo it back.
		echoBuf := make([]byte, 4096)
		dn, dataErr := stream.Read(echoBuf)
		if dataErr != nil {
			return
		}
		_, _ = stream.Write(echoBuf[:dn])
	}()

	// Start serveTCPTunnel in background (it will close ln on return).
	go s.serveTCPTunnel(ln, client, "test-tunnel")

	// Connect to the TCP tunnel port.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	// Send data and expect echo.
	payload := []byte("tcp tunnel integration test")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	resp := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	require.NoError(t, err)
	assert.Equal(t, payload, resp[:n])

	// Close connection and shutdown.
	_ = conn.Close()
	<-clientDone

	// Mark server as closed so accept loop exits.
	atomic.StoreUint32(&s.closed, 1)
	_ = ln.Close()
}

// TestServer_HandleP2POffer_WithPeer tests that when a compatible peer
// exists, the server returns the peer's info and notifies the peer.
func TestServer_HandleP2POffer_WithPeer(t *testing.T) {
	s := newTestServerForIntegration()

	// Create mux pairs for initiator and peer.
	initiatorClientMux, initiatorServerMux := newMuxPair(t)
	peerClientMux, peerServerMux := newMuxPair(t)

	initiator := &ClientSession{
		ID:  "initiator",
		Mux: initiatorServerMux,
	}
	peer := &ClientSession{
		ID:            "peer",
		Mux:           peerServerMux,
		P2PPublicAddr: "5.6.7.8:6000",
		P2PNATType:    natTypeFullCone,
		P2PPublicKey:  "peer-public-key-base64",
		Tunnels:       []*TunnelInfo{{ID: "peer-tunnel-1", Subdomain: "peerapp"}},
	}

	s.clientLock.Lock()
	s.clients[initiator.ID] = initiator
	s.clients[peer.ID] = peer
	s.clientLock.Unlock()
	require.NoError(t, s.router.RegisterSubdomain("peerapp", peer))

	// Peer goroutine: accept the notification stream from server.
	peerNotified := make(chan bool, 1)
	go func() {
		stream, err := peerClientMux.AcceptStream()
		if err != nil {
			peerNotified <- false
			return
		}
		defer stream.Close()

		msg, err := proto.ReadControlMessage(stream)
		if err != nil || msg.P2POfferResponse == nil {
			peerNotified <- false
			return
		}

		// Verify the notification contains the initiator's info.
		peerNotified <- msg.P2POfferResponse.Success
	}()

	// Initiator sends P2P offer.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := initiatorClientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", natTypeFullCone, "1.2.3.4:5000", "192.168.1.1:5000", "initiator-pub-key", "peerapp")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		msg, readErr := proto.ReadControlMessage(stream)
		if readErr != nil {
			return
		}

		if msg != nil && msg.P2POfferResponse != nil {
			// Should get the peer's info.
			assert.True(t, msg.P2POfferResponse.Success)
			assert.Equal(t, "5.6.7.8:6000", msg.P2POfferResponse.PeerAddr)
			assert.Equal(t, natTypeFullCone, msg.P2POfferResponse.PeerNATType)
			assert.Equal(t, "peer-public-key-base64", msg.P2POfferResponse.PeerPublicKey)
			assert.Equal(t, "peer-tunnel-1", msg.P2POfferResponse.PeerTunnelID)
		}
	}()

	// Server side: accept stream and handle P2P offer.
	stream, err := initiatorServerMux.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.P2POfferRequest)

	s.handleP2POffer(initiator, stream, msg.P2POfferRequest)
	<-done

	// Verify peer was notified.
	select {
	case notified := <-peerNotified:
		assert.True(t, notified, "peer should receive P2P notification")
	case <-time.After(3 * time.Second):
		t.Fatal("peer notification timed out")
	}

	// Verify initiator's P2P info was stored.
	initiator.mu.Lock()
	assert.Equal(t, "1.2.3.4:5000", initiator.P2PPublicAddr)
	assert.Equal(t, natTypeFullCone, initiator.P2PNATType)
	assert.Equal(t, "initiator-pub-key", initiator.P2PPublicKey)
	initiator.mu.Unlock()
}

// TestServer_HandleClientStream_P2PResult verifies that a P2PResult message
// dispatched via handleClientStream reaches handleP2PResult correctly.
func TestServer_HandleClientStream_P2PResult(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:  "p2p-result-client",
		Mux: serverMux,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		// Send a P2PResult message.
		msg := proto.NewP2PResult("tunnel-1", true, "5.6.7.8:9000", "")
		data, _ := msg.Encode()
		_, _ = stream.Write(data)
	}()

	// Server accepts and dispatches.
	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	// Should not panic and should handle P2PResult case in the switch.
	s.handleClientStream(client, stream)
	<-done
}

// TestServer_HandleClientStream_UnknownType verifies that unknown message types
// are logged and handled gracefully.
func TestServer_HandleClientStream_UnknownType(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:  "unknown-type-client",
		Mux: serverMux,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		// Craft a message with an unknown type.
		msg := &proto.ControlMessage{Type: 255}
		data, _ := msg.Encode()
		_, _ = stream.Write(data)
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	// Should not panic — goes through the default case.
	s.handleClientStream(client, stream)
	<-done
}

// TestServer_HandleRegister_TCP verifies the TCP tunnel registration path:
// the server allocates a TCP port and registers the tunnel with a TCP port.
func TestServer_HandleRegister_TCP(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "tcp-reg-client",
		Subdomain: "tcpreg",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("tcpreg", client)

	// Client sends a TCP register request.
	errCh := make(chan error, 1)
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(3306, proto.ProtocolTCP, "tcpreg", "", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.RegisterResponse == nil || !msg.RegisterResponse.Success {
			errCh <- errors.New("expected successful TCP registration")
			return
		}
		if msg.RegisterResponse.TCPPort == 0 {
			errCh <- errors.New("expected non-zero TCP port in response")
			return
		}
		errCh <- nil
	}()

	// Server side: accept stream and handle TCP registration.
	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)
	require.Equal(t, proto.ProtocolTCP, msg.RegisterRequest.Protocol)

	s.handleRegister(client, stream, msg.RegisterRequest)

	// Verify client response.
	require.NoError(t, <-errCh)

	// Verify tunnel was registered with TCP port.
	client.mu.Lock()
	require.Len(t, client.Tunnels, 1)
	assert.Equal(t, proto.ProtocolTCP, client.Tunnels[0].Protocol)
	assert.Greater(t, client.Tunnels[0].TCPPort, uint32(0))
	tcpPort := client.Tunnels[0].TCPPort
	client.mu.Unlock()

	// Release the allocated TCP port to clean up.
	s.portAllocator.Release(int(tcpPort))
}

// TestServer_HandleRegister_TCP_PortAllocationFailure verifies the DP-18
// fix: when no TCP port can be allocated, registration is rejected
// (Success=false) instead of silently "succeeding" with TCPPort 0, which
// would advertise a tunnel that can never actually receive traffic.
func TestServer_HandleRegister_TCP_PortAllocationFailure(t *testing.T) {
	s := newTestServerForIntegration()
	// Exhausted range: Allocate() always fails.
	s.portAllocator = NewTCPPortAllocator(20000, 20000)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "tcp-fail-client",
		Subdomain: "tcpfail",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("tcpfail", client)

	errCh := make(chan error, 1)
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(3306, proto.ProtocolTCP, "tcpfail", "", "")
		data, _ := req.Encode()
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.RegisterResponse == nil {
			errCh <- errors.New("expected register response")
			return
		}
		if msg.RegisterResponse.Success {
			errCh <- errors.New("expected registration to fail when TCP port allocation fails")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream, msg.RegisterRequest)
	require.NoError(t, <-errCh)

	// No tunnel should have been added to the client session.
	client.mu.Lock()
	assert.Empty(t, client.Tunnels)
	client.mu.Unlock()
}

// TestServer_HandleP2POffer_SymmetricSymmetric verifies that when both peers
// have Symmetric NAT, the server now uses port prediction and proceeds with P2P
// (rather than immediately rejecting the pairing).
func TestServer_HandleP2POffer_SymmetricSymmetric(t *testing.T) {
	s := newTestServerForIntegration()

	// Both the initiator and peer need a live Mux so notifyPeerOfP2P can open a stream.
	clientMux1, serverMux1 := newMuxPair(t)
	clientMux2, serverMux2 := newMuxPair(t)

	initiator := &ClientSession{
		ID:  "sym-initiator",
		Mux: serverMux1,
	}
	peer := &ClientSession{
		ID:            "sym-peer",
		P2PPublicAddr: "5.6.7.8:6000",
		P2PNATType:    natTypeSymmetric,
		P2PTunnelID:   "peer-tunnel-1",
		Mux:           serverMux2,
		Tunnels:       []*TunnelInfo{{ID: "peer-tunnel-1", Subdomain: "symapp"}},
	}

	s.clientLock.Lock()
	s.clients[initiator.ID] = initiator
	s.clients[peer.ID] = peer
	s.clientLock.Unlock()
	require.NoError(t, s.router.RegisterSubdomain("symapp", peer))

	// Goroutine simulating the peer client — reads the notification stream
	// opened by notifyPeerOfP2P and asserts that BOTH the P2PCandidates
	// message and the terminal P2POfferResponse are correctly framed and
	// decoded (DP-24 fix), rather than silently discarding one of them.
	peerGotCandidates := 0
	peerGotOfferResponse := false
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		stream, err := clientMux2.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		for {
			msg, readErr := proto.ReadControlMessage(stream)
			if readErr != nil {
				return
			}
			if msg.P2PCandidates != nil {
				peerGotCandidates = len(msg.P2PCandidates.Candidates)
				continue
			}
			if msg.P2POfferResponse != nil {
				peerGotOfferResponse = msg.P2POfferResponse.Success
				return
			}
		}
	}()

	// Goroutine simulating the initiating client — sends offer and reads
	// its own P2PCandidates + P2POfferResponse off the same stream.
	initiatorGotCandidates := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux1.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", natTypeSymmetric, "1.2.3.4:5000", "192.168.1.1:5000", "key", "symapp")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		// Read framed messages: an optional P2PCandidates message, then
		// the terminal P2POfferResponse.
		var resp *proto.P2POfferResponse
		for resp == nil {
			msg, readErr := proto.ReadControlMessage(stream)
			if readErr != nil {
				return
			}
			if msg.P2PCandidates != nil {
				initiatorGotCandidates = len(msg.P2PCandidates.Candidates)
				continue
			}
			resp = msg.P2POfferResponse
		}
		// With port prediction enabled, Symmetric+Symmetric should succeed.
		assert.True(t, resp.Success)
	}()

	stream, err := serverMux1.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.P2POfferRequest)

	s.handleP2POffer(initiator, stream, msg.P2POfferRequest)
	<-done
	<-peerDone

	// Both sides must have received and correctly decoded their predicted
	// candidates in addition to the terminal offer response — this is the
	// DP-24 acceptance criterion.
	assert.Greater(t, initiatorGotCandidates, 0, "initiator should receive peer's predicted candidates")
	assert.Greater(t, peerGotCandidates, 0, "peer should receive initiator's predicted candidates")
	assert.True(t, peerGotOfferResponse, "peer should receive a successful offer notification")
}

// TestServer_HandleP2POffer_IncompatibleNAT verifies that two clients with
// completely unknown/empty NAT types are rejected.
func TestServer_HandleP2POffer_IncompatibleNAT(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	initiator := &ClientSession{
		ID:  "unknown-initiator",
		Mux: serverMux,
	}
	peer := &ClientSession{
		ID:            "unknown-peer",
		P2PPublicAddr: "5.6.7.8:6000",
		P2PNATType:    "", // unknown type — priority 0
		Tunnels:       []*TunnelInfo{{ID: "peer-tunnel-1", Subdomain: "unknownapp"}},
	}

	s.clientLock.Lock()
	s.clients[initiator.ID] = initiator
	s.clients[peer.ID] = peer
	s.clientLock.Unlock()
	require.NoError(t, s.router.RegisterSubdomain("unknownapp", peer))

	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", "", "1.2.3.4:5000", "192.168.1.1:5000", "key", "unknownapp")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		msg, readErr := proto.ReadControlMessage(stream)
		if readErr != nil {
			return
		}

		if msg != nil && msg.P2POfferResponse != nil {
			assert.False(t, msg.P2POfferResponse.Success)
			assert.Contains(t, msg.P2POfferResponse.Error, "NAT types not compatible")
		}
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.P2POfferRequest)

	s.handleP2POffer(initiator, stream, msg.P2POfferRequest)
	<-done
}

// TestServer_HandleRegister_CustomHostname verifies that a custom hostname
// registration request works with the router.
func TestServer_HandleRegister_CustomHostname(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "hostname-client",
		Subdomain: "hostapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("hostapp", client)

	errCh := make(chan error, 1)
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "hostapp", "custom.example.com", "")
		data, _ := req.Encode()
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.RegisterResponse == nil || !msg.RegisterResponse.Success {
			errCh <- errors.New("expected successful registration")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream, msg.RegisterRequest)
	require.NoError(t, <-errCh)

	// Verify the custom hostname was registered in the router.
	resolved := s.router.Route("custom.example.com", "/")
	assert.Equal(t, client, resolved)
}

// doRegisterRequest performs a full RegisterRequest/RegisterResponse
// round-trip against handleRegister via a real mux pair, returning the
// decoded response. Used by multi-tunnel routing tests below.
func doRegisterRequest(t *testing.T, s *Server, client *ClientSession, req *proto.ControlMessage) *proto.RegisterResponse {
	t.Helper()

	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()
	client.Mux = serverMux

	errCh := make(chan error, 1)
	respCh := make(chan *proto.RegisterResponse, 1)
	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		respCh <- msg.RegisterResponse
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream, msg.RegisterRequest)
	require.NoError(t, <-errCh)
	return <-respCh
}

// TestServer_HandleRegister_MultiTunnel_DistinctSubdomains verifies the
// DP-21/DP-22 fix: a single client connection can register multiple
// tunnels, each with its own subdomain, and each gets routed independently
// (not all collapsed onto the connection-level default subdomain).
func TestServer_HandleRegister_MultiTunnel_DistinctSubdomains(t *testing.T) {
	s := newTestServerForIntegration()

	client := &ClientSession{
		ID:        "multi-tunnel-client",
		Subdomain: "default",
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("default", client)

	webReq := proto.NewRegisterRequest(3000, proto.ProtocolHTTP, "web", "", "")
	webResp := doRegisterRequest(t, s, client, webReq)
	require.NotNil(t, webResp)
	require.True(t, webResp.Success)

	apiReq := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "api", "", "")
	apiResp := doRegisterRequest(t, s, client, apiReq)
	require.NotNil(t, apiResp)
	require.True(t, apiResp.Success)

	// Both subdomains should independently route to the same client.
	assert.Equal(t, client, s.router.Route("web.localhost", "/"))
	assert.Equal(t, client, s.router.Route("api.localhost", "/"))
	assert.Equal(t, client, s.router.Route("default.localhost", "/"))

	client.mu.Lock()
	require.Len(t, client.Tunnels, 2)
	assert.Equal(t, "web", client.Tunnels[0].Subdomain)
	assert.Equal(t, "api", client.Tunnels[1].Subdomain)
	client.mu.Unlock()
}

// TestServer_HandleRegister_MultiTunnel_SubdomainConflict verifies that
// registering a tunnel with a subdomain already claimed by a *different*
// client is rejected rather than silently overwriting the existing route.
func TestServer_HandleRegister_MultiTunnel_SubdomainConflict(t *testing.T) {
	s := newTestServerForIntegration()

	other := &ClientSession{ID: "other-client", Subdomain: "taken"}
	_ = s.router.RegisterSubdomain("taken", other)

	client := &ClientSession{
		ID:        "conflicting-client",
		Subdomain: "default2",
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("default2", client)

	req := proto.NewRegisterRequest(3000, proto.ProtocolHTTP, "taken", "", "")
	resp := doRegisterRequest(t, s, client, req)
	require.NotNil(t, resp)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Error, "taken")

	// The conflicting subdomain must still resolve to the original owner.
	assert.Equal(t, other, s.router.Route("taken.localhost", "/"))
}

// TestServer_HandleClose_UnregistersTunnelSpecificRoutes verifies that
// closing one tunnel of a multi-tunnel client removes only that tunnel's
// subdomain route, leaving the client's other tunnels reachable.
func TestServer_HandleClose_UnregistersTunnelSpecificRoutes(t *testing.T) {
	s := newTestServerForIntegration()

	client := &ClientSession{
		ID:        "close-multi-client",
		Subdomain: "default3",
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("default3", client)

	webResp := doRegisterRequest(t, s, client, proto.NewRegisterRequest(3000, proto.ProtocolHTTP, "web2", "", ""))
	require.True(t, webResp.Success)
	apiResp := doRegisterRequest(t, s, client, proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "api2", "", ""))
	require.True(t, apiResp.Success)

	require.NotNil(t, s.router.Route("web2.localhost", "/"))
	require.NotNil(t, s.router.Route("api2.localhost", "/"))

	// Close the "web2" tunnel only.
	clientMux, serverMux := newMuxPair(t)
	defer clientMux.Close()
	defer serverMux.Close()
	client.Mux = serverMux

	go func() {
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()
		req := proto.NewCloseRequest(webResp.TunnelID, "test close")
		data, _ := req.Encode()
		_, _ = stream.Write(data)
		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.CloseRequest)

	s.handleClose(client, stream, msg.CloseRequest)

	// web2 route is gone, api2 route (the other tunnel) is untouched.
	assert.Nil(t, s.router.Route("web2.localhost", "/"))
	assert.Equal(t, client, s.router.Route("api2.localhost", "/"))
}

// --- P1-3: Quota Enforcement Tests ---

func TestServer_HandleClient_MaxClientsEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxClients = 1
	cfg.RequireAuth = false
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	// First client should connect successfully.
	clientConn1, serverConn1 := net.Pipe()
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		s.handleClient(serverConn1)
	}()

	clientMux1, err := tunnel.Client(clientConn1, cfg.MuxConfig)
	require.NoError(t, err)

	// Give server time to register client.
	time.Sleep(100 * time.Millisecond)

	s.clientLock.RLock()
	count := len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 1, count)

	// Second client should be rejected — server at capacity.
	clientConn2, serverConn2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.handleClient(serverConn2)
	}()

	// The server should close the connection immediately.
	buf := make([]byte, 1)
	_ = clientConn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, readErr := clientConn2.Read(buf)
	assert.Error(t, readErr, "expected connection to be closed or deadline exceeded")
	_ = clientConn2.Close()
	<-done2

	// First client still registered.
	s.clientLock.RLock()
	count = len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 1, count)

	// Disconnect first client and verify slot freed.
	_ = clientMux1.Close()
	<-done1

	s.clientLock.RLock()
	count = len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 0, count)
}

func TestServer_HandleClient_MaxClientsZeroUnlimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxClients = 0 // Unlimited.
	cfg.RequireAuth = false
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	// Multiple clients should connect successfully.
	muxes := make([]*tunnel.Mux, 3)
	dones := make([]chan struct{}, 3)

	for i := 0; i < 3; i++ {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})
		dones[i] = done

		go func() {
			defer close(done)
			s.handleClient(serverConn)
		}()

		clientMux, err := tunnel.Client(clientConn, cfg.MuxConfig)
		require.NoError(t, err)
		muxes[i] = clientMux
	}

	time.Sleep(100 * time.Millisecond)

	s.clientLock.RLock()
	count := len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 3, count)

	// Clean up.
	for i := 0; i < 3; i++ {
		_ = muxes[i].Close()
		<-dones[i]
	}
}

func TestServer_HandleClient_DisconnectFreesSlot(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxClients = 1
	cfg.RequireAuth = false
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	// First client connects.
	clientConn1, serverConn1 := net.Pipe()
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		s.handleClient(serverConn1)
	}()

	clientMux1, err := tunnel.Client(clientConn1, cfg.MuxConfig)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// First client disconnects.
	_ = clientMux1.Close()
	<-done1

	s.clientLock.RLock()
	count := len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 0, count)

	// Second client should now connect successfully.
	clientConn2, serverConn2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.handleClient(serverConn2)
	}()

	clientMux2, err := tunnel.Client(clientConn2, cfg.MuxConfig)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	s.clientLock.RLock()
	count = len(s.clients)
	s.clientLock.RUnlock()
	assert.Equal(t, 1, count)

	_ = clientMux2.Close()
	<-done2
}

func TestServer_HandleRegister_MaxTunnelsPerClient(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTunnelsPerClient = 1
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "quota-client",
		Subdomain: "quotaapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("quotaapp", client)

	// Register the first tunnel — should succeed.
	errCh1 := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh1 <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "quotaapp", "", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh1 <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh1 <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh1 <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh1 <- decErr
			return
		}
		if msg.RegisterResponse == nil || !msg.RegisterResponse.Success {
			errCh1 <- errors.New("expected first tunnel to succeed")
			return
		}
		errCh1 <- nil
	}()

	stream1, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream1.Close()

	buf := make([]byte, 4096)
	n, err := stream1.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.RegisterRequest)

	s.handleRegister(client, stream1, msg.RegisterRequest)
	require.NoError(t, <-errCh1)

	// Verify first tunnel registered.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	client.mu.Unlock()

	// Register a second tunnel — should be rejected.
	errCh2 := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh2 <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewRegisterRequest(9090, proto.ProtocolHTTP, "quotaapp", "", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh2 <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh2 <- writeErr
			return
		}

		respBuf := make([]byte, 4096)
		rn, readErr := stream.Read(respBuf)
		if readErr != nil {
			errCh2 <- readErr
			return
		}

		respMsg, decErr := proto.DecodeControlMessage(respBuf[:rn])
		if decErr != nil {
			errCh2 <- decErr
			return
		}
		if respMsg.RegisterResponse == nil {
			errCh2 <- errors.New("expected register response")
			return
		}
		if respMsg.RegisterResponse.Success {
			errCh2 <- errors.New("expected second tunnel to be rejected")
			return
		}
		if respMsg.RegisterResponse.Error == "" {
			errCh2 <- errors.New("expected error message in rejected response")
			return
		}
		errCh2 <- nil
	}()

	stream2, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream2.Close()

	buf2 := make([]byte, 4096)
	n2, err := stream2.Read(buf2)
	require.NoError(t, err)

	msg2, err := proto.DecodeControlMessage(buf2[:n2])
	require.NoError(t, err)
	require.NotNil(t, msg2.RegisterRequest)

	s.handleRegister(client, stream2, msg2.RegisterRequest)
	require.NoError(t, <-errCh2)

	// Tunnel count should still be 1.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	client.mu.Unlock()
}

func TestServer_HandleRegister_MaxTunnelsZeroUnlimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTunnelsPerClient = 0 // Unlimited.
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "unlimited-client",
		Subdomain: "unlimitedapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()
	_ = s.router.RegisterSubdomain("unlimitedapp", client)

	// Register 3 tunnels — all should succeed.
	for i := 0; i < 3; i++ {
		errCh := make(chan error, 1)
		port := uint32(8080 + i)
		go func() {
			stream, openErr := clientMux.OpenStream()
			if openErr != nil {
				errCh <- openErr
				return
			}
			defer stream.Close()

			req := proto.NewRegisterRequest(port, proto.ProtocolHTTP, "unlimitedapp", "", "")
			data, encErr := req.Encode()
			if encErr != nil {
				errCh <- encErr
				return
			}
			if _, writeErr := stream.Write(data); writeErr != nil {
				errCh <- writeErr
				return
			}

			buf := make([]byte, 4096)
			rn, readErr := stream.Read(buf)
			if readErr != nil {
				errCh <- readErr
				return
			}

			msg, decErr := proto.DecodeControlMessage(buf[:rn])
			if decErr != nil {
				errCh <- decErr
				return
			}
			if msg.RegisterResponse == nil || !msg.RegisterResponse.Success {
				errCh <- errors.New("expected successful registration")
				return
			}
			errCh <- nil
		}()

		stream, sErr := serverMux.AcceptStream()
		require.NoError(t, sErr)

		buf := make([]byte, 4096)
		n, rErr := stream.Read(buf)
		require.NoError(t, rErr)

		msg, dErr := proto.DecodeControlMessage(buf[:n])
		require.NoError(t, dErr)
		require.NotNil(t, msg.RegisterRequest)

		s.handleRegister(client, stream, msg.RegisterRequest)
		require.NoError(t, <-errCh)
		stream.Close()
	}

	client.mu.Lock()
	assert.Len(t, client.Tunnels, 3)
	client.mu.Unlock()
}

func TestDefaultConfig_QuotaDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 1000, cfg.MaxClients)
	assert.Equal(t, 0, cfg.MaxTunnelsPerClient)
}

// --- P1-2: Control Protocol Closure Tests ---

func TestServer_HandleStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "stats-client",
		Subdomain: "statsapp",
		Mux:       serverMux,
		CreatedAt: time.Now().Add(-10 * time.Second), // 10 seconds ago.
		LastSeen:  time.Now(),
		BytesIn:   1024,
		BytesOut:  2048,
		Tunnels: []*TunnelInfo{
			{ID: "t1", LocalPort: 8080, Protocol: proto.ProtocolHTTP, CreatedAt: time.Now()},
			{ID: "t2", LocalPort: 9090, Protocol: proto.ProtocolTCP, CreatedAt: time.Now()},
		},
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Client sends a StatsRequest.
	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewStatsRequest("stats-client")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.StatsResponse == nil {
			errCh <- errors.New("expected stats response")
			return
		}
		if msg.StatsResponse.ActiveTunnels != 2 {
			errCh <- fmt.Errorf("expected 2 active tunnels, got %d", msg.StatsResponse.ActiveTunnels)
			return
		}
		if msg.StatsResponse.BytesReceived != 1024 {
			errCh <- fmt.Errorf("expected 1024 bytes received, got %d", msg.StatsResponse.BytesReceived)
			return
		}
		if msg.StatsResponse.BytesSent != 2048 {
			errCh <- fmt.Errorf("expected 2048 bytes sent, got %d", msg.StatsResponse.BytesSent)
			return
		}
		if msg.StatsResponse.UptimeSeconds < 10 {
			errCh <- fmt.Errorf("expected uptime >= 10s, got %d", msg.StatsResponse.UptimeSeconds)
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.StatsRequest)

	s.handleStats(client, stream, msg.StatsRequest)
	require.NoError(t, <-errCh)
}

func TestServer_HandleClose_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "close-client",
		Subdomain: "closeapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Tunnels: []*TunnelInfo{
			{ID: "tunnel-to-close", LocalPort: 8080, Protocol: proto.ProtocolHTTP, PublicURL: "http://closeapp.example.com", CreatedAt: time.Now()},
			{ID: "tunnel-to-keep", LocalPort: 9090, Protocol: proto.ProtocolHTTP, PublicURL: "http://closeapp2.example.com", CreatedAt: time.Now()},
		},
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Set initial tunnel count.
	atomic.StoreUint64(&s.stats.ActiveTunnels, 2)

	// Client sends a CloseRequest.
	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewCloseRequest("tunnel-to-close", "user requested")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.CloseResponse == nil {
			errCh <- errors.New("expected close response")
			return
		}
		if !msg.CloseResponse.Success {
			errCh <- errors.New("expected close to succeed")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.CloseRequest)

	s.handleClose(client, stream, msg.CloseRequest)
	require.NoError(t, <-errCh)

	// Verify the tunnel was removed.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	assert.Equal(t, "tunnel-to-keep", client.Tunnels[0].ID)
	client.mu.Unlock()

	// Verify active tunnel counter decremented.
	assert.Equal(t, uint64(1), atomic.LoadUint64(&s.stats.ActiveTunnels))
}

// TestServer_HandleClose_RBAC_ViewerRejected verifies S2: a RoleViewer
// client cannot close/delete a tunnel once RequireAuth is enabled.
func TestServer_HandleClose_RBAC_ViewerRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	cfg.RequireAuth = true
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "viewer-close-client",
		Subdomain: "closeapp",
		Mux:       serverMux,
		Role:      auth.RoleViewer,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Tunnels: []*TunnelInfo{
			{ID: "tunnel-to-close", LocalPort: 8080, Protocol: proto.ProtocolHTTP, PublicURL: "http://closeapp.example.com", CreatedAt: time.Now()},
		},
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewCloseRequest("tunnel-to-close", "user requested")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.CloseResponse == nil {
			errCh <- errors.New("expected close response")
			return
		}
		if msg.CloseResponse.Success {
			errCh <- errors.New("expected close to be rejected for viewer role")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.CloseRequest)

	s.handleClose(client, stream, msg.CloseRequest)
	require.NoError(t, <-errCh)

	// The tunnel must still be present — the close was rejected.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	client.mu.Unlock()
}

func TestServer_HandleClose_TunnelNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "close-notfound-client",
		Subdomain: "notfound",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Tunnels: []*TunnelInfo{
			{ID: "existing-tunnel", LocalPort: 8080, Protocol: proto.ProtocolHTTP, CreatedAt: time.Now()},
		},
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Client sends a CloseRequest for a non-existent tunnel.
	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewCloseRequest("non-existent-tunnel", "test")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.CloseResponse == nil {
			errCh <- errors.New("expected close response")
			return
		}
		if msg.CloseResponse.Success {
			errCh <- errors.New("expected close to fail for non-existent tunnel")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.CloseRequest)

	s.handleClose(client, stream, msg.CloseRequest)
	require.NoError(t, <-errCh)

	// Original tunnel should still be there.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 1)
	client.mu.Unlock()
}

func TestServer_HandleClose_EmptyTunnelID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "close-empty-client",
		Subdomain: "emptyclose",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Client sends a CloseRequest with empty tunnel ID.
	errCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			errCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewCloseRequest("", "")
		data, encErr := req.Encode()
		if encErr != nil {
			errCh <- encErr
			return
		}
		if _, writeErr := stream.Write(data); writeErr != nil {
			errCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}

		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil {
			errCh <- decErr
			return
		}
		if msg.CloseResponse == nil {
			errCh <- errors.New("expected close response")
			return
		}
		if msg.CloseResponse.Success {
			errCh <- errors.New("expected close to fail for empty tunnel ID")
			return
		}
		errCh <- nil
	}()

	stream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	require.NoError(t, err)

	msg, err := proto.DecodeControlMessage(buf[:n])
	require.NoError(t, err)
	require.NotNil(t, msg.CloseRequest)

	s.handleClose(client, stream, msg.CloseRequest)
	require.NoError(t, <-errCh)
}

func TestServer_HandleClientStream_StatsAndClose(t *testing.T) {
	// Test that handleClientStream correctly routes to handleStats and handleClose
	// through the full message dispatch path.
	cfg := DefaultConfig()
	cfg.MuxConfig.KeepAliveInterval = 0
	s := NewServer(cfg)

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:        "dispatch-client",
		Subdomain: "dispatch",
		Mux:       serverMux,
		CreatedAt: time.Now().Add(-5 * time.Second),
		LastSeen:  time.Now(),
		Tunnels: []*TunnelInfo{
			{ID: "disp-t1", LocalPort: 8080, Protocol: proto.ProtocolHTTP, CreatedAt: time.Now()},
		},
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	atomic.StoreUint64(&s.stats.ActiveTunnels, 1)

	// Test 1: Stats via handleClientStream.
	statsCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			statsCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewStatsRequest("dispatch-client")
		data, _ := req.Encode()
		if _, writeErr := stream.Write(data); writeErr != nil {
			statsCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			statsCh <- readErr
			return
		}
		msg, _ := proto.DecodeControlMessage(buf[:n])
		if msg.StatsResponse == nil {
			statsCh <- errors.New("expected stats response via dispatch")
			return
		}
		if msg.StatsResponse.ActiveTunnels != 1 {
			statsCh <- fmt.Errorf("expected 1 tunnel, got %d", msg.StatsResponse.ActiveTunnels)
			return
		}
		statsCh <- nil
	}()

	statsStream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	s.handleClientStream(client, statsStream)
	require.NoError(t, <-statsCh)

	// Test 2: Close via handleClientStream.
	closeCh := make(chan error, 1)
	go func() {
		stream, openErr := clientMux.OpenStream()
		if openErr != nil {
			closeCh <- openErr
			return
		}
		defer stream.Close()

		req := proto.NewCloseRequest("disp-t1", "testing dispatch")
		data, _ := req.Encode()
		if _, writeErr := stream.Write(data); writeErr != nil {
			closeCh <- writeErr
			return
		}

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			closeCh <- readErr
			return
		}
		msg, _ := proto.DecodeControlMessage(buf[:n])
		if msg.CloseResponse == nil {
			closeCh <- errors.New("expected close response via dispatch")
			return
		}
		if !msg.CloseResponse.Success {
			closeCh <- errors.New("expected close to succeed via dispatch")
			return
		}
		closeCh <- nil
	}()

	closeStream, err := serverMux.AcceptStream()
	require.NoError(t, err)
	s.handleClientStream(client, closeStream)
	require.NoError(t, <-closeCh)

	// Verify tunnel removed.
	client.mu.Lock()
	assert.Len(t, client.Tunnels, 0)
	client.mu.Unlock()

	assert.Equal(t, uint64(0), atomic.LoadUint64(&s.stats.ActiveTunnels))
}

func TestProto_NewStatsRequest(t *testing.T) {
	msg := proto.NewStatsRequest("test-session")
	assert.Equal(t, proto.MessageTypeStatsRequest, msg.Type)
	require.NotNil(t, msg.StatsRequest)
	assert.Equal(t, "test-session", msg.StatsRequest.SessionID)
}

func TestProto_NewStatsResponse(t *testing.T) {
	msg := proto.NewStatsResponse(5, 10, 1024, 2048, 100, 3600)
	assert.Equal(t, proto.MessageTypeStatsResponse, msg.Type)
	require.NotNil(t, msg.StatsResponse)
	assert.Equal(t, uint32(5), msg.StatsResponse.ActiveTunnels)
	assert.Equal(t, uint32(10), msg.StatsResponse.ActiveConnections)
	assert.Equal(t, uint64(1024), msg.StatsResponse.BytesSent)
	assert.Equal(t, uint64(2048), msg.StatsResponse.BytesReceived)
	assert.Equal(t, uint64(100), msg.StatsResponse.RequestsHandled)
	assert.Equal(t, uint64(3600), msg.StatsResponse.UptimeSeconds)
}

// TestServer_Shutdown_DrainsInFlightHTTPRequest is the DP-26 regression
// test: it drives a real HTTP request through the actual s.httpServer
// (listening on a real TCP port, not the in-process httptest.Recorder
// used by handler_test.go) while the backend is deliberately slow, then
// triggers Shutdown mid-request. Before the fix, Shutdown closed
// s.httpListener directly, which would have reset the in-flight
// connection instead of letting the slow handler finish.
func TestServer_Shutdown_DrainsInFlightHTTPRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.MuxConfig.KeepAliveInterval = 0
	cfg.ShutdownTimeout = 5 * time.Second

	s := NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- s.Start(ctx)
	}()

	// Wait for listeners to be bound (race-detector-safe, unlike a fixed sleep).
	select {
	case <-s.listenersReady:
	case <-time.After(time.Second):
		t.Fatal("server did not become ready in time")
	}

	// Wire up a fake tunnel client: server-side mux is registered with
	// the router under "slowapp", client-side mux plays the role of the
	// backend, deliberately sleeping before responding so the request
	// is still in flight when Shutdown runs.
	clientConn, serverConn := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)
	defer serverMux.Close()
	clientMux, err := tunnel.Client(clientConn, muxCfg)
	require.NoError(t, err)
	defer clientMux.Close()

	session := &ClientSession{
		ID:        "slow-backend-session",
		Subdomain: "slowapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	require.NoError(t, s.router.RegisterSubdomain("slowapp", session))

	const backendDelay = 400 * time.Millisecond
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		stream, acceptErr := clientMux.AcceptStream()
		if acceptErr != nil {
			return
		}
		defer stream.Close()

		br := bufio.NewReader(stream)
		if _, decErr := proto.ReadControlMessage(br); decErr != nil {
			return
		}
		httpReq, parseErr := http.ReadRequest(br)
		if parseErr != nil {
			return
		}
		_ = httpReq.Body.Close()

		// Simulate a slow local backend so the HTTP request is still
		// in flight when the test triggers Shutdown below.
		time.Sleep(backendDelay)

		body := "slow response completed"
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

	// Fire the HTTP request at the real listener in the background.
	type result struct {
		status int
		body   string
		err    error
	}
	respCh := make(chan result, 1)
	go func() {
		req, reqErr := http.NewRequest(http.MethodGet, "http://"+s.httpListener.Addr().String()+"/", nil)
		if reqErr != nil {
			respCh <- result{err: reqErr}
			return
		}
		req.Host = "slowapp.localhost"
		httpClient := &http.Client{Timeout: 5 * time.Second}
		resp, doErr := httpClient.Do(req)
		if doErr != nil {
			respCh <- result{err: doErr}
			return
		}
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		respCh <- result{status: resp.StatusCode, body: string(b), err: readErr}
	}()

	// Let the request reach the slow handler, then shut down while it's
	// still sleeping.
	time.Sleep(backendDelay / 4)
	shutdownStart := time.Now()
	cancel()

	require.NoError(t, <-startErrCh)
	shutdownElapsed := time.Since(shutdownStart)

	<-clientDone
	res := <-respCh

	require.NoError(t, res.err)
	assert.Equal(t, http.StatusOK, res.status)
	assert.Contains(t, res.body, "slow response completed")

	// Shutdown must have waited for the slow handler (it started well
	// after backendDelay/4 had already elapsed), proving it drained the
	// in-flight request instead of yanking the listener out from under it.
	assert.GreaterOrEqual(t, shutdownElapsed, backendDelay/2)
}
