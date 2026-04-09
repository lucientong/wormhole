package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

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

func TestServer_IsP2PCompatible(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	tests := []struct {
		name     string
		nat1     string
		nat2     string
		expected bool
	}{
		{"Both Full Cone", "Full Cone", "Full Cone", true},
		{"Full Cone and Restricted", "Full Cone", "Restricted Cone", true},
		{"Symmetric and Full Cone", "Symmetric", "Full Cone", true},
		{"Both Symmetric", "Symmetric", "Symmetric", false},
		{"Port Restricted and Symmetric", "Port Restricted Cone", "Symmetric", true},
		{"Empty and Full Cone", "", "Full Cone", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.isP2PCompatible(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServer_FindPeerForP2P(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// No clients — should return nil.
	peer := s.FindPeerForP2P("client-1")
	assert.Nil(t, peer)

	// Add a client with P2P info.
	s.clients["client-2"] = &ClientSession{
		ID:            "client-2",
		P2PPublicAddr: "1.2.3.4:5000",
	}

	// Should find client-2.
	peer = s.FindPeerForP2P("client-1")
	require.NotNil(t, peer)
	assert.Equal(t, "client-2", peer.ID)

	// Should not find self.
	peer = s.FindPeerForP2P("client-2")
	assert.Nil(t, peer)
}

func TestServer_FindPeerForP2P_ExcludesNonP2P(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg)

	// Add client without P2P info.
	s.clients["client-2"] = &ClientSession{
		ID: "client-2",
		// P2PPublicAddr is empty.
	}

	peer := s.FindPeerForP2P("client-1")
	assert.Nil(t, peer)
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

func TestServerStats_StartTime(t *testing.T) {
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

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "myapp")
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

		req := proto.NewRegisterRequest(3000, proto.ProtocolHTTP, "testapp")
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

func TestServer_HandleP2POffer_NoPeer(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	client := &ClientSession{
		ID:  "initiator",
		Mux: serverMux,
	}
	s.clientLock.Lock()
	s.clients[client.ID] = client
	s.clientLock.Unlock()

	// Client sends P2P offer with no peer available.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", "Full Cone", "1.2.3.4:5000", "192.168.1.1:5000", "")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}

		msg, _ := proto.DecodeControlMessage(buf[:n])
		if msg != nil && msg.P2POfferResponse != nil {
			assert.False(t, msg.P2POfferResponse.Success)
			assert.Contains(t, msg.P2POfferResponse.Error, "no peer available")
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

		// Read StreamRequest.
		buf := make([]byte, 4096)
		n, err := stream.Read(buf)
		if err != nil {
			return
		}

		msg, err := proto.DecodeControlMessage(buf[:n])
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
		s.handleTCPConnection(proxyConn, client)
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
		s.handleTCPConnection(proxyConn, client)
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

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}

		msg, _ := proto.DecodeControlMessage(buf[:n])
		if msg == nil || msg.StreamRequest == nil {
			return
		}

		// Read one message and echo it back.
		dn, dataErr := stream.Read(buf)
		if dataErr != nil {
			return
		}
		_, _ = stream.Write(buf[:dn])
	}()

	// Start serveTCPTunnel in background (it will close ln on return).
	go s.serveTCPTunnel(ln, client)

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
		P2PNATType:    "Full Cone",
		P2PPublicKey:  "peer-public-key-base64",
	}

	s.clientLock.Lock()
	s.clients[initiator.ID] = initiator
	s.clients[peer.ID] = peer
	s.clientLock.Unlock()

	// Peer goroutine: accept the notification stream from server.
	peerNotified := make(chan bool, 1)
	go func() {
		stream, err := peerClientMux.AcceptStream()
		if err != nil {
			peerNotified <- false
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, err := stream.Read(buf)
		if err != nil {
			peerNotified <- false
			return
		}

		msg, err := proto.DecodeControlMessage(buf[:n])
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

		req := proto.NewP2POfferRequest("tunnel-1", "Full Cone", "1.2.3.4:5000", "192.168.1.1:5000", "initiator-pub-key")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}

		msg, _ := proto.DecodeControlMessage(buf[:n])
		if msg != nil && msg.P2POfferResponse != nil {
			// Should get the peer's info.
			assert.True(t, msg.P2POfferResponse.Success)
			assert.Equal(t, "5.6.7.8:6000", msg.P2POfferResponse.PeerAddr)
			assert.Equal(t, "Full Cone", msg.P2POfferResponse.PeerNATType)
			assert.Equal(t, "peer-public-key-base64", msg.P2POfferResponse.PeerPublicKey)
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
	assert.Equal(t, "Full Cone", initiator.P2PNATType)
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

		req := proto.NewRegisterRequest(3306, proto.ProtocolTCP, "tcpreg")
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

// TestServer_HandleP2POffer_IncompatibleNAT verifies that when both peers
// have Symmetric NAT, the server responds with a failure.
func TestServer_HandleP2POffer_IncompatibleNAT(t *testing.T) {
	s := newTestServerForIntegration()

	clientMux, serverMux := newMuxPair(t)

	initiator := &ClientSession{
		ID:  "sym-initiator",
		Mux: serverMux,
	}
	peer := &ClientSession{
		ID:            "sym-peer",
		P2PPublicAddr: "5.6.7.8:6000",
		P2PNATType:    "Symmetric",
	}

	s.clientLock.Lock()
	s.clients[initiator.ID] = initiator
	s.clients[peer.ID] = peer
	s.clientLock.Unlock()

	// Initiator sends P2P offer with Symmetric NAT.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := clientMux.OpenStream()
		if err != nil {
			return
		}
		defer stream.Close()

		req := proto.NewP2POfferRequest("tunnel-1", "Symmetric", "1.2.3.4:5000", "192.168.1.1:5000", "key")
		data, _ := req.Encode()
		_, _ = stream.Write(data)

		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}

		msg, _ := proto.DecodeControlMessage(buf[:n])
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

		req := proto.NewRegisterRequest(8080, proto.ProtocolHTTP, "hostapp")
		req.RegisterRequest.Hostname = "custom.example.com"
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
