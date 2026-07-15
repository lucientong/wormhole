package client

// Tests in this file exercise RelayClient behavior directly against a
// scripted fake server peer, independent of Client/P2PSession: unlike
// most of client_test.go (which drives everything through a
// *Client), these construct a *relayClient on its own via newRelayClient,
// with nil localForwarder/statsRecorder — safe because none of the paths
// under test (registration, reload, auth) touch either.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopStatsRecorder discards every call — a stand-in for Client's real
// statsRecorder implementation in tests that exercise relayClient.connect
// (which unconditionally records connection time) without caring about
// aggregate stats.
type noopStatsRecorder struct{}

func (noopStatsRecorder) addBytesIn(uint64)           {}
func (noopStatsRecorder) addBytesOut(uint64)          {}
func (noopStatsRecorder) addRequest()                 {}
func (noopStatsRecorder) addReconnect()               {}
func (noopStatsRecorder) setConnectionTime(time.Time) {}

// newTestRelayClient builds a bare *relayClient wired to the client side
// of a mux-pair, with the server side returned for the test to drive.
func newTestRelayClient(t *testing.T, cfg Config) (*relayClient, *tunnel.Mux) {
	t.Helper()
	clientMux, serverMux := newClientMuxPair(t)

	closeCh := make(chan struct{})
	var wg sync.WaitGroup
	r := newRelayClient(cfg, nil, nil, nil, closeCh, &wg)
	r.mu.Lock()
	r.mux = clientMux
	r.mu.Unlock()

	return r, serverMux
}

// serveFakeRegistryPeer answers RegisterRequest/CloseRequest messages on
// serverMux until it's closed, reporting each one it handles on the
// returned channels (registered: the request's Subdomain; closed: the
// request's TunnelID) so tests can assert on what was actually sent over
// the wire rather than just the client's resulting local state.
func serveFakeRegistryPeer(t *testing.T, serverMux *tunnel.Mux) (registered <-chan string, closed <-chan string) {
	t.Helper()
	registeredCh := make(chan string, 16)
	closedCh := make(chan string, 16)

	go func() {
		for {
			stream, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer stream.Close()
				buf := make([]byte, 4096)
				n, err := stream.Read(buf)
				if err != nil {
					return
				}
				msg, err := proto.DecodeControlMessage(buf[:n])
				if err != nil {
					return
				}
				switch {
				case msg.RegisterRequest != nil:
					req := msg.RegisterRequest
					registeredCh <- req.Subdomain
					resp := proto.NewRegisterResponse(true, "", "tid-"+req.Subdomain, "http://"+req.Subdomain+".test", 0)
					data, _ := resp.Encode()
					_, _ = stream.Write(data)
				case msg.CloseRequest != nil:
					req := msg.CloseRequest
					closedCh <- req.TunnelID
					resp := proto.NewCloseResponse(true)
					data, _ := resp.Encode()
					_, _ = stream.Write(data)
				}
			}()
		}
	}()

	return registeredCh, closedCh
}

// TestRelayClient_ReloadTunnels_AddsRemovesAndKeepsUnchanged verifies:
// ReloadTunnels must register newly-added tunnels, close and drop
// no-longer-configured ones, and leave unchanged ones alone (no spurious
// close+re-register), which is what makes it a differential — not a
// full — reload.
func TestRelayClient_ReloadTunnels_AddsRemovesAndKeepsUnchanged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tunnels = []TunnelDef{
		{Name: "a", LocalPort: 8001, Subdomain: "a"},
		{Name: "b", LocalPort: 8002, Subdomain: "b"},
	}
	r, serverMux := newTestRelayClient(t, cfg)
	registered, closed := serveFakeRegistryPeer(t, serverMux)

	// Seed activeTunnels as if registerAllTunnels already ran for "a"
	// and "b" — ReloadTunnels operates purely on this existing state plus
	// the newly-supplied definitions, so seeding it directly (rather than
	// re-deriving it via a real registerAllTunnels call) keeps the test
	// focused on ReloadTunnels' own diff logic.
	r.activeTunnelsMu.Lock()
	r.activeTunnels["a"] = &ActiveTunnel{Def: cfg.Tunnels[0], TunnelID: "tid-a"}
	r.activeTunnels["b"] = &ActiveTunnel{Def: cfg.Tunnels[1], TunnelID: "tid-b"}
	r.activeTunnelsMu.Unlock()

	newDefs := []TunnelDef{
		cfg.Tunnels[0], // "a" unchanged
		{Name: "c", LocalPort: 8003, Subdomain: "c"}, // "c" newly added
		// "b" is dropped by omission.
	}

	r.ReloadTunnels(context.Background(), newDefs)

	// "b" must have been closed with its existing TunnelID ...
	select {
	case tunnelID := <-closed:
		assert.Equal(t, "tid-b", tunnelID)
	case <-time.After(2 * time.Second):
		t.Fatal("removed tunnel \"b\" was never closed on the server")
	}
	// ... and "c" must have been newly registered ...
	select {
	case subdomain := <-registered:
		assert.Equal(t, "c", subdomain)
	case <-time.After(2 * time.Second):
		t.Fatal("added tunnel \"c\" was never registered with the server")
	}
	// ... while "a" must never have triggered any message at all.
	select {
	case name := <-registered:
		t.Fatalf("unchanged tunnel must not be re-registered, got register for %q", name)
	case name := <-closed:
		t.Fatalf("unchanged tunnel must not be closed, got close for %q", name)
	case <-time.After(100 * time.Millisecond):
	}

	r.activeTunnelsMu.RLock()
	defer r.activeTunnelsMu.RUnlock()
	assert.Contains(t, r.activeTunnels, "a", "unchanged tunnel must remain active")
	assert.Contains(t, r.activeTunnels, "c", "newly added tunnel must become active")
	assert.NotContains(t, r.activeTunnels, "b", "removed tunnel must no longer be active")
}

// TestRelayClient_ReloadTunnels_NotConnected verifies ReloadTunnels is a
// safe no-op (not a panic) when called with no live mux — e.g. a SIGHUP
// arriving in the reconnect backoff window.
func TestRelayClient_ReloadTunnels_NotConnected(t *testing.T) {
	cfg := DefaultConfig()
	closeCh := make(chan struct{})
	var wg sync.WaitGroup
	r := newRelayClient(cfg, nil, nil, nil, closeCh, &wg)

	assert.NotPanics(t, func() {
		r.ReloadTunnels(context.Background(), []TunnelDef{{Name: "a", LocalPort: 8001}})
	})
	assert.Empty(t, r.activeTunnels)
}

// TestRelayClient_AuthenticateWithRefresh_RetriesWithNewTokenOnRejection
// covers the core case: a server rejecting the current token invokes
// Config.OnAuthFailure, and a successful refresh is retried exactly once
// with the new token — the same code path Run's reconnect loop re-enters
// on every reconnection attempt, so this is what actually exercises "an
// OIDC access token that expired mid-session" surviving a reconnect.
func TestRelayClient_AuthenticateWithRefresh_RetriesWithNewTokenOnRejection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "expired-token"
	refreshCalled := false
	cfg.OnAuthFailure = func(_ context.Context) (string, bool) {
		refreshCalled = true
		return "fresh-token", true
	}
	r, serverMux := newTestRelayClient(t, cfg)

	var gotTokens []string
	var mu sync.Mutex
	go func() {
		for i := 0; i < 2; i++ {
			stream, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
			func() {
				defer stream.Close()
				buf := make([]byte, 4096)
				n, err := stream.Read(buf)
				require.NoError(t, err)
				msg, err := proto.DecodeControlMessage(buf[:n])
				require.NoError(t, err)
				require.NotNil(t, msg.AuthRequest)

				mu.Lock()
				gotTokens = append(gotTokens, msg.AuthRequest.Token)
				mu.Unlock()

				var resp *proto.ControlMessage
				if msg.AuthRequest.Token == "expired-token" {
					resp = proto.NewAuthResponse(false, "token expired", "", "", "")
				} else {
					resp = proto.NewAuthResponse(true, "", "mysubdomain", "", "session-1")
				}
				data, encErr := resp.Encode()
				require.NoError(t, encErr)
				_, writeErr := stream.Write(data)
				require.NoError(t, writeErr)
			}()
		}
	}()

	err := r.authenticateWithRefresh(context.Background())
	require.NoError(t, err)
	assert.True(t, refreshCalled)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, gotTokens, 2, "must authenticate exactly twice: once with the expired token, once with the refreshed one")
	assert.Equal(t, "expired-token", gotTokens[0])
	assert.Equal(t, "fresh-token", gotTokens[1])

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Equal(t, "fresh-token", r.config.Token, "the refreshed token must be persisted for subsequent requests")
}

// TestRelayClient_AuthenticateWithRefresh_NoHookReturnsOriginalError
// verifies that without Config.OnAuthFailure wired up (the CLI layer
// didn't configure OAuth2 refresh), a rejected token fails immediately —
// no second attempt, no panic on the nil hook.
func TestRelayClient_AuthenticateWithRefresh_NoHookReturnsOriginalError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "bad-token"
	r, serverMux := newTestRelayClient(t, cfg)

	attempts := 0
	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		attempts++
		buf := make([]byte, 4096)
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		if _, decErr := proto.DecodeControlMessage(buf[:n]); decErr != nil {
			return
		}
		resp := proto.NewAuthResponse(false, "invalid token", "", "", "")
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := r.authenticateWithRefresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

// TestRelayClient_AuthenticateWithRefresh_HookDeclinesReturnsOriginalError
// covers OnAuthFailure itself failing to produce a usable token (e.g. the
// refresh_token grant was also rejected) — authenticateWithRefresh must
// surface the *original* rejection rather than retry with an empty token.
func TestRelayClient_AuthenticateWithRefresh_HookDeclinesReturnsOriginalError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "expired-token"
	cfg.OnAuthFailure = func(_ context.Context) (string, bool) {
		return "", false
	}
	r, serverMux := newTestRelayClient(t, cfg)

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4096)
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		if _, decErr := proto.DecodeControlMessage(buf[:n]); decErr != nil {
			return
		}
		resp := proto.NewAuthResponse(false, "token expired", "", "", "")
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := r.authenticateWithRefresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Equal(t, "expired-token", r.config.Token, "a declined refresh must not overwrite the existing token")
}

// TestRelayClient_Connect_RefreshesTokenOverRealReconnect drives
// authenticateWithRefresh through relayClient.connect itself — the exact
// method Run's reconnect loop calls on every attempt — over a real TCP
// listener, so this is the token-refresh reconnect path end to end: dial,
// get rejected, refresh, redial-free retry, then continue on to tunnel
// registration exactly as a real reconnect after an OIDC token expiry
// would.
func TestRelayClient_Connect_RefreshesTokenOverRealReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		muxCfg := tunnel.DefaultMuxConfig()
		muxCfg.KeepAliveInterval = 0
		serverMux, muxErr := tunnel.Server(conn, muxCfg)
		if muxErr != nil {
			return
		}
		defer serverMux.Close()

		// Auth attempt #1: reject the expired token.
		authStream, acceptErr := serverMux.AcceptStream()
		if acceptErr != nil {
			t.Logf("accept auth stream 1: %v", acceptErr)
			return
		}
		buf := make([]byte, 4096)
		n, readErr := authStream.Read(buf)
		if readErr != nil {
			t.Logf("read auth request 1: %v", readErr)
			return
		}
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr != nil || msg.AuthRequest == nil || msg.AuthRequest.Token != "expired-token" {
			t.Logf("decode auth request 1: decErr=%v msg=%+v", decErr, msg)
			return
		}
		resp := proto.NewAuthResponse(false, "token expired", "", "", "")
		data, _ := resp.Encode()
		_, _ = authStream.Write(data)
		_ = authStream.Close()

		// Auth attempt #2: accept the refreshed token.
		authStream2, acceptErr := serverMux.AcceptStream()
		if acceptErr != nil {
			t.Logf("accept auth stream 2: %v", acceptErr)
			return
		}
		n, readErr = authStream2.Read(buf)
		if readErr != nil {
			t.Logf("read auth request 2: %v", readErr)
			return
		}
		msg, decErr = proto.DecodeControlMessage(buf[:n])
		if decErr != nil || msg.AuthRequest == nil || msg.AuthRequest.Token != "fresh-token" {
			t.Logf("decode auth request 2: decErr=%v msg=%+v", decErr, msg)
			return
		}
		resp2 := proto.NewAuthResponse(true, "", "mysubdomain", "", "session-1")
		data2, _ := resp2.Encode()
		_, _ = authStream2.Write(data2)
		_ = authStream2.Close()

		// Tunnel registration, now that auth succeeded.
		regStream, acceptErr := serverMux.AcceptStream()
		if acceptErr != nil {
			t.Logf("accept register stream: %v", acceptErr)
			return
		}
		n, readErr = regStream.Read(buf)
		if readErr != nil {
			t.Logf("read register request: %v", readErr)
			return
		}
		if msg, decErr = proto.DecodeControlMessage(buf[:n]); decErr != nil || msg.RegisterRequest == nil {
			t.Logf("decode register request: decErr=%v msg=%+v", decErr, msg)
			return
		}
		regResp := proto.NewRegisterResponse(true, "", "tid-1", "http://mysubdomain.test", 0)
		regData, _ := regResp.Encode()
		_, _ = regStream.Write(regData)
		_ = regStream.Close()

		// sendLoop flushes DATA/CLOSE frames asynchronously (see its doc
		// comment) — closing serverMux/conn right after Write/Close
		// returning would race that flush and could tear down the
		// connection before the client ever sees this last response.
		// Waiting here (rather than removing the deferred closes
		// entirely) keeps the fake peer's teardown deterministic once
		// the client has had time to read.
		time.Sleep(200 * time.Millisecond)
	}()

	cfg := DefaultConfig()
	cfg.ServerAddr = ln.Addr().String()
	cfg.Token = "expired-token"
	cfg.P2PEnabled = false
	cfg.MuxConfig.KeepAliveInterval = 0
	cfg.OnAuthFailure = func(_ context.Context) (string, bool) {
		return "fresh-token", true
	}
	closeCh := make(chan struct{})
	var wg sync.WaitGroup
	r := newRelayClient(cfg, nil, noopStatsRecorder{}, nil, closeCh, &wg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.connect(ctx)
	require.NoError(t, err)

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Equal(t, "fresh-token", r.config.Token)
	assert.Equal(t, "tid-1", r.tunnelID)
	_ = r.mux.Close()
}

// TestRelayClient_RegisterAllTunnels_PartialFailureIsBestEffort verifies
// multi-tunnel (config file) mode's registration pass: a tunnel the
// server rejects must not block the others from becoming active, and
// activeTunnels ends up containing exactly the ones that succeeded. Only
// an all-tunnels failure is a hard error.
func TestRelayClient_RegisterAllTunnels_PartialFailureIsBestEffort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tunnels = []TunnelDef{
		{Name: "good", LocalPort: 8001, Subdomain: "good"},
		{Name: "bad", LocalPort: 8002, Subdomain: "bad"},
	}
	r, serverMux := newTestRelayClient(t, cfg)

	go func() {
		for i := 0; i < 2; i++ {
			stream, err := serverMux.AcceptStream()
			if err != nil {
				return
			}
			func() {
				defer stream.Close()
				buf := make([]byte, 4096)
				n, readErr := stream.Read(buf)
				if readErr != nil {
					return
				}
				msg, decErr := proto.DecodeControlMessage(buf[:n])
				if decErr != nil || msg.RegisterRequest == nil {
					return
				}
				var resp *proto.ControlMessage
				if msg.RegisterRequest.Subdomain == "bad" {
					resp = proto.NewRegisterResponse(false, "subdomain taken", "", "", 0)
				} else {
					resp = proto.NewRegisterResponse(true, "", "tid-good", "http://good.test", 0)
				}
				data, _ := resp.Encode()
				_, _ = stream.Write(data)
			}()
		}
	}()

	err := r.registerAllTunnels(context.Background())
	require.NoError(t, err, "at least one tunnel registered, so this must not be a hard error")

	r.activeTunnelsMu.RLock()
	defer r.activeTunnelsMu.RUnlock()
	assert.Contains(t, r.activeTunnels, "good")
	assert.NotContains(t, r.activeTunnels, "bad")
}

// TestRelayClient_RegisterAllTunnels_AllFailReturnsError verifies that
// when every configured tunnel is rejected, registerAllTunnels surfaces a
// hard error instead of silently starting with zero tunnels.
func TestRelayClient_RegisterAllTunnels_AllFailReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tunnels = []TunnelDef{{Name: "bad", LocalPort: 8001, Subdomain: "bad"}}
	r, serverMux := newTestRelayClient(t, cfg)

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4096)
		n, readErr := stream.Read(buf)
		if readErr != nil {
			return
		}
		if _, decErr := proto.DecodeControlMessage(buf[:n]); decErr != nil {
			return
		}
		resp := proto.NewRegisterResponse(false, "subdomain taken", "", "", 0)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := r.registerAllTunnels(context.Background())
	require.Error(t, err)
	assert.Empty(t, r.activeTunnels)
}

// TestRelayClient_PublicURL_And_SessionID verifies the single-tunnel-mode
// accessors simply reflect state set during authentication/registration,
// defaulting to "" beforehand.
func TestRelayClient_PublicURL_And_SessionID(t *testing.T) {
	closeCh := make(chan struct{})
	var wg sync.WaitGroup
	r := newRelayClient(DefaultConfig(), nil, nil, nil, closeCh, &wg)

	assert.Empty(t, r.PublicURL())
	assert.Empty(t, r.SessionID())

	r.mu.Lock()
	r.publicURL = "https://mysubdomain.example.com"
	r.sessionID = "session-42"
	r.mu.Unlock()

	assert.Equal(t, "https://mysubdomain.example.com", r.PublicURL())
	assert.Equal(t, "session-42", r.SessionID())
}
