package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)
	require.NotNil(t, c)

	assert.False(t, c.IsConnected())
	assert.False(t, c.IsP2PMode())
	assert.NotNil(t, c.inspector)
	assert.NotNil(t, c.p2pManager)
	assert.NotNil(t, c.closeCh)
}

func TestNewClient_WithCustomConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "example.com:9000"
	cfg.LocalPort = 3000
	cfg.LocalHost = "0.0.0.0"
	cfg.P2PEnabled = false

	c := NewClient(cfg)
	require.NotNil(t, c)
	assert.Equal(t, "example.com:9000", c.config.ServerAddr)
	assert.Equal(t, 3000, c.config.LocalPort)
	assert.Equal(t, "0.0.0.0", c.config.LocalHost)
	assert.False(t, c.config.P2PEnabled)
}

func TestClient_IsConnected(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	assert.False(t, c.IsConnected())

	// Simulate connected state.
	atomic.StoreUint32(&c.connected, 1)
	assert.True(t, c.IsConnected())

	// Simulate disconnected state.
	atomic.StoreUint32(&c.connected, 0)
	assert.False(t, c.IsConnected())
}

func TestClient_IsP2PMode(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	assert.False(t, c.IsP2PMode())

	// Simulate P2P mode.
	atomic.StoreUint32(&c.p2pMode, 1)
	assert.True(t, c.IsP2PMode())

	// Simulate relay mode.
	atomic.StoreUint32(&c.p2pMode, 0)
	assert.False(t, c.IsP2PMode())
}

func TestClient_GetStats(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Initial stats should be zero.
	stats := c.GetStats()
	assert.Equal(t, uint64(0), stats.BytesIn)
	assert.Equal(t, uint64(0), stats.BytesOut)
	assert.Equal(t, uint64(0), stats.Requests)
	assert.Equal(t, uint64(0), stats.Reconnects)
}

func TestClient_GetStats_AfterActivity(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Simulate activity.
	atomic.AddUint64(&c.stats.BytesIn, 1024)
	atomic.AddUint64(&c.stats.BytesOut, 2048)
	atomic.AddUint64(&c.stats.Requests, 10)
	atomic.AddUint64(&c.stats.Reconnects, 3)

	stats := c.GetStats()
	assert.Equal(t, uint64(1024), stats.BytesIn)
	assert.Equal(t, uint64(2048), stats.BytesOut)
	assert.Equal(t, uint64(10), stats.Requests)
	assert.Equal(t, uint64(3), stats.Reconnects)
}

func TestClient_GetPublicURL(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Initially empty.
	c.mu.Lock()
	assert.Equal(t, "", c.publicURL)
	c.mu.Unlock()

	// Set a public URL.
	c.mu.Lock()
	c.publicURL = "https://myapp.worm.io"
	c.mu.Unlock()

	c.mu.Lock()
	assert.Equal(t, "https://myapp.worm.io", c.publicURL)
	c.mu.Unlock()
}

func TestClient_Close(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Close should succeed.
	err := c.Close()
	assert.NoError(t, err)

	// Double close should be no-op.
	err = c.Close()
	assert.NoError(t, err)
}

func TestClient_Close_Idempotent(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Close multiple times concurrently.
	done := make(chan struct{}, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_ = c.Close()
			done <- struct{}{}
		}()
	}

	for range 5 {
		<-done
	}

	// Should be closed.
	assert.Equal(t, uint32(1), atomic.LoadUint32(&c.closed))
}

func TestClient_ParseEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	tests := []struct {
		name    string
		addr    string
		wantIP  string
		wantPrt int
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			addr:    "1.2.3.4:5000",
			wantIP:  "1.2.3.4",
			wantPrt: 5000,
		},
		{
			name:    "valid IPv6",
			addr:    "[::1]:8080",
			wantIP:  "::1",
			wantPrt: 8080,
		},
		{
			name:    "valid hostname",
			addr:    "example.com:443",
			wantIP:  "example.com",
			wantPrt: 443,
		},
		{
			name:    "invalid no port",
			addr:    "1.2.3.4",
			wantErr: true,
		},
		{
			name:    "invalid empty",
			addr:    "",
			wantErr: true,
		},
		{
			name:    "invalid port",
			addr:    "1.2.3.4:abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := c.parseEndpoint(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantIP, ep.IP)
				assert.Equal(t, tt.wantPrt, ep.Port)
			}
		})
	}
}

func TestClient_FallbackToRelay_NotInP2PMode(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Not in P2P mode, should be a no-op.
	c.fallbackToRelay("test reason")
	assert.False(t, c.IsP2PMode())
}

func TestClient_FallbackToRelay_InP2PMode(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Simulate being in P2P mode.
	atomic.StoreUint32(&c.p2pMode, 1)
	assert.True(t, c.IsP2PMode())

	c.fallbackToRelay("read error")

	assert.False(t, c.IsP2PMode())
	assert.Nil(t, c.p2pTransport)
	assert.Nil(t, c.p2pConn)
	assert.Nil(t, c.p2pPeer)
	assert.Nil(t, c.p2pKeyPair)
	assert.Nil(t, c.p2pCipher)
}

func TestClient_GetInspector(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	insp := c.GetInspector()
	require.NotNil(t, insp)
}

func TestClient_GetP2PManager(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	mgr := c.GetP2PManager()
	require.NotNil(t, mgr)
}

func TestClient_StartInspector_ZeroPort(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Port 0 should be a no-op.
	err := c.StartInspector(0)
	assert.NoError(t, err)
}

// --- Helper: create a mux pair for integration tests ---

func newClientMuxPair(t *testing.T) (*tunnel.Mux, *tunnel.Mux) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	cfg := tunnel.DefaultMuxConfig()
	cfg.KeepAliveInterval = 0

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

// --- Client Integration Tests ---

func TestClient_Authenticate_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "valid-token"
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Server goroutine: accept stream, validate token, send success.
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.AuthRequest == nil {
			return
		}

		// Validate token matches.
		require.Equal(t, "valid-token", msg.AuthRequest.Token)

		// Send success response.
		resp := proto.NewAuthResponse(true, "", "mysubdomain", "", "session-123")
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.authenticate(context.Background())
	require.NoError(t, err)

	c.mu.Lock()
	assert.Equal(t, "mysubdomain", c.config.Subdomain)
	c.mu.Unlock()
}

func TestClient_Authenticate_Failure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "invalid-token"
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Server goroutine: reject auth.
	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		resp := proto.NewAuthResponse(false, "bad credentials", "", "", "")
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.authenticate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected authentication")
}

func TestClient_Authenticate_NilMux(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "token"
	c := NewClient(cfg)

	// mux is nil.
	err := c.authenticate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestClient_RegisterTunnel_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 8080
	cfg.Subdomain = "myapp"
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Server goroutine: accept stream, read register, send success.
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.RegisterRequest == nil {
			return
		}

		assert.Equal(t, uint32(8080), msg.RegisterRequest.LocalPort)
		assert.Equal(t, proto.ProtocolHTTP, msg.RegisterRequest.Protocol)

		resp := proto.NewRegisterResponse(true, "", "tunnel-123", "https://myapp.example.com", 0)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.registerTunnel(context.Background())
	require.NoError(t, err)

	c.mu.Lock()
	assert.Equal(t, "tunnel-123", c.tunnelID)
	assert.Equal(t, "https://myapp.example.com", c.publicURL)
	c.mu.Unlock()
}

func TestClient_RegisterTunnel_Failure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 8080
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		resp := proto.NewRegisterResponse(false, "server busy", "", "", 0)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.registerTunnel(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration failed")
}

func TestClient_RegisterTunnel_NilMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	err := c.registerTunnel(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestClient_RegisterTunnel_InvalidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = -1
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Server side not needed since it will fail before writing.
	_ = serverMux

	err := c.registerTunnel(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid local port")
}

func TestClient_SendPing_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HeartbeatTimeout = 5 * time.Second
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Server goroutine: accept stream, read ping, send pong.
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.PingRequest == nil {
			return
		}

		assert.Equal(t, uint64(42), msg.PingRequest.PingID)

		resp := proto.NewPingResponse(msg.PingRequest.PingID)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.sendPing(context.Background(), 42)
	require.NoError(t, err)
}

func TestClient_SendPing_NilMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	err := c.sendPing(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestClient_DeriveP2PCipher_Success(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Generate a local key pair.
	localKeyPair, err := p2p.GenerateKeyPair()
	require.NoError(t, err)

	c.mu.Lock()
	c.p2pKeyPair = localKeyPair
	c.mu.Unlock()

	// Generate a peer key pair.
	peerKeyPair, err := p2p.GenerateKeyPair()
	require.NoError(t, err)

	peerPubB64 := base64.StdEncoding.EncodeToString(peerKeyPair.Public)

	err = c.deriveP2PCipher(peerPubB64)
	require.NoError(t, err)

	c.mu.Lock()
	assert.NotNil(t, c.p2pCipher)
	c.mu.Unlock()
}

func TestClient_DeriveP2PCipher_InvalidBase64(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	localKeyPair, err := p2p.GenerateKeyPair()
	require.NoError(t, err)
	c.mu.Lock()
	c.p2pKeyPair = localKeyPair
	c.mu.Unlock()

	err = c.deriveP2PCipher("not-valid-base64!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode peer public key")
}

func TestClient_DeriveP2PCipher_NilKeyPair(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// No local key pair.
	peerKeyPair, err := p2p.GenerateKeyPair()
	require.NoError(t, err)
	peerPubB64 := base64.StdEncoding.EncodeToString(peerKeyPair.Public)

	err = c.deriveP2PCipher(peerPubB64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local key pair not generated")
}

func TestClient_HandleStream_StreamRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 19999 // A port likely not in use.
	cfg.LocalHost = "127.0.0.1"
	c := NewClient(cfg)

	// Disable inspector capture to avoid forwardHTTPWithInspect trying to parse HTTP.
	c.inspector.SetEnabled(false)

	clientMux, serverMux := newClientMuxPair(t)

	// Server opens a stream to client, sends a StreamRequest.
	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	req := proto.NewStreamRequest("", "req-1", "1.2.3.4:1234", proto.ProtocolHTTP)
	err = proto.WriteControlMessage(serverStream, req)
	require.NoError(t, err)

	// Client accepts and handles the stream.
	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	// handleStream blocks until forwarding completes; run it with a timeout.
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleStream(context.Background(), clientStream)
	}()

	// Wait for handleStream to finish (it should fail to dial quickly).
	select {
	case <-done:
		// ok
	case <-time.After(10 * time.Second):
		t.Fatal("handleStream timed out")
	}

	// Close server stream to unblock its goroutines.
	_ = serverStream.Close()

	// Requests counter should be incremented.
	assert.Equal(t, uint64(1), atomic.LoadUint64(&c.stats.Requests))
}

func TestClient_Close_WithMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientConn, _ := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	clientMux, err := tunnel.Client(clientConn, muxCfg)
	require.NoError(t, err)

	c.mu.Lock()
	c.mux = clientMux
	c.conn = clientConn
	c.mu.Unlock()

	err = c.Close()
	assert.NoError(t, err)
	assert.True(t, clientMux.IsClosed())
}

func TestClient_StartInspector_WithPort(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Use port 0 to let the OS pick a free port. But StartInspector(0) returns early.
	// Use a specific port instead.
	err := c.StartInspector(19876)
	assert.NoError(t, err)

	// Verify the server was created.
	c.mu.Lock()
	assert.NotNil(t, c.inspectorServer)
	assert.NotNil(t, c.inspectorHandler)
	c.mu.Unlock()

	// Cleanup.
	_ = c.Close()
}

// --- forwardHTTPWithInspect tests ---

// TestClient_ForwardHTTPWithInspect_Success verifies the full HTTP-aware
// forwarding path: stream → parse HTTP → forward to local httptest.Server →
// write response back to stream, with inspector capture.
func TestClient_ForwardHTTPWithInspect_Success(t *testing.T) {
	// Start a local HTTP server to receive forwarded requests.
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request was forwarded correctly.
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/test", r.URL.Path)

		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response from local"))
	}))
	defer localServer.Close()

	// Parse the local server's address.
	localAddr := localServer.Listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(localAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = host
	cfg.LocalPort = port
	c := NewClient(cfg)
	// Enable inspector capture.
	c.inspector.SetEnabled(true)

	clientMux, serverMux := newClientMuxPair(t)

	// Server opens a stream to the client.
	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	// Client accepts the stream.
	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "fwd-test-1",
		Protocol:  proto.ProtocolHTTP,
	}

	// Write a raw HTTP request to the stream (simulating what the server handler does).
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardHTTPWithInspect(context.Background(), clientStream, sreq)
	}()

	// Write raw HTTP request to server stream.
	httpReqStr := "GET /api/test HTTP/1.1\r\n" +
		"Host: myapp.example.com\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	_, err = serverStream.Write([]byte(httpReqStr))
	require.NoError(t, err)

	// Read the HTTP response from the server stream.
	br := bufio.NewReader(serverStream)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "response from local", string(body))
	assert.Equal(t, "test-value", resp.Header.Get("X-Test-Header"))

	_ = serverStream.Close()
	<-done

	// Verify inspector captured the request.
	records := c.inspector.Records(10, 0)
	require.NotEmpty(t, records, "inspector should capture the request/response")
	assert.Equal(t, http.StatusOK, records[0].Status)
}

// TestClient_ForwardHTTPWithInspect_LocalDown verifies that when the local
// service is unavailable, a 502 response is written back.
func TestClient_ForwardHTTPWithInspect_LocalDown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = 19998 // Port with nothing listening.
	c := NewClient(cfg)
	c.inspector.SetEnabled(true)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "fwd-test-502",
		Protocol:  proto.ProtocolHTTP,
	}

	// Read the 502 response in a goroutine to avoid deadlock:
	// forwardHTTPWithInspect writes the response then returns, but
	// http.Response.Write uses chunked encoding (no ContentLength set),
	// so ReadAll blocks until the stream closes. We read in parallel
	// and let the function complete → stream close → body EOF.
	type readResult struct {
		statusCode int
		body       string
		err        error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		br := bufio.NewReader(serverStream)
		resp, readErr := http.ReadResponse(br, nil)
		if readErr != nil {
			resultCh <- readResult{err: readErr}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		resultCh <- readResult{statusCode: resp.StatusCode, body: string(body)}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardHTTPWithInspect(context.Background(), clientStream, sreq)
	}()

	// Write a valid HTTP request.
	httpReqStr := "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	_, _ = serverStream.Write([]byte(httpReqStr))

	// Wait for forwardHTTPWithInspect to complete.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("forwardHTTPWithInspect timed out")
	}

	// Close the client stream so the reader goroutine sees EOF on body.
	_ = clientStream.Close()

	// Read result.
	select {
	case res := <-resultCh:
		require.NoError(t, res.err)
		assert.Equal(t, http.StatusBadGateway, res.statusCode)
		assert.Contains(t, res.body, "Local service unavailable")
	case <-time.After(5 * time.Second):
		t.Fatal("reading 502 response timed out")
	}

	_ = serverStream.Close()
}

// --- heartbeatLoop tests ---

// TestClient_HeartbeatLoop verifies that the heartbeat loop sends periodic
// pings and exits when the context is canceled.
func TestClient_HeartbeatLoop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HeartbeatInterval = 50 * time.Millisecond
	cfg.HeartbeatTimeout = 2 * time.Second
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Count pings received by the server.
	var pingCount int32
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
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
				if err != nil || msg.PingRequest == nil {
					return
				}

				atomic.AddInt32(&pingCount, 1)

				// Send pong.
				resp := proto.NewPingResponse(msg.PingRequest.PingID)
				data, _ := resp.Encode()
				_, _ = stream.Write(data)
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())

	// heartbeatLoop expects closeWg to be set up.
	c.closeWg.Add(1)
	go c.heartbeatLoop(ctx)

	// Let it run for enough time to send several pings.
	time.Sleep(250 * time.Millisecond)
	cancel()

	c.closeWg.Wait()

	count := atomic.LoadInt32(&pingCount)
	assert.GreaterOrEqual(t, count, int32(3),
		"should have sent at least 3 pings in 250ms with 50ms interval, got %d", count)

	_ = serverMux.Close()
	<-serverDone
}

// TestClient_HeartbeatLoop_MuxClosed verifies that the heartbeat loop exits
// gracefully when the mux is closed.
func TestClient_HeartbeatLoop_MuxClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HeartbeatInterval = 50 * time.Millisecond
	cfg.HeartbeatTimeout = 1 * time.Second
	c := NewClient(cfg)

	clientMux, _ := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Close mux immediately.
	_ = clientMux.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.closeWg.Add(1)
	go c.heartbeatLoop(ctx)

	// Should exit quickly since mux is closed.
	done := make(chan struct{})
	go func() {
		c.closeWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeatLoop should exit when mux is closed")
	}
}

// --- connectWithRetry tests ---

// TestClient_ConnectWithRetry_MaxAttempts verifies that connectWithRetry
// returns an error after exhausting maximum reconnection attempts.
func TestClient_ConnectWithRetry_MaxAttempts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:1" // Unreachable port.
	cfg.MaxReconnectAttempts = 2
	cfg.ReconnectInterval = 10 * time.Millisecond
	cfg.ReconnectBackoff = 1.0
	cfg.MaxReconnectInterval = 50 * time.Millisecond
	c := NewClient(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := c.connectWithRetry(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max reconnection attempts reached")

	// Reconnects is incremented only for attempts that are followed by a retry.
	// The final attempt (that triggers the max error) does not increment.
	stats := c.GetStats()
	assert.Equal(t, uint64(1), stats.Reconnects)
}

// TestClient_ConnectWithRetry_ContextCancel verifies that connectWithRetry
// returns ctx.Err() when the context is canceled during backoff.
func TestClient_ConnectWithRetry_ContextCancel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:1"
	cfg.MaxReconnectAttempts = 0 // Infinite.
	cfg.ReconnectInterval = 5 * time.Second
	cfg.ReconnectBackoff = 1.0
	c := NewClient(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.connectWithRetry(ctx)
	}()

	// Cancel after first failure's backoff starts.
	time.Sleep(200 * time.Millisecond)
	cancel()

	err := <-errCh
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestClient_ConnectWithRetry_CloseCh verifies that connectWithRetry
// returns nil when closeCh is signaled.
func TestClient_ConnectWithRetry_CloseCh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:1"
	cfg.MaxReconnectAttempts = 0
	cfg.ReconnectInterval = 5 * time.Second
	c := NewClient(cfg)

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.connectWithRetry(ctx)
	}()

	// Signal close.
	time.Sleep(200 * time.Millisecond)
	close(c.closeCh)

	err := <-errCh
	assert.NoError(t, err)
}

// --- handleConnection + acceptStreams tests ---

// TestClient_AcceptStreams verifies that acceptStreams dispatches incoming
// tunnel streams to handleStream correctly.
func TestClient_AcceptStreams(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 19997
	cfg.LocalHost = "127.0.0.1"
	c := NewClient(cfg)
	c.inspector.SetEnabled(false)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	c.closeWg.Add(1)
	go c.acceptStreams(ctx)

	// Server opens 3 streams, each with a StreamRequest.
	for i := 0; i < 3; i++ {
		stream, err := serverMux.OpenStream()
		require.NoError(t, err)

		req := proto.NewStreamRequest("", fmt.Sprintf("req-%d", i), "10.0.0.1:1234", proto.ProtocolHTTP)
		_ = proto.WriteControlMessage(stream, req)

		// Read response (error response since local is not listening).
		buf := make([]byte, 4096)
		_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = stream.Read(buf)
		_ = stream.Close()
	}

	// Give time for all streams to be processed.
	time.Sleep(100 * time.Millisecond)

	// Verify requests were counted.
	assert.Equal(t, uint64(3), atomic.LoadUint64(&c.stats.Requests))

	cancel()
	c.closeWg.Wait()
}

// TestClient_SendP2PResult verifies that sendP2PResult sends the correct
// P2P result message through the mux.
func TestClient_SendP2PResult_Success(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.tunnelID = "tunnel-42"
	c.mu.Unlock()

	// Server goroutine: accept stream, read P2P result.
	resultCh := make(chan *proto.P2PResult, 1)
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.P2PResult == nil {
			return
		}
		resultCh <- msg.P2PResult
	}()

	c.sendP2PResult(context.Background(), true, "5.6.7.8:9000", "")

	select {
	case result := <-resultCh:
		assert.True(t, result.Success)
		assert.Equal(t, "5.6.7.8:9000", result.PeerAddr)
		assert.Equal(t, "tunnel-42", result.TunnelID)
	case <-time.After(3 * time.Second):
		t.Fatal("did not receive P2P result")
	}
}

// TestClient_SendP2PResult_ClosedMux verifies sendP2PResult is a no-op
// when the mux is already closed.
func TestClient_SendP2PResult_ClosedMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, _ := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Close mux.
	_ = clientMux.Close()

	// Should not panic or block.
	c.sendP2PResult(context.Background(), false, "", "test error")
}

// TestClient_HandleP2PNotification verifies that handleP2PNotification
// generates a key pair and derives a cipher when valid peer info is provided.
func TestClient_HandleP2PNotification_KeyDerivation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.P2PEnabled = true
	c := NewClient(cfg)

	// Generate a peer key pair to provide in the notification.
	peerKP, err := p2p.GenerateKeyPair()
	require.NoError(t, err)
	peerPubB64 := base64.StdEncoding.EncodeToString(peerKP.Public)

	resp := &proto.P2POfferResponse{
		Success:       true,
		PeerAddr:      "10.0.0.1:5000",
		PeerNATType:   "Full Cone",
		PeerPublicKey: peerPubB64,
	}

	// handleP2PNotification will start attemptP2P in a goroutine,
	// which will fail (no real peer). We just verify key derivation works.
	c.handleP2PNotification(context.Background(), resp)

	// Give a moment for the goroutine to start.
	time.Sleep(50 * time.Millisecond)

	c.mu.Lock()
	assert.NotNil(t, c.p2pKeyPair, "key pair should be generated")
	assert.NotNil(t, c.p2pCipher, "cipher should be derived from peer key")
	c.mu.Unlock()
}

// TestClient_HandleP2PNotification_NoSuccess verifies that handleP2PNotification
// is a no-op when the response indicates failure.
func TestClient_HandleP2PNotification_NoSuccess(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	resp := &proto.P2POfferResponse{
		Success:  false,
		PeerAddr: "",
	}

	// Should return immediately without generating keys.
	c.handleP2PNotification(context.Background(), resp)

	c.mu.Lock()
	assert.Nil(t, c.p2pKeyPair)
	c.mu.Unlock()
}

// TestClient_ForwardToLocal_HTTPWithInspector verifies that when the inspector
// is enabled and protocol is HTTP, forwardToLocal delegates to forwardHTTPWithInspect.
func TestClient_ForwardToLocal_HTTPWithInspector(t *testing.T) {
	// Start a local HTTP server.
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer localServer.Close()

	localAddr := localServer.Listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(localAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = host
	cfg.LocalPort = port
	c := NewClient(cfg)
	c.inspector.SetEnabled(true) // Inspector enabled + HTTP protocol → forwardHTTPWithInspect.

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "http-inspect-test",
		Protocol:  proto.ProtocolHTTP,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardToLocal(context.Background(), clientStream, sreq)
	}()

	// Write a valid HTTP request.
	httpReq := "GET /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
	_, _ = serverStream.Write([]byte(httpReq))

	// Read the response.
	br := bufio.NewReader(serverStream)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	_ = serverStream.Close()
	<-done
}

// TestClient_ForwardToLocal_InspectorDisabled verifies that when the
// inspector is disabled, forwardToLocal uses raw TCP even for HTTP protocol.
func TestClient_ForwardToLocal_InspectorDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 19996
	cfg.LocalHost = "127.0.0.1"
	c := NewClient(cfg)
	c.inspector.SetEnabled(false)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "fwd-disabled",
		Protocol:  proto.ProtocolHTTP,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardToLocal(context.Background(), clientStream, sreq)
	}()

	// Should use raw TCP path. Since nothing is listening, it should get
	// an error response.
	buf := make([]byte, 4096)
	_ = serverStream.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := serverStream.Read(buf)

	if n > 0 {
		// Should get a StreamResponse with failure.
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr == nil && msg.StreamResponse != nil {
			assert.False(t, msg.StreamResponse.Accepted)
			assert.Contains(t, msg.StreamResponse.Error, "Local service unavailable")
		}
	}

	_ = serverStream.Close()
	<-done
}

// --- dialAndProxy success path tests ---

// TestClient_DialAndProxy_Success verifies the full bidirectional proxy path:
// client stream ↔ local TCP server, with BytesIn/BytesOut stats updated.
func TestClient_DialAndProxy_Success(t *testing.T) {
	// Start a local TCP echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Echo: read data and write it back.
				buf := make([]byte, 4096)
				n, readErr := c.Read(buf)
				if readErr != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = port
	c := NewClient(cfg)
	c.inspector.SetEnabled(false)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "proxy-test",
		Protocol:  proto.ProtocolHTTP,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardRawTCP(context.Background(), clientStream, sreq)
	}()

	// Write data from the "remote" side.
	testData := []byte("hello from tunnel")
	_, err = serverStream.Write(testData)
	require.NoError(t, err)

	// Read the echoed response from the local server.
	buf := make([]byte, 4096)
	_ = serverStream.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, readErr := serverStream.Read(buf)
	require.NoError(t, readErr)
	assert.Equal(t, "hello from tunnel", string(buf[:n]))

	// Close the server stream to unblock proxy goroutines.
	_ = serverStream.Close()
	<-done

	// Verify BytesIn and BytesOut were updated.
	stats := c.GetStats()
	assert.Greater(t, stats.BytesIn, uint64(0), "BytesIn should be incremented")
	assert.Greater(t, stats.BytesOut, uint64(0), "BytesOut should be incremented")
}

// TestClient_ForwardRawTCPWithReader verifies the custom reader path.
func TestClient_ForwardRawTCPWithReader(t *testing.T) {
	// Start a local TCP server that reads data and responds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, readErr := c.Read(buf)
				if readErr != nil {
					return
				}
				_, _ = c.Write([]byte("echo:" + string(buf[:n])))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = port
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "reader-test",
		Protocol:  proto.ProtocolTCP,
	}

	// Create a custom reader wrapping some pre-buffered data + stream.
	prefixData := []byte("prefix-data")
	customReader := io.MultiReader(bytes.NewReader(prefixData), clientStream)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardRawTCPWithReader(context.Background(), customReader, clientStream, sreq)
	}()

	// Read echoed response.
	buf := make([]byte, 4096)
	_ = serverStream.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, readErr := serverStream.Read(buf)
	require.NoError(t, readErr)
	// The echo server should see the prefix data.
	assert.Contains(t, string(buf[:n]), "echo:prefix-data")

	_ = serverStream.Close()
	<-done
}

// TestClient_HandleStream_DefaultBranch exercises the default (unknown message) branch.
func TestClient_HandleStream_DefaultBranch(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)

	// Server opens a stream and sends a message with no StreamRequest or P2POfferResponse.
	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	// Send a PingRequest which is not handled by handleStream's switch.
	msg := proto.NewPingRequest(99)
	err = proto.WriteControlMessage(serverStream, msg)
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleStream(context.Background(), clientStream)
	}()

	select {
	case <-done:
		// handleStream should log warning and return without incrementing Requests.
	case <-time.After(5 * time.Second):
		t.Fatal("handleStream should return quickly for unknown message type")
	}

	// Requests counter should NOT be incremented for unknown types.
	assert.Equal(t, uint64(0), atomic.LoadUint64(&c.stats.Requests))
	_ = serverStream.Close()
}

// TestClient_HandleStream_ReadError exercises the read error path.
func TestClient_HandleStream_ReadError(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)

	// Server opens a stream but closes it immediately.
	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)
	_ = serverStream.Close()

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleStream(context.Background(), clientStream)
	}()

	select {
	case <-done:
		// Should return due to read error (EOF).
	case <-time.After(5 * time.Second):
		t.Fatal("handleStream should return on read error")
	}
}

// TestClient_HandleStream_DecodeError exercises the decode error path.
func TestClient_HandleStream_DecodeError(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	// Send garbage data that can't be decoded.
	_, err = serverStream.Write([]byte("this is not a valid proto message"))
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleStream(context.Background(), clientStream)
	}()

	select {
	case <-done:
		// Should return due to decode error.
	case <-time.After(5 * time.Second):
		t.Fatal("handleStream should return on decode error")
	}

	_ = serverStream.Close()
}

// TestClient_ForwardToLocal_TCPProtocol verifies that TCP protocol uses raw TCP path
// even when the inspector is enabled.
func TestClient_ForwardToLocal_TCPProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 19994
	cfg.LocalHost = "127.0.0.1"
	c := NewClient(cfg)
	c.inspector.SetEnabled(true)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "tcp-proto-test",
		Protocol:  proto.ProtocolTCP,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardToLocal(context.Background(), clientStream, sreq)
	}()

	// Raw TCP path: since no local service is listening, should get error response.
	buf := make([]byte, 4096)
	_ = serverStream.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := serverStream.Read(buf)
	if n > 0 {
		msg, decErr := proto.DecodeControlMessage(buf[:n])
		if decErr == nil && msg.StreamResponse != nil {
			assert.False(t, msg.StreamResponse.Accepted)
			assert.Contains(t, msg.StreamResponse.Error, "Local service unavailable")
		}
	}

	_ = serverStream.Close()
	<-done
}

// TestClient_HandleStream_P2POfferResponse exercises the P2POfferResponse branch.
func TestClient_HandleStream_P2POfferResponse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.P2PEnabled = true
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)

	// Generate a peer key pair.
	peerKP, err := p2p.GenerateKeyPair()
	require.NoError(t, err)
	peerPubB64 := base64.StdEncoding.EncodeToString(peerKP.Public)

	// Server sends a P2POfferResponse via a stream.
	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	resp := proto.NewP2POfferResponse(true, "", "10.0.0.1:5000", "Full Cone", peerPubB64)
	err = proto.WriteControlMessage(serverStream, resp)
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleStream(context.Background(), clientStream)
	}()

	select {
	case <-done:
		// handleStream should process the P2POfferResponse and return.
	case <-time.After(5 * time.Second):
		t.Fatal("handleStream with P2POfferResponse timed out")
	}

	// Give time for the async handleP2PNotification goroutine to run.
	time.Sleep(100 * time.Millisecond)

	// The P2P key pair should have been generated and cipher derived.
	c.mu.Lock()
	assert.NotNil(t, c.p2pKeyPair, "key pair should be generated from P2POfferResponse")
	assert.NotNil(t, c.p2pCipher, "cipher should be derived from P2POfferResponse")
	c.mu.Unlock()

	_ = serverStream.Close()
}

// --- P2P data handling tests ---

// TestClient_SendP2PResponse_EncodeError verifies that sendP2PResponse
// handles the encode path and nil transport gracefully.
// The non-nil transport write path is covered indirectly by
// TestClient_ForwardP2PRequestToLocal_Success + TestClient_ForwardP2PDataToLocal_Success.

// TestClient_SendP2PResponse_NilTransport verifies no-op when transport is nil.
func TestClient_SendP2PResponse_NilTransport(_ *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Transport is nil. Should not panic.
	c.sendP2PResponse("req-456", false, "some error")
}

// TestClient_HandleP2PData_ValidStreamRequest exercises the StreamRequest branch.
func TestClient_HandleP2PData_ValidStreamRequest(t *testing.T) {
	// Start a local TCP server to receive the forwarded P2P request.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = port
	c := NewClient(cfg)

	// Encode a StreamRequest to simulate P2P data.
	req := proto.NewStreamRequest("", "p2p-req-1", "1.2.3.4:1234", proto.ProtocolHTTP)
	data, _ := req.Encode()

	// handleP2PData should decode the message and route to forwardP2PRequestToLocal.
	c.handleP2PData(context.Background(), data)

	// Requests counter should be incremented.
	assert.Equal(t, uint64(1), atomic.LoadUint64(&c.stats.Requests))
}

// TestClient_HandleP2PData_InvalidData exercises the raw data fallback.
func TestClient_HandleP2PData_InvalidData(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = 19993 // Nothing listening.
	c := NewClient(cfg)

	// Garbage data that can't be decoded as a proto message.
	c.handleP2PData(context.Background(), []byte("raw-binary-data"))

	// Should not panic; requests counter should not be incremented.
	assert.Equal(t, uint64(0), atomic.LoadUint64(&c.stats.Requests))
}

// TestClient_ForwardP2PDataToLocal_Success exercises the full P2P data forwarding path.
func TestClient_ForwardP2PDataToLocal_Success(t *testing.T) {
	// Start a local TCP server that receives data and sends a response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, readErr := c.Read(buf)
				if readErr != nil {
					return
				}
				_, _ = c.Write([]byte("response-to:" + string(buf[:n])))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = port
	c := NewClient(cfg)

	// p2pTransport is nil — the response write-back part will be skipped,
	// but the local forward + BytesIn tracking should still work.
	c.forwardP2PDataToLocal(context.Background(), []byte("test-payload"))

	// Verify BytesIn was updated.
	stats := c.GetStats()
	assert.Greater(t, stats.BytesIn, uint64(0), "BytesIn should be updated after P2P data forwarding")
}

// TestClient_ForwardP2PDataToLocal_LocalDown verifies graceful handling when local is down.
func TestClient_ForwardP2PDataToLocal_LocalDown(_ *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = 19992 // Nothing listening.
	c := NewClient(cfg)

	// Should not panic even when local service is unavailable.
	c.forwardP2PDataToLocal(context.Background(), []byte("orphan-data"))
}

// TestClient_ForwardP2PRequestToLocal_Success verifies P2P request forwarding to local.
func TestClient_ForwardP2PRequestToLocal_Success(t *testing.T) {
	// Start a local TCP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = port
	c := NewClient(cfg)

	req := &proto.StreamRequest{
		RequestID: "p2p-fwd-1",
		Protocol:  proto.ProtocolHTTP,
	}

	// Should connect to local, then send a success response via P2P transport.
	// Without a transport set, sendP2PResponse will be a no-op.
	c.forwardP2PRequestToLocal(context.Background(), req)
}

// TestClient_ForwardP2PRequestToLocal_LocalDown verifies that when local is down,
// a failure P2P response is sent.
func TestClient_ForwardP2PRequestToLocal_LocalDown(_ *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalHost = "127.0.0.1"
	cfg.LocalPort = 19991
	c := NewClient(cfg)

	req := &proto.StreamRequest{
		RequestID: "p2p-fwd-fail",
		Protocol:  proto.ProtocolHTTP,
	}

	// Should not panic; sendP2PResponse with failure will be called.
	c.forwardP2PRequestToLocal(context.Background(), req)
}

// TestClient_ForwardHTTPWithInspect_InvalidHTTP verifies the fallback to raw TCP
// when the stream data is not valid HTTP.
func TestClient_ForwardHTTPWithInspect_InvalidHTTP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 19990
	cfg.LocalHost = "127.0.0.1"
	c := NewClient(cfg)
	c.inspector.SetEnabled(true)

	clientMux, serverMux := newClientMuxPair(t)

	serverStream, err := serverMux.OpenStream()
	require.NoError(t, err)

	clientStream, err := clientMux.AcceptStream()
	require.NoError(t, err)

	sreq := &proto.StreamRequest{
		RequestID: "invalid-http",
		Protocol:  proto.ProtocolHTTP,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardHTTPWithInspect(context.Background(), clientStream, sreq)
	}()

	// Write non-HTTP data with enough content to be buffered.
	_, _ = serverStream.Write([]byte("NOT HTTP DATA\x00\x01\x02"))
	// Close to trigger EOF so the reader finishes.
	_ = serverStream.Close()

	select {
	case <-done:
		// Should fall back to raw TCP and eventually return.
	case <-time.After(10 * time.Second):
		t.Fatal("forwardHTTPWithInspect should return after invalid HTTP fallback")
	}
}

// TestClient_Close_WithP2PResources verifies that Close properly cleans up P2P resources.
func TestClient_Close_WithP2PResources(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Set up P2P state without creating a real transport (which starts goroutines).
	pConn, _ := net.Pipe()

	kp, _ := p2p.GenerateKeyPair()
	peerKP, _ := p2p.GenerateKeyPair()
	cipher, _ := p2p.DeriveSession(kp.Private, peerKP.Public)

	c.mu.Lock()
	c.p2pConn = newFakePacketConn(pConn)
	// p2pTransport intentionally nil — Close handles nil transport gracefully.
	c.p2pPeer = &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}
	c.p2pCloseCh = make(chan struct{})
	c.p2pKeyPair = kp
	c.p2pCipher = cipher
	c.mu.Unlock()

	err := c.Close()
	assert.NoError(t, err)

	// Verify P2P resources were cleaned up.
	c.mu.Lock()
	assert.Nil(t, c.p2pConn)
	assert.Nil(t, c.p2pPeer)
	c.mu.Unlock()
}

// TestClient_FallbackToRelay_WithResources verifies fallbackToRelay properly
// cleans up P2P transport, conn, cipher, and key pair.
func TestClient_FallbackToRelay_WithResources(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// Set up full P2P state without real transport.
	pConn, _ := net.Pipe()

	kp, _ := p2p.GenerateKeyPair()
	peerKP, _ := p2p.GenerateKeyPair()
	cipher, _ := p2p.DeriveSession(kp.Private, peerKP.Public)

	c.mu.Lock()
	c.p2pConn = newFakePacketConn(pConn)
	// p2pTransport nil — fallback handles nil gracefully.
	c.p2pPeer = &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}
	c.p2pCloseCh = make(chan struct{})
	c.p2pKeyPair = kp
	c.p2pCipher = cipher
	c.mu.Unlock()
	atomic.StoreUint32(&c.p2pMode, 1)

	c.fallbackToRelay("test reason with resources")

	assert.False(t, c.IsP2PMode())
	c.mu.Lock()
	assert.Nil(t, c.p2pConn)
	assert.Nil(t, c.p2pPeer)
	assert.Nil(t, c.p2pKeyPair)
	assert.Nil(t, c.p2pCipher)
	assert.Nil(t, c.p2pCloseCh, "close channel should be nil after fallback")
	c.mu.Unlock()
}

// TestClient_Connect_DialFailure verifies that connect returns an error when
// the server address is unreachable.
func TestClient_Connect_DialFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:1" // Unreachable port.
	c := NewClient(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := c.connect(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial server")
}

// TestClient_Authenticate_UnexpectedResponse verifies authenticate handles
// a response with no AuthResponse field.
func TestClient_Authenticate_UnexpectedResponse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Token = "some-token"
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		// Send a PingResponse instead of AuthResponse.
		resp := proto.NewPingResponse(1)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.authenticate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response type")
}

// TestClient_RegisterTunnel_UnexpectedResponse verifies registerTunnel handles
// a response with no RegisterResponse field.
func TestClient_RegisterTunnel_UnexpectedResponse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 8080
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		// Send a PingResponse instead of RegisterResponse.
		resp := proto.NewPingResponse(1)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.registerTunnel(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response type")
}

// --- fakePacketConn for P2P transport testing ---

// fakePacketConn wraps a net.Conn to satisfy the net.PacketConn interface.
type fakePacketConn struct {
	conn net.Conn
}

func newFakePacketConn(conn net.Conn) *fakePacketConn {
	return &fakePacketConn{conn: conn}
}

func (f *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = f.conn.Read(p)
	return n, &net.UDPAddr{}, err
}

func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return f.conn.Write(p)
}

func (f *fakePacketConn) Close() error {
	return f.conn.Close()
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (f *fakePacketConn) SetDeadline(t time.Time) error {
	return f.conn.SetDeadline(t)
}

func (f *fakePacketConn) SetReadDeadline(t time.Time) error {
	return f.conn.SetReadDeadline(t)
}

func (f *fakePacketConn) SetWriteDeadline(t time.Time) error {
	return f.conn.SetWriteDeadline(t)
}

// ============================================================================
// P0-2 Multi-Protocol: parseProtocol Tests
// ============================================================================

// TestParseProtocol verifies parseProtocol maps protocol strings correctly.
func TestParseProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected proto.Protocol
	}{
		{"http", proto.ProtocolHTTP},
		{"HTTP", proto.ProtocolHTTP},
		{"Http", proto.ProtocolHTTP},
		{"", proto.ProtocolHTTP},
		{"https", proto.ProtocolHTTPS},
		{"HTTPS", proto.ProtocolHTTPS},
		{"tcp", proto.ProtocolTCP},
		{"TCP", proto.ProtocolTCP},
		{"udp", proto.ProtocolUDP},
		{"UDP", proto.ProtocolUDP},
		{"ws", proto.ProtocolWebSocket},
		{"websocket", proto.ProtocolWebSocket},
		{"WebSocket", proto.ProtocolWebSocket},
		{"grpc", proto.ProtocolGRPC},
		{"gRPC", proto.ProtocolGRPC},
		{"unknown", proto.ProtocolHTTP},
		{"ftp", proto.ProtocolHTTP},
	}

	for _, tt := range tests {
		t.Run("protocol_"+tt.input, func(t *testing.T) {
			result := parseProtocol(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// P0-1 TLS: buildTLSConfig Tests
// ============================================================================

// TestBuildTLSConfig_Defaults verifies TLS config defaults.
func TestBuildTLSConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "example.com:7000"
	cfg.TLSEnabled = true

	c := NewClient(cfg)
	tlsCfg, err := c.buildTLSConfig()
	require.NoError(t, err)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	assert.False(t, tlsCfg.InsecureSkipVerify)
	assert.Equal(t, "example.com", tlsCfg.ServerName)
	assert.Nil(t, tlsCfg.RootCAs) // No custom CA.
}

// TestBuildTLSConfig_Insecure verifies InsecureSkipVerify when TLSInsecure is set.
func TestBuildTLSConfig_Insecure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "example.com:7000"
	cfg.TLSEnabled = true
	cfg.TLSInsecure = true

	c := NewClient(cfg)
	tlsCfg, err := c.buildTLSConfig()
	require.NoError(t, err)

	assert.True(t, tlsCfg.InsecureSkipVerify)
	assert.Equal(t, "example.com", tlsCfg.ServerName)
}

// TestBuildTLSConfig_ServerNameFromAddr verifies SNI extraction.
func TestBuildTLSConfig_ServerNameFromAddr(t *testing.T) {
	tests := []struct {
		name       string
		serverAddr string
		expectSNI  string
	}{
		{"host:port", "myserver.io:7000", "myserver.io"},
		{"IP:port", "10.0.0.1:7000", "10.0.0.1"},
		{"no port", "myserver.io", "myserver.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ServerAddr = tt.serverAddr
			cfg.TLSEnabled = true

			c := NewClient(cfg)
			tlsCfg, err := c.buildTLSConfig()
			require.NoError(t, err)
			assert.Equal(t, tt.expectSNI, tlsCfg.ServerName)
		})
	}
}

// TestBuildTLSConfig_InvalidCAFile verifies error on missing CA file.
func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "example.com:7000"
	cfg.TLSEnabled = true
	cfg.TLSCACert = "/nonexistent/ca-cert.pem"

	c := NewClient(cfg)
	_, err := c.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read CA certificate")
}

// TestBuildTLSConfig_InvalidCACert verifies error on invalid PEM content.
func TestBuildTLSConfig_InvalidCACert(t *testing.T) {
	// Create a temp file with invalid PEM content.
	tmpFile, err := os.CreateTemp(t.TempDir(), "invalid-ca-*.pem")
	require.NoError(t, err)

	_, err = tmpFile.WriteString("this is not a valid PEM certificate")
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	cfg := DefaultConfig()
	cfg.ServerAddr = "example.com:7000"
	cfg.TLSEnabled = true
	cfg.TLSCACert = tmpFile.Name()

	c := NewClient(cfg)
	_, err = c.buildTLSConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

// ============================================================================
// P0 Config: New Fields Tests
// ============================================================================

// TestDefaultConfig_NewP0Fields verifies that new P0 config fields have correct defaults.
func TestDefaultConfig_NewP0Fields(t *testing.T) {
	cfg := DefaultConfig()

	// P0-3: InspectorHost not set in DefaultConfig (empty string → caller uses "127.0.0.1").
	assert.Empty(t, cfg.InspectorHost)

	// P0-1: TLS defaults to disabled.
	assert.False(t, cfg.TLSEnabled)
	assert.False(t, cfg.TLSInsecure)
	assert.Empty(t, cfg.TLSCACert)

	// P0-2: Protocol defaults to empty (interpreted as "http").
	assert.Empty(t, cfg.Protocol)
	assert.Empty(t, cfg.Hostname)
	assert.Empty(t, cfg.PathPrefix)
}

// TestConfigFields_CanBeSet verifies P0 config fields can be set.
func TestConfigFields_CanBeSet(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InspectorHost = "0.0.0.0"
	cfg.TLSEnabled = true
	cfg.TLSInsecure = true
	cfg.TLSCACert = "/path/to/ca.pem"
	cfg.Protocol = "tcp"
	cfg.Hostname = "custom.example.com"
	cfg.PathPrefix = "/api/v1"

	assert.Equal(t, "0.0.0.0", cfg.InspectorHost)
	assert.True(t, cfg.TLSEnabled)
	assert.True(t, cfg.TLSInsecure)
	assert.Equal(t, "/path/to/ca.pem", cfg.TLSCACert)
	assert.Equal(t, "tcp", cfg.Protocol)
	assert.Equal(t, "custom.example.com", cfg.Hostname)
	assert.Equal(t, "/api/v1", cfg.PathPrefix)
}

// ============================================================================
// P1-2 Control Protocol: RequestStats / CloseTunnel Integration Tests
// ============================================================================

// TestClient_RequestStats_Success verifies that RequestStats sends a StatsRequest
// and correctly parses the StatsResponse from the server.
func TestClient_RequestStats_Success(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.sessionID = "session-abc"
	c.mu.Unlock()

	// Server goroutine: accept stream, read StatsRequest, send StatsResponse.
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.StatsRequest == nil {
			return
		}

		// Validate session ID matches.
		require.Equal(t, "session-abc", msg.StatsRequest.SessionID)

		resp := proto.NewStatsResponse(2, 5, 1024, 2048, 100, 3600)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	stats, err := c.RequestStats(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, uint32(2), stats.ActiveTunnels)
	assert.Equal(t, uint32(5), stats.ActiveConnections)
	assert.Equal(t, uint64(1024), stats.BytesSent)
	assert.Equal(t, uint64(2048), stats.BytesReceived)
	assert.Equal(t, uint64(100), stats.RequestsHandled)
	assert.Equal(t, uint64(3600), stats.UptimeSeconds)
}

// TestClient_RequestStats_NilMux verifies RequestStats returns an error when not connected.
func TestClient_RequestStats_NilMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// mux is nil.
	stats, err := c.RequestStats(context.Background())
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "not connected")
}

// TestClient_RequestStats_ClosedMux verifies RequestStats returns an error when mux is closed.
func TestClient_RequestStats_ClosedMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, _ := newClientMuxPair(t)
	_ = clientMux.Close()

	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	stats, err := c.RequestStats(context.Background())
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "not connected")
}

// TestClient_RequestStats_UnexpectedResponse verifies RequestStats handles
// a response with no StatsResponse field.
func TestClient_RequestStats_UnexpectedResponse(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		// Send a PingResponse instead of StatsResponse.
		resp := proto.NewPingResponse(1)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	stats, err := c.RequestStats(context.Background())
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "unexpected response type")
}

// TestClient_CloseTunnel_Success verifies that CloseTunnel sends a CloseRequest
// and correctly handles a successful CloseResponse.
func TestClient_CloseTunnel_Success(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	// Server goroutine: accept stream, read CloseRequest, send success CloseResponse.
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.CloseRequest == nil {
			return
		}

		// Validate tunnel ID and reason.
		require.Equal(t, "tunnel-xyz", msg.CloseRequest.TunnelID)
		require.Equal(t, "user requested", msg.CloseRequest.Reason)

		resp := proto.NewCloseResponse(true)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.CloseTunnel(context.Background(), "tunnel-xyz", "user requested")
	require.NoError(t, err)
}

// TestClient_CloseTunnel_Rejected verifies CloseTunnel handles server rejection.
func TestClient_CloseTunnel_Rejected(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		resp := proto.NewCloseResponse(false)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.CloseTunnel(context.Background(), "tunnel-404", "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server rejected close request")
}

// TestClient_CloseTunnel_NilMux verifies CloseTunnel returns an error when not connected.
func TestClient_CloseTunnel_NilMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	// mux is nil.
	err := c.CloseTunnel(context.Background(), "tunnel-1", "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestClient_CloseTunnel_ClosedMux verifies CloseTunnel returns an error when mux is closed.
func TestClient_CloseTunnel_ClosedMux(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, _ := newClientMuxPair(t)
	_ = clientMux.Close()

	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	err := c.CloseTunnel(context.Background(), "tunnel-closed", "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestClient_CloseTunnel_UnexpectedResponse verifies CloseTunnel handles
// a response with no CloseResponse field.
func TestClient_CloseTunnel_UnexpectedResponse(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.mu.Unlock()

	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, 4096)
		n, _ := stream.Read(buf)
		if n == 0 {
			return
		}

		// Send a PingResponse instead of CloseResponse.
		resp := proto.NewPingResponse(1)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.CloseTunnel(context.Background(), "tunnel-bad", "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response type")
}

// TestClient_Close_GracefulShutdown verifies that Close() sends a CloseRequest
// to the server when mux is connected and tunnelID is set.
func TestClient_Close_GracefulShutdown(t *testing.T) {
	cfg := DefaultConfig()
	c := NewClient(cfg)

	clientMux, serverMux := newClientMuxPair(t)
	c.mu.Lock()
	c.mux = clientMux
	c.tunnelID = "tunnel-graceful"
	c.mu.Unlock()

	// Server goroutine: accept the close stream and respond.
	closeReceived := make(chan string, 1)
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

		msg, err := proto.DecodeControlMessage(buf[:n])
		if err != nil || msg.CloseRequest == nil {
			return
		}

		closeReceived <- msg.CloseRequest.TunnelID

		resp := proto.NewCloseResponse(true)
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
	}()

	err := c.Close()
	assert.NoError(t, err)

	// Verify the server received the CloseRequest.
	select {
	case tunnelID := <-closeReceived:
		assert.Equal(t, "tunnel-graceful", tunnelID)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive CloseRequest during graceful shutdown")
	}
}
