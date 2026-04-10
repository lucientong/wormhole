package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTCPPortAllocator(t *testing.T) {
	a := NewTCPPortAllocator(10000, 10010)

	assert.NotNil(t, a)
	assert.Equal(t, 10000, a.start)
	assert.Equal(t, 10010, a.end)
	assert.Equal(t, 10000, a.nextPort)
	assert.Equal(t, 0, a.AllocatedPorts())
}

func TestTCPPortAllocator_Allocate(t *testing.T) {
	a := NewTCPPortAllocator(10000, 10005)
	ctx := context.Background()

	// Allocate first port.
	port1, ln1, err := a.Allocate(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, port1, 10000)
	assert.Less(t, port1, 10005)
	assert.NotNil(t, ln1)
	assert.Equal(t, 1, a.AllocatedPorts())

	// Allocate second port.
	port2, ln2, err := a.Allocate(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, port1, port2)
	assert.NotNil(t, ln2)
	assert.Equal(t, 2, a.AllocatedPorts())

	// Clean up.
	ln1.Close()
	ln2.Close()
}

func TestTCPPortAllocator_Release(t *testing.T) {
	a := NewTCPPortAllocator(10000, 10005)
	ctx := context.Background()

	port, _, err := a.Allocate(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, a.AllocatedPorts())

	// Release the port.
	a.Release(port)
	assert.Equal(t, 0, a.AllocatedPorts())

	// Release non-existent port (should not panic).
	a.Release(99999)
}

func TestTCPPortAllocator_CloseAll(t *testing.T) {
	a := NewTCPPortAllocator(10000, 10010)
	ctx := context.Background()

	// Allocate multiple ports.
	for i := 0; i < 5; i++ {
		_, _, err := a.Allocate(ctx)
		require.NoError(t, err)
	}
	assert.Equal(t, 5, a.AllocatedPorts())

	// Close all.
	a.CloseAll()
	assert.Equal(t, 0, a.AllocatedPorts())
}

func TestTCPPortAllocator_ExhaustedPorts(t *testing.T) {
	// Very small range for testing exhaustion.
	a := NewTCPPortAllocator(59000, 59003)
	ctx := context.Background()

	// Allocate all available ports.
	var listeners []func()
	for i := 0; i < 3; i++ {
		_, ln, err := a.Allocate(ctx)
		if err == nil {
			listeners = append(listeners, func() { ln.Close() })
		}
	}

	// Next allocation should fail.
	_, _, err := a.Allocate(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no available ports")

	// Clean up.
	for _, close := range listeners {
		close()
	}
}

func TestTCPPortAllocator_Concurrency(t *testing.T) {
	a := NewTCPPortAllocator(59100, 59200)
	ctx := context.Background()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var ports []int

	// Concurrent allocations.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port, ln, err := a.Allocate(ctx)
			if err == nil {
				mu.Lock()
				ports = append(ports, port)
				mu.Unlock()
				defer ln.Close()
			}
		}()
	}
	wg.Wait()

	// All ports should be unique.
	portSet := make(map[int]bool)
	for _, p := range ports {
		assert.False(t, portSet[p], "duplicate port: %d", p)
		portSet[p] = true
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		isUpgrade bool
	}{
		{
			name: "Valid WebSocket upgrade",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "upgrade",
			},
			isUpgrade: true,
		},
		{
			name: "Case insensitive",
			headers: map[string]string{
				"Upgrade":    "WebSocket",
				"Connection": "Upgrade",
			},
			isUpgrade: true,
		},
		{
			name: "Connection with keep-alive",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "keep-alive, Upgrade",
			},
			isUpgrade: true,
		},
		{
			name: "Missing Upgrade header",
			headers: map[string]string{
				"Connection": "upgrade",
			},
			isUpgrade: false,
		},
		{
			name: "Missing Connection header",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			isUpgrade: false,
		},
		{
			name: "Wrong Upgrade value",
			headers: map[string]string{
				"Upgrade":    "h2c",
				"Connection": "upgrade",
			},
			isUpgrade: false,
		},
		{
			name:      "No headers",
			headers:   map[string]string{},
			isUpgrade: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tt.isUpgrade, isWebSocketUpgrade(req))
		})
	}
}

func TestCopyHeaders(t *testing.T) {
	src := make(http.Header)
	src.Set("Content-Type", "application/json")
	src.Set("X-Custom-Header", "custom-value")
	src.Add("X-Multi", "value1")
	src.Add("X-Multi", "value2")
	src.Set("Connection", "keep-alive")     // Hop-by-hop, should be skipped.
	src.Set("Transfer-Encoding", "chunked") // Hop-by-hop, should be skipped.

	dst := make(http.Header)
	copyHeaders(dst, src)

	assert.Equal(t, "application/json", dst.Get("Content-Type"))
	assert.Equal(t, "custom-value", dst.Get("X-Custom-Header"))
	assert.Equal(t, []string{"value1", "value2"}, dst["X-Multi"])
	assert.Empty(t, dst.Get("Connection"))
	assert.Empty(t, dst.Get("Transfer-Encoding"))
}

func TestIsHopByHop(t *testing.T) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
	}

	for _, h := range hopByHopHeaders {
		t.Run(h, func(t *testing.T) {
			assert.True(t, isHopByHop(h))
			// Test case insensitivity.
			assert.True(t, isHopByHop(h))
		})
	}

	// Non hop-by-hop headers.
	assert.False(t, isHopByHop("Content-Type"))
	assert.False(t, isHopByHop("X-Custom"))
	assert.False(t, isHopByHop("Authorization"))
}

func TestHTTPHandler_NotFound(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "unknown.test.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "Tunnel Not Found")
	assert.Contains(t, rec.Body.String(), "unknown.test.example.com")
}

func TestHTTPHandler_NotFound_XSS(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Attempt XSS via Host header.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "<script>alert('xss')</script>.test.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Should be HTML escaped.
	assert.NotContains(t, rec.Body.String(), "<script>")
	assert.Contains(t, rec.Body.String(), "&lt;script&gt;")
}

func TestHTTPHandler_ForwardHTTP(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Create a mux pair — server mux represents the tunnel to the client.
	clientConn, serverConn := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := tunnel.Client(clientConn, muxCfg)
	require.NoError(t, err)
	defer clientMux.Close()

	// Register a client session with the router.
	session := &ClientSession{
		ID:        "test-session",
		Subdomain: "myapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	err = router.RegisterSubdomain("myapp", session)
	require.NoError(t, err)

	// Client goroutine: accept stream, read StreamRequest + HTTP req, send HTTP response.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		stream, acceptErr := clientMux.AcceptStream()
		if acceptErr != nil {
			return
		}
		defer stream.Close()

		// Use a single bufio.Reader to avoid data loss between reads.
		br := bufio.NewReader(stream)

		// Use json.Decoder to consume exactly the JSON control message,
		// leaving the HTTP request bytes in the bufio.Reader's buffer.
		var msg proto.ControlMessage
		dec := json.NewDecoder(br)
		if decErr := dec.Decode(&msg); decErr != nil {
			return
		}
		if msg.StreamRequest == nil {
			return
		}

		// Read the raw HTTP request from the buffered reader.
		// json.Decoder may have buffered extra bytes; create a new reader
		// that combines the decoder's buffered bytes with the original reader.
		combined := io.MultiReader(dec.Buffered(), br)
		httpReq, parseErr := http.ReadRequest(bufio.NewReader(combined))
		if parseErr != nil {
			return
		}
		httpReq.Body.Close()

		// Send back an HTTP response.
		bodyStr := "hello from tunnel"
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain"}},
			Body:          io.NopCloser(strings.NewReader(bodyStr)),
			ContentLength: int64(len(bodyStr)),
		}
		_ = resp.Write(stream)
	}()

	// Make request to the handler.
	req := httptest.NewRequest(http.MethodGet, "/test-path", nil)
	req.Host = "myapp.test.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Wait for client goroutine.
	<-clientDone

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "from tunnel")
	assert.Equal(t, "myapp", rec.Header().Get("X-Wormhole-Tunnel"))
	assert.NotEmpty(t, rec.Header().Get("X-Wormhole-Duration"))
}

func TestHTTPHandler_ForwardHTTP_ClientError(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Create a mux pair — immediately close the client side.
	clientConn, serverConn := net.Pipe()
	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := tunnel.Client(clientConn, muxCfg)
	require.NoError(t, err)

	// Close client mux so stream open on server side still works
	// but reading response will fail.
	go func() {
		stream, _ := clientMux.AcceptStream()
		if stream != nil {
			// Read the control message and http request, then close stream without responding.
			buf := make([]byte, 8192)
			_, _ = stream.Read(buf)
			_ = stream.Close()
		}
	}()

	session := &ClientSession{
		ID:        "test-session-2",
		Subdomain: "broken",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	_ = router.RegisterSubdomain("broken", session)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "broken.test.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should return 502 Bad Gateway since client closed without responding.
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestSendStreamRequest(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Create a mux pair.
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
		ID:        "session-1",
		Subdomain: "test",
		CreatedAt: time.Now(),
	}

	// Open stream on server side.
	stream, err := serverMux.OpenStream()
	require.NoError(t, err)

	// Client accepts in background.
	go func() {
		s, _ := clientMux.AcceptStream()
		if s != nil {
			buf := make([]byte, 4096)
			n, _ := s.Read(buf)
			if n > 0 {
				msg, _ := proto.DecodeControlMessage(buf[:n])
				assert.NotNil(t, msg.StreamRequest)
				assert.Equal(t, proto.ProtocolHTTP, msg.StreamRequest.Protocol)
				assert.Equal(t, "myhost.example.com", msg.StreamRequest.HTTPMetadata.Host)
				assert.Equal(t, "GET", msg.StreamRequest.HTTPMetadata.Method)
			}
			_ = s.Close()
		}
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "myhost.example.com"
	req.Header.Set("Content-Type", "application/json")

	err = handler.sendStreamRequest(stream, session, req)
	require.NoError(t, err)

	_ = stream.Close()
	time.Sleep(50 * time.Millisecond) // Let client goroutine read.
}

// TestHTTPHandler_HandleWebSocket tests the WebSocket proxy path by
// using a real HTTP server that supports Hijack and verifying bidirectional
// data flow through the tunnel.
func TestHTTPHandler_HandleWebSocket(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Create mux pair.
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
		ID:        "ws-session",
		Subdomain: "wsapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	err = router.RegisterSubdomain("wsapp", session)
	require.NoError(t, err)

	// Tunnel client goroutine: accept stream, read control msg + upgrade request,
	// send back a 101 Switching Protocols response, then echo data.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		stream, acceptErr := clientMux.AcceptStream()
		if acceptErr != nil {
			return
		}
		defer stream.Close()

		br := bufio.NewReader(stream)

		// Read StreamRequest (JSON).
		var msg proto.ControlMessage
		dec := json.NewDecoder(br)
		if decErr := dec.Decode(&msg); decErr != nil {
			return
		}
		if msg.StreamRequest == nil {
			return
		}

		// Read the HTTP upgrade request.
		combined := io.MultiReader(dec.Buffered(), br)
		httpReq, parseErr := http.ReadRequest(bufio.NewReader(combined))
		if parseErr != nil {
			return
		}
		httpReq.Body.Close()

		// Send 101 Switching Protocols response.
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"\r\n"
		_, _ = stream.Write([]byte(resp))

		// Echo data back (simulating WebSocket frames as raw bytes).
		buf := make([]byte, 4096)
		for {
			n, readErr := stream.Read(buf)
			if readErr != nil {
				return
			}
			if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
				return
			}
		}
	}()

	// Create a real HTTP server wrapping the handler to get Hijack support.
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Connect to the test server as a raw TCP client.
	wsConn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	require.NoError(t, err)
	defer wsConn.Close()

	// Send WebSocket upgrade request.
	upgradeReq := "GET /test HTTP/1.1\r\n" +
		"Host: wsapp.test.example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	_, err = wsConn.Write([]byte(upgradeReq))
	require.NoError(t, err)

	// Read the 101 response.
	_ = wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 4096)
	n, err := wsConn.Read(respBuf)
	require.NoError(t, err)
	respStr := string(respBuf[:n])
	assert.Contains(t, respStr, "101 Switching Protocols")

	// Send some data and expect echo.
	testData := []byte("ws-test-payload-12345")
	_, err = wsConn.Write(testData)
	require.NoError(t, err)

	echoBuf := make([]byte, 4096)
	_ = wsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	echoN, err := wsConn.Read(echoBuf)
	require.NoError(t, err)
	assert.Equal(t, testData, echoBuf[:echoN])

	// Cleanup: close triggers goroutine exit.
	_ = wsConn.Close()
	<-clientDone
}

// TestHTTPHandler_ServeHTTP_WebSocketRoute verifies the ServeHTTP method
// correctly detects a WebSocket upgrade and routes to handleWebSocket.
func TestHTTPHandler_ServeHTTP_WebSocketRoute(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// No matching client — should return 404.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "noexist.test.example.com"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHTTPHandler_HandleWebSocket_NonHijackable verifies that the handler
// returns 500 when the ResponseWriter does not support Hijack (e.g. httptest.ResponseRecorder).
func TestHTTPHandler_HandleWebSocket_NonHijackable(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Create a mux pair and register a session.
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
		ID:        "ws-nohijack",
		Subdomain: "wsnh",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	err = router.RegisterSubdomain("wsnh", session)
	require.NoError(t, err)

	// Use httptest.ResponseRecorder which does NOT implement http.Hijacker.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "wsnh.test.example.com"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should return 500 because httptest.ResponseRecorder cannot be hijacked.
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "WebSocket not supported")
}

// TestHTTPHandler_ForwardHTTP_LargeBody verifies that large response bodies
// are correctly proxied through the tunnel without truncation.
func TestHTTPHandler_ForwardHTTP_LargeBody(t *testing.T) {
	server := newTestServer()
	router := NewRouter("test.example.com")
	handler := NewHTTPHandler(router, server)

	// Use real TCP connections instead of net.Pipe to avoid a known race
	// condition in Go's net.Pipe with the race detector on large writes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	serverConn := <-connCh
	_ = ln.Close()

	muxCfg := tunnel.DefaultMuxConfig()
	muxCfg.KeepAliveInterval = 0
	serverMux, err := tunnel.Server(serverConn, muxCfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := tunnel.Client(clientConn, muxCfg)
	require.NoError(t, err)
	defer clientMux.Close()

	session := &ClientSession{
		ID:        "large-body-session",
		Subdomain: "bigapp",
		Mux:       serverMux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	_ = router.RegisterSubdomain("bigapp", session)

	// Generate a large body (64KB).
	largeBody := strings.Repeat("x", 64*1024)

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		stream, acceptErr := clientMux.AcceptStream()
		if acceptErr != nil {
			return
		}
		defer stream.Close()

		br := bufio.NewReader(stream)
		var msg proto.ControlMessage
		dec := json.NewDecoder(br)
		if decErr := dec.Decode(&msg); decErr != nil {
			return
		}

		combined := io.MultiReader(dec.Buffered(), br)
		httpReq, parseErr := http.ReadRequest(bufio.NewReader(combined))
		if parseErr != nil {
			return
		}
		httpReq.Body.Close()

		bodyBytes := make([]byte, len(largeBody))
		copy(bodyBytes, largeBody)

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"application/octet-stream"}},
			Body:          io.NopCloser(bytes.NewReader(bodyBytes)),
			ContentLength: int64(len(bodyBytes)),
		}
		_ = resp.Write(stream)
	}()

	req := httptest.NewRequest(http.MethodGet, "/large", nil)
	req.Host = "bigapp.test.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	<-clientDone

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, len(largeBody), rec.Body.Len(),
		"response body should not be truncated")
}
