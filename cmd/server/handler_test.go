package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

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
