package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildClientWithTunnels returns a minimal Client pre-populated with active tunnels.
func buildClientWithTunnels(defs []ActiveTunnel) *Client {
	c := NewClient(DefaultConfig())
	for i := range defs {
		d := defs[i]
		c.relay.activeTunnels[d.Def.Name] = &d
	}
	return c
}

func TestListActiveTunnels_MultiTunnel(t *testing.T) {
	c := buildClientWithTunnels([]ActiveTunnel{
		{Def: TunnelDef{Name: "web", LocalPort: 3000, Protocol: protocolHTTP}, TunnelID: "tid-1", PublicURL: "https://abc.example.com"},
		{Def: TunnelDef{Name: "api", LocalPort: 8080, Protocol: protocolHTTP}, TunnelID: "tid-2", PublicURL: "https://def.example.com"},
	})

	list := c.ListActiveTunnels()
	assert.Len(t, list, 2)
}

func TestListActiveTunnels_SingleTunnelFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LocalPort = 5000
	cfg.LocalHost = "127.0.0.1"
	cfg.Protocol = protocolHTTP
	c := NewClient(cfg)
	c.relay.tunnelID = "single-tid"
	c.relay.publicURL = "https://xyz.example.com"

	list := c.ListActiveTunnels()
	require.Len(t, list, 1)
	assert.Equal(t, "single-tid", list[0].TunnelID)
	assert.Equal(t, "default", list[0].Def.Name)
}

func TestListActiveTunnels_Empty(t *testing.T) {
	c := NewClient(DefaultConfig())
	list := c.ListActiveTunnels()
	assert.Empty(t, list)
}

// ─── Control API (handler unit tests) ────────────────────────────────────────

func TestHandleCtrlTunnels_JSON(t *testing.T) {
	c := buildClientWithTunnels([]ActiveTunnel{
		{
			Def:       TunnelDef{Name: "web", LocalPort: 3000, LocalHost: "127.0.0.1", Protocol: protocolHTTP},
			TunnelID:  "tid-1",
			PublicURL: "https://abc.example.com",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/tunnels", nil)
	w := httptest.NewRecorder()
	c.handleCtrlTunnels(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var infos []TunnelInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &infos))
	require.Len(t, infos, 1)
	assert.Equal(t, "web", infos[0].Name)
	assert.Equal(t, "https://abc.example.com", infos[0].PublicURL)
	assert.Equal(t, 3000, infos[0].LocalPort)
}

func TestHandleCtrlTunnels_MethodNotAllowed(t *testing.T) {
	c := NewClient(DefaultConfig())

	req := httptest.NewRequest(http.MethodPut, "/tunnels", nil)
	w := httptest.NewRecorder()
	c.handleCtrlTunnels(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ─── Control API: create/delete (U1) ─────────────────────────────────────

func TestHandleCtrlCreateTunnel_InvalidBody(t *testing.T) {
	c := NewClient(DefaultConfig())

	req := httptest.NewRequest(http.MethodPost, "/tunnels", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	c.handleCtrlTunnels(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCtrlCreateTunnel_MissingName(t *testing.T) {
	c := NewClient(DefaultConfig())

	body, _ := json.Marshal(createTunnelRequest{LocalPort: 8080})
	req := httptest.NewRequest(http.MethodPost, "/tunnels", bytes.NewReader(body))
	w := httptest.NewRecorder()
	c.handleCtrlTunnels(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

func TestHandleCtrlCreateTunnel_RejectsUDP(t *testing.T) {
	c := NewClient(DefaultConfig())

	body, _ := json.Marshal(createTunnelRequest{Name: "db", LocalPort: 5432, Protocol: protocolUDP})
	req := httptest.NewRequest(http.MethodPost, "/tunnels", bytes.NewReader(body))
	w := httptest.NewRecorder()
	c.handleCtrlTunnels(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "UDP")
}

func TestHandleCtrlCreateTunnel_DuplicateName(t *testing.T) {
	c := buildClientWithTunnels([]ActiveTunnel{
		{Def: TunnelDef{Name: "web", LocalPort: 3000}, TunnelID: "tid-1"},
	})

	body, _ := json.Marshal(createTunnelRequest{Name: "web", LocalPort: 4000})
	req := httptest.NewRequest(http.MethodPost, "/tunnels", bytes.NewReader(body))
	w := httptest.NewRecorder()
	c.handleCtrlTunnels(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandleCtrlDeleteTunnel_NotFound(t *testing.T) {
	c := NewClient(DefaultConfig())

	req := httptest.NewRequest(http.MethodDelete, "/tunnels/missing", nil)
	req.SetPathValue("name", "missing")
	w := httptest.NewRecorder()
	c.handleCtrlDeleteTunnel(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestCreateTunnel_DuplicateName verifies CreateTunnel itself (not just
// the HTTP handler wrapper) rejects a name collision.
func TestCreateTunnel_DuplicateName(t *testing.T) {
	c := buildClientWithTunnels([]ActiveTunnel{
		{Def: TunnelDef{Name: "web", LocalPort: 3000}, TunnelID: "tid-1"},
	})

	_, err := c.CreateTunnel(context.Background(), TunnelDef{Name: "web", LocalPort: 4000})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestDeleteTunnel_NotFound verifies DeleteTunnel itself rejects an
// unknown tunnel name without touching the mux.
func TestDeleteTunnel_NotFound(t *testing.T) {
	c := NewClient(DefaultConfig())

	err := c.DeleteTunnel(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStartControlServer_BindsAndServes(t *testing.T) {
	c := buildClientWithTunnels([]ActiveTunnel{
		{Def: TunnelDef{Name: "test", LocalPort: 9999, Protocol: protocolHTTP}, TunnelID: "tid-test"},
	})

	// Port 0 should be treated as disabled (no-op).
	require.NoError(t, c.StartControlServer("127.0.0.1", 0))
	c.mu.Lock()
	noSrv := c.ctrlServer
	c.mu.Unlock()
	assert.Nil(t, noSrv, "port 0 should not start a server")

	// Bind to a free port.
	port := freeTCPPort(t)
	require.NoError(t, c.StartControlServer("127.0.0.1", port))

	// Poll until the server accepts connections (give it up to 500ms).
	var resp *http.Response
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		var err error
		resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/tunnels", port))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.NotNil(t, resp, "control server did not become ready in time")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// freeTCPPort allocates and immediately releases a free TCP port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
