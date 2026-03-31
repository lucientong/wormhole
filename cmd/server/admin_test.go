package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wormhole-tunnel/wormhole/pkg/proto"
)

func newTestServer() *Server {
	config := DefaultConfig()
	config.Domain = "test.example.com"
	s := &Server{
		config:  config,
		clients: make(map[string]*ClientSession),
		closeCh: make(chan struct{}),
		stats: ServerStats{
			StartTime: time.Now().Add(-1 * time.Hour), // 1 hour ago
		},
	}
	s.router = NewRouter(config.Domain)
	s.portAllocator = NewTCPPortAllocator(10000, 10100)
	return s
}

func TestAdminAPI_Health(t *testing.T) {
	server := newTestServer()
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))

	var resp HealthResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "healthy", resp.Status)
	assert.NotEmpty(t, resp.Uptime)
}

func TestAdminAPI_Stats(t *testing.T) {
	server := newTestServer()
	server.stats.ActiveClients = 5
	server.stats.TotalClients = 10
	server.stats.ActiveTunnels = 3
	server.stats.Requests = 100
	server.stats.BytesIn = 1024
	server.stats.BytesOut = 2048

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp StatsResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, uint64(5), resp.ActiveClients)
	assert.Equal(t, uint64(10), resp.TotalClients)
	assert.Equal(t, uint64(3), resp.ActiveTunnels)
	assert.Equal(t, uint64(100), resp.Requests)
	assert.Equal(t, uint64(1024), resp.BytesIn)
	assert.Equal(t, uint64(2048), resp.BytesOut)
	assert.Greater(t, resp.UptimeSeconds, int64(0))
}

func TestAdminAPI_Clients_Empty(t *testing.T) {
	server := newTestServer()
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var clients []ClientInfo
	err := json.Unmarshal(rec.Body.Bytes(), &clients)
	require.NoError(t, err)

	assert.Empty(t, clients)
}

func TestAdminAPI_Clients_WithClients(t *testing.T) {
	server := newTestServer()

	// Add test clients.
	now := time.Now()
	client1 := &ClientSession{
		ID:        "client-1",
		Subdomain: "app1",
		CreatedAt: now.Add(-1 * time.Hour),
		LastSeen:  now,
		BytesIn:   1000,
		BytesOut:  2000,
		Tunnels: []*TunnelInfo{
			{
				ID:        "tunnel-1",
				LocalPort: 8080,
				Protocol:  proto.ProtocolHTTP,
				PublicURL: "http://app1.test.example.com",
				CreatedAt: now,
			},
		},
	}
	client2 := &ClientSession{
		ID:        "client-2",
		Subdomain: "app2",
		CreatedAt: now.Add(-30 * time.Minute),
		LastSeen:  now,
		BytesIn:   500,
		BytesOut:  1500,
		Tunnels:   []*TunnelInfo{},
	}

	server.clients["client-1"] = client1
	server.clients["client-2"] = client2

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var clients []ClientInfo
	err := json.Unmarshal(rec.Body.Bytes(), &clients)
	require.NoError(t, err)

	assert.Len(t, clients, 2)

	// Find client-1.
	var found *ClientInfo
	for i := range clients {
		if clients[i].ID == "client-1" {
			found = &clients[i]
			break
		}
	}
	require.NotNil(t, found)

	assert.Equal(t, "client-1", found.ID)
	assert.Equal(t, "app1", found.Subdomain)
	assert.Equal(t, uint64(1000), found.BytesIn)
	assert.Equal(t, uint64(2000), found.BytesOut)
	assert.Len(t, found.Tunnels, 1)
	assert.Equal(t, "tunnel-1", found.Tunnels[0].ID)
	assert.Equal(t, "HTTP", found.Tunnels[0].Protocol)
}

func TestAdminAPI_Tunnels_Empty(t *testing.T) {
	server := newTestServer()
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/tunnels", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var tunnels []map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &tunnels)
	require.NoError(t, err)

	assert.Empty(t, tunnels)
}

func TestAdminAPI_Tunnels_WithTunnels(t *testing.T) {
	server := newTestServer()

	now := time.Now()
	client := &ClientSession{
		ID:        "client-1",
		Subdomain: "app1",
		Tunnels: []*TunnelInfo{
			{
				ID:        "tunnel-1",
				LocalPort: 8080,
				Protocol:  proto.ProtocolHTTP,
				PublicURL: "http://app1.test.example.com",
				CreatedAt: now,
			},
			{
				ID:        "tunnel-2",
				LocalPort: 3306,
				Protocol:  proto.ProtocolTCP,
				PublicURL: "",
				TCPPort:   10001,
				CreatedAt: now,
			},
		},
	}
	server.clients["client-1"] = client

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/tunnels", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var tunnels []map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &tunnels)
	require.NoError(t, err)

	assert.Len(t, tunnels, 2)

	// Check TCP tunnel.
	var tcpTunnel map[string]interface{}
	for _, t := range tunnels {
		if t["id"] == "tunnel-2" {
			tcpTunnel = t
			break
		}
	}
	require.NotNil(t, tcpTunnel)

	assert.Equal(t, "TCP", tcpTunnel["protocol"])
	assert.Equal(t, float64(10001), tcpTunnel["tcp_port"])
	assert.Equal(t, "client-1", tcpTunnel["client_id"])
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()

	data := map[string]interface{}{
		"key":   "value",
		"count": 42,
	}

	writeJSON(rec, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))

	var result map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &result)
	require.NoError(t, err)

	assert.Equal(t, "value", result["key"])
	assert.Equal(t, float64(42), result["count"])
}
