package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer() *Server {
	config := DefaultConfig()
	config.Domain = "test.example.com"
	s := &Server{
		config:  config,
		clients: make(map[string]*ClientSession),
		closeCh: make(chan struct{}),
		stats: Stats{
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

func TestAdminAPI_RateLimit_Disabled(t *testing.T) {
	server := newTestServer()
	// rateLimiter is nil by default.
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/ratelimit", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RateLimitResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Enabled)
	assert.Equal(t, 0, resp.TrackedIPs)
	assert.Empty(t, resp.BlockedIPs)
}

func TestAdminAPI_RateLimit_Enabled(t *testing.T) {
	server := newTestServer()
	server.rateLimiter = auth.NewRateLimiter(auth.RateLimitConfig{
		MaxFailures:     3,
		Window:          5 * time.Minute,
		BlockDuration:   10 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	})
	defer server.rateLimiter.Close()

	// Simulate some failures to trigger blocking.
	for range 3 {
		server.rateLimiter.RecordFailure("192.168.1.100")
	}

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/ratelimit", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RateLimitResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Enabled)
	assert.Equal(t, 1, resp.TrackedIPs)
	assert.Contains(t, resp.BlockedIPs, "192.168.1.100")
}

func TestAdminAPI_RateLimit_MethodNotAllowed(t *testing.T) {
	server := newTestServer()
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodPost, "/ratelimit", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminAPI_UnblockIP_Success(t *testing.T) {
	server := newTestServer()
	server.rateLimiter = auth.NewRateLimiter(auth.RateLimitConfig{
		MaxFailures:     3,
		Window:          5 * time.Minute,
		BlockDuration:   10 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	})
	defer server.rateLimiter.Close()

	// Block an IP.
	for range 3 {
		server.rateLimiter.RecordFailure("10.0.0.1")
	}
	assert.True(t, server.rateLimiter.IsBlocked("10.0.0.1"))

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"ip":"10.0.0.1"}`)
	req := httptest.NewRequest(http.MethodPost, "/ratelimit/unblock", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "IP unblocked successfully", result["message"])
	assert.Equal(t, "10.0.0.1", result["ip"])

	// Verify IP is no longer blocked.
	assert.False(t, server.rateLimiter.IsBlocked("10.0.0.1"))
}

func TestAdminAPI_UnblockIP_RateLimitDisabled(t *testing.T) {
	server := newTestServer()
	// rateLimiter is nil.
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"ip":"10.0.0.1"}`)
	req := httptest.NewRequest(http.MethodPost, "/ratelimit/unblock", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "rate limiting is not enabled", resp.Error)
}

func TestAdminAPI_UnblockIP_InvalidBody(t *testing.T) {
	server := newTestServer()
	server.rateLimiter = auth.NewRateLimiter(auth.RateLimitConfig{
		MaxFailures:     3,
		Window:          5 * time.Minute,
		BlockDuration:   10 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	})
	defer server.rateLimiter.Close()

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`invalid json`)
	req := httptest.NewRequest(http.MethodPost, "/ratelimit/unblock", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid request body", resp.Error)
}

func TestAdminAPI_UnblockIP_MissingIP(t *testing.T) {
	server := newTestServer()
	server.rateLimiter = auth.NewRateLimiter(auth.RateLimitConfig{
		MaxFailures:     3,
		Window:          5 * time.Minute,
		BlockDuration:   10 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	})
	defer server.rateLimiter.Close()

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/ratelimit/unblock", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ip is required", resp.Error)
}

func TestAdminAPI_UnblockIP_MethodNotAllowed(t *testing.T) {
	server := newTestServer()
	server.rateLimiter = auth.NewRateLimiter(auth.RateLimitConfig{
		MaxFailures:     3,
		Window:          5 * time.Minute,
		BlockDuration:   10 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	})
	defer server.rateLimiter.Close()

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/ratelimit/unblock", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminAPI_RequireAdminAuth(t *testing.T) {
	server := newTestServer()
	server.config.AdminToken = "secret-admin-token"

	api := NewAdminAPI(server)
	handler := api.Handler()

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "no auth header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid format",
			authHeader: "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong token",
			authHeader: "Bearer wrong-token",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "valid token",
			authHeader: "Bearer secret-admin-token",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/stats", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"127.0.0.1:0", "127.0.0.1"},
		{"invalid-no-port", "invalid-no-port"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractIP(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func newTestServerWithAuth(t *testing.T) *Server {
	config := DefaultConfig()
	config.Domain = "test.example.com"
	config.RequireAuth = true
	config.AuthSecret = "test-secret-key-0123456789abcdef"

	authenticator, err := auth.New(auth.Config{
		Secret:      []byte(config.AuthSecret),
		TokenExpiry: 1 * time.Hour,
	})
	require.NoError(t, err)

	s := &Server{
		config:        config,
		clients:       make(map[string]*ClientSession),
		closeCh:       make(chan struct{}),
		authenticator: authenticator,
		stats: Stats{
			StartTime: time.Now().Add(-1 * time.Hour),
		},
	}
	s.router = NewRouter(config.Domain)
	s.portAllocator = NewTCPPortAllocator(10000, 10100)
	return s
}

func TestAdminAPI_Teams_List(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Register some teams.
	err := server.authenticator.RegisterTeam("team1")
	require.NoError(t, err)
	err = server.authenticator.RegisterTeam("team2")
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/teams", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var teams []TeamResponse
	err = json.Unmarshal(rec.Body.Bytes(), &teams)
	require.NoError(t, err)

	assert.Len(t, teams, 2)
}

func TestAdminAPI_Teams_Create(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"name":"new-team"}`)
	req := httptest.NewRequest(http.MethodPost, "/teams", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var result map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "team created successfully", result["message"])
	assert.Equal(t, "new-team", result["name"])

	// Verify team exists.
	_, err = server.authenticator.GetTeam("new-team")
	require.NoError(t, err)
}

func TestAdminAPI_Teams_Create_Duplicate(t *testing.T) {
	server := newTestServerWithAuth(t)

	err := server.authenticator.RegisterTeam("existing-team")
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"name":"existing-team"}`)
	req := httptest.NewRequest(http.MethodPost, "/teams", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestAdminAPI_Teams_Create_MissingName(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/teams", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminAPI_TeamByName(t *testing.T) {
	server := newTestServerWithAuth(t)

	err := server.authenticator.RegisterTeam("test-team")
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/teams/test-team", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var team TeamResponse
	err = json.Unmarshal(rec.Body.Bytes(), &team)
	require.NoError(t, err)
	assert.Equal(t, "test-team", team.Name)
}

func TestAdminAPI_TeamByName_NotFound(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/teams/nonexistent", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAdminAPI_GenerateToken(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"team":"dev-team","role":"member"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/generate", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp GenerateTokenResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, "dev-team", resp.Team)
	assert.Equal(t, "member", resp.Role)
	assert.NotEmpty(t, resp.Expires)

	// Verify token is valid.
	claims, err := server.authenticator.ValidateToken(resp.Token)
	require.NoError(t, err)
	assert.Equal(t, "dev-team", claims.TeamName)
}

func TestAdminAPI_GenerateToken_DefaultRole(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"team":"dev-team"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/generate", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp GenerateTokenResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Default role should be member.
	claims, err := server.authenticator.ValidateToken(resp.Token)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleMember, claims.Role)
}

func TestAdminAPI_GenerateToken_InvalidRole(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"team":"dev-team","role":"superuser"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/generate", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminAPI_GenerateToken_MissingTeam(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"role":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/generate", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminAPI_RevokeToken(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Generate a token first.
	token, err := server.authenticator.GenerateTeamToken("team1", auth.RoleMember)
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"token":"` + token + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify token is revoked.
	_, err = server.authenticator.ValidateToken(token)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestAdminAPI_RevokeToken_ByID(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Generate a token and get its ID.
	token, err := server.authenticator.GenerateTeamToken("team1", auth.RoleMember)
	require.NoError(t, err)

	claims, err := server.authenticator.ValidateToken(token)
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"token_id":"` + claims.TokenID + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify token is revoked.
	_, err = server.authenticator.ValidateToken(token)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)
}

func TestAdminAPI_RevokeToken_MissingTokenAndID(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminAPI_RefreshToken(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Generate a token.
	originalToken, err := server.authenticator.GenerateTeamToken("team1", auth.RoleMember)
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"token":"` + originalToken + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp GenerateTokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Token)
	assert.NotEqual(t, originalToken, resp.Token)
	assert.Equal(t, "team1", resp.Team)

	// Both tokens should be valid (old not revoked).
	_, err = server.authenticator.ValidateToken(originalToken)
	require.NoError(t, err)
	_, err = server.authenticator.ValidateToken(resp.Token)
	require.NoError(t, err)
}

func TestAdminAPI_RefreshToken_RevokeOld(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Generate a token.
	originalToken, err := server.authenticator.GenerateTeamToken("team1", auth.RoleMember)
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"token":"` + originalToken + `","revoke_old":true}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp GenerateTokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Old token should be revoked.
	_, err = server.authenticator.ValidateToken(originalToken)
	assert.ErrorIs(t, err, auth.ErrTokenRevoked)

	// New token should be valid.
	_, err = server.authenticator.ValidateToken(resp.Token)
	require.NoError(t, err)
}

func TestAdminAPI_RefreshToken_ExtendExpiry(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Generate a token.
	originalToken, err := server.authenticator.GenerateTeamToken("team1", auth.RoleMember)
	require.NoError(t, err)

	originalClaims, err := server.authenticator.ValidateToken(originalToken)
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"token":"` + originalToken + `","extend_by":"24h"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp GenerateTokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// New token should have extended expiry.
	newClaims, err := server.authenticator.ValidateToken(resp.Token)
	require.NoError(t, err)
	assert.True(t, newClaims.ExpiresAt.After(originalClaims.ExpiresAt))
}

func TestAdminAPI_RefreshToken_MissingToken(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminAPI_Teams_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	// DELETE is not a valid method for /teams.
	req := httptest.NewRequest(http.MethodDelete, "/teams", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "method not allowed", resp.Error)
}

func TestAdminAPI_Teams_Create_InvalidBody(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`not valid json`)
	req := httptest.NewRequest(http.MethodPost, "/teams", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid request body", resp.Error)
}

func TestAdminAPI_TeamByName_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodPost, "/teams/someteam", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "method not allowed", resp.Error)
}

func TestAdminAPI_TeamByName_EmptyName(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	// /teams/ with empty name after trimming prefix.
	req := httptest.NewRequest(http.MethodGet, "/teams/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "team name is required", resp.Error)
}

func TestAdminAPI_GenerateToken_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/tokens/generate", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "method not allowed", resp.Error)
}

func TestAdminAPI_GenerateToken_InvalidBody(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`invalid json`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/generate", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid request body", resp.Error)
}

func TestAdminAPI_GenerateToken_AllRoles(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	roles := []struct {
		role     string
		expected auth.Role
	}{
		{"admin", auth.RoleAdmin},
		{"viewer", auth.RoleViewer},
	}

	for _, tt := range roles {
		t.Run(tt.role, func(t *testing.T) {
			body := bytes.NewBufferString(`{"team":"role-team","role":"` + tt.role + `"}`)
			req := httptest.NewRequest(http.MethodPost, "/tokens/generate", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)

			var resp GenerateTokenResponse
			err := json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err)

			claims, err := server.authenticator.ValidateToken(resp.Token)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, claims.Role)
		})
	}
}

func TestAdminAPI_RevokeToken_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/tokens/revoke", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminAPI_RevokeToken_InvalidBody(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`bad json`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid request body", resp.Error)
}

func TestAdminAPI_RefreshToken_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/tokens/refresh", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminAPI_RefreshToken_InvalidBody(t *testing.T) {
	server := newTestServerWithAuth(t)
	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`bad json`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid request body", resp.Error)
}

func TestAdminAPI_RefreshToken_InvalidDuration(t *testing.T) {
	server := newTestServerWithAuth(t)

	// Generate a token to refresh.
	token, err := server.authenticator.GenerateTeamToken("team1", auth.RoleMember)
	require.NoError(t, err)

	api := NewAdminAPI(server)
	handler := api.Handler()

	body := bytes.NewBufferString(`{"token":"` + token + `","extend_by":"not-a-duration"}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid extend_by duration", resp.Error)
}

func TestAdminAPI_NoAuthenticator(t *testing.T) {
	server := newTestServer()
	// server.authenticator is nil.
	api := NewAdminAPI(server)
	handler := api.Handler()

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/teams", ""},
		{http.MethodPost, "/teams", `{"name":"team"}`},
		{http.MethodGet, "/teams/team", ""},
		{http.MethodPost, "/tokens/generate", `{"team":"t"}`},
		{http.MethodPost, "/tokens/revoke", `{"token":"t"}`},
		{http.MethodPost, "/tokens/refresh", `{"token":"t"}`},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = bytes.NewBuffer(nil)
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)

			var resp ErrorResponse
			err := json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, "authentication is not enabled", resp.Error)
		})
	}
}
