package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/rs/zerolog/log"
)

// AdminAPI provides the RESTful management API.
type AdminAPI struct {
	server *Server
}

// NewAdminAPI creates a new admin API handler.
func NewAdminAPI(server *Server) *AdminAPI {
	return &AdminAPI{server: server}
}

// Handler returns the http.Handler for the admin API.
func (a *AdminAPI) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/stats", a.requireAdminAuth(a.handleStats))
	mux.HandleFunc("/clients", a.requireAdminAuth(a.handleClients))
	mux.HandleFunc("/tunnels", a.requireAdminAuth(a.handleTunnels))
	mux.HandleFunc("/ratelimit", a.requireAdminAuth(a.handleRateLimit))
	mux.HandleFunc("/ratelimit/unblock", a.requireAdminAuth(a.handleUnblockIP))
	mux.HandleFunc("/teams", a.requireAdminAuth(a.handleTeams))
	mux.HandleFunc("/teams/", a.requireAdminAuth(a.handleTeamByName))
	mux.HandleFunc("/tokens/generate", a.requireAdminAuth(a.handleGenerateToken))
	mux.HandleFunc("/tokens/revoke", a.requireAdminAuth(a.handleRevokeToken))
	mux.HandleFunc("/tokens/refresh", a.requireAdminAuth(a.handleRefreshToken))

	// Wrap with request body size limiter to mitigate DoS via large payloads.
	return a.maxBodySize(mux, 1<<20) // 1 MB.
}

// maxBodySize wraps a handler to enforce a maximum request body size.
func (a *AdminAPI) maxBodySize(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// HealthResponse is the response for the health endpoint.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Uptime  string `json:"uptime"`
}

// StatsResponse is the response for the stats endpoint.
type StatsResponse struct {
	ActiveClients  uint64 `json:"active_clients"`
	TotalClients   uint64 `json:"total_clients"`
	ActiveTunnels  uint64 `json:"active_tunnels"`
	ActiveRoutes   int    `json:"active_routes"`
	Requests       uint64 `json:"requests"`
	BytesIn        uint64 `json:"bytes_in"`
	BytesOut       uint64 `json:"bytes_out"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	AllocatedPorts int    `json:"allocated_ports"`
}

// ClientInfo is the per-client info returned by the API.
type ClientInfo struct {
	ID         string       `json:"id"`
	Subdomain  string       `json:"subdomain"`
	RemoteAddr string       `json:"remote_addr"`
	CreatedAt  time.Time    `json:"created_at"`
	LastSeen   time.Time    `json:"last_seen"`
	BytesIn    uint64       `json:"bytes_in"`
	BytesOut   uint64       `json:"bytes_out"`
	Tunnels    []TunnelJSON `json:"tunnels"`
}

// TunnelJSON is the JSON representation of a tunnel.
type TunnelJSON struct {
	ID        string `json:"id"`
	LocalPort uint32 `json:"local_port"`
	Protocol  string `json:"protocol"`
	PublicURL string `json:"public_url"`
	TCPPort   uint32 `json:"tcp_port,omitempty"`
	CreatedAt string `json:"created_at"`
}

// handleHealth returns the server health status.
func (a *AdminAPI) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := HealthResponse{
		Status: "healthy",
		Uptime: time.Since(a.server.stats.StartTime).Round(time.Second).String(),
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleStats returns aggregated server statistics.
func (a *AdminAPI) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats := a.server.getStats()

	allocatedPorts := 0
	if a.server.portAllocator != nil {
		allocatedPorts = a.server.portAllocator.AllocatedPorts()
	}

	activeRoutes := 0
	if a.server.router != nil {
		activeRoutes = a.server.router.ActiveRoutes()
	}

	resp := StatsResponse{
		ActiveClients:  stats.ActiveClients,
		TotalClients:   stats.TotalClients,
		ActiveTunnels:  stats.ActiveTunnels,
		ActiveRoutes:   activeRoutes,
		Requests:       stats.Requests,
		BytesIn:        stats.BytesIn,
		BytesOut:       stats.BytesOut,
		UptimeSeconds:  int64(time.Since(stats.StartTime).Seconds()),
		AllocatedPorts: allocatedPorts,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleClients returns the list of connected clients.
func (a *AdminAPI) handleClients(w http.ResponseWriter, _ *http.Request) {
	a.server.clientLock.RLock()
	defer a.server.clientLock.RUnlock()

	clients := make([]ClientInfo, 0, len(a.server.clients))
	for _, client := range a.server.clients {
		client.mu.Lock()
		tunnels := make([]TunnelJSON, 0, len(client.Tunnels))
		for _, t := range client.Tunnels {
			tunnels = append(tunnels, TunnelJSON{
				ID:        t.ID,
				LocalPort: t.LocalPort,
				Protocol:  t.Protocol.String(),
				PublicURL: t.PublicURL,
				TCPPort:   t.TCPPort,
				CreatedAt: t.CreatedAt.Format(time.RFC3339),
			})
		}
		info := ClientInfo{
			ID:        client.ID,
			Subdomain: client.Subdomain,
			CreatedAt: client.CreatedAt,
			LastSeen:  client.LastSeen,
			BytesIn:   atomic.LoadUint64(&client.BytesIn),
			BytesOut:  atomic.LoadUint64(&client.BytesOut),
			Tunnels:   tunnels,
		}
		if client.Mux != nil {
			info.RemoteAddr = client.Mux.RemoteAddr().String()
		}
		client.mu.Unlock()

		clients = append(clients, info)
	}

	writeJSON(w, http.StatusOK, clients)
}

// handleTunnels returns all active tunnels across all clients.
func (a *AdminAPI) handleTunnels(w http.ResponseWriter, _ *http.Request) {
	a.server.clientLock.RLock()
	defer a.server.clientLock.RUnlock()

	var tunnels []map[string]interface{}
	for _, client := range a.server.clients {
		client.mu.Lock()
		for _, t := range client.Tunnels {
			tunnels = append(tunnels, map[string]interface{}{
				"id":         t.ID,
				"client_id":  client.ID,
				"subdomain":  client.Subdomain,
				"local_port": t.LocalPort,
				"protocol":   t.Protocol.String(),
				"public_url": t.PublicURL,
				"tcp_port":   t.TCPPort,
				"created_at": t.CreatedAt.Format(time.RFC3339),
			})
		}
		client.mu.Unlock()
	}

	if tunnels == nil {
		tunnels = make([]map[string]interface{}, 0)
	}

	writeJSON(w, http.StatusOK, tunnels)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

// ErrorResponse is the standard error response for the admin API.
type ErrorResponse struct {
	Error string `json:"error"`
}

// requireAdminAuth wraps a handler with admin token authentication.
// If AdminToken is not configured, it passes through without checking.
func (a *AdminAPI) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminToken := a.server.config.AdminToken
		if adminToken == "" {
			// No admin token configured — allow unrestricted access.
			next(w, r)
			return
		}

		// Check Authorization header: "Bearer <token>".
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "missing authorization header"})
			return
		}

		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid authorization format, expected: Bearer <token>"})
			return
		}

		token := strings.TrimPrefix(authHeader, bearerPrefix)
		if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "invalid admin token"})
			return
		}

		next(w, r)
	}
}

// RateLimitResponse is the response for the rate limit status endpoint.
type RateLimitResponse struct {
	Enabled    bool     `json:"enabled"`
	TrackedIPs int      `json:"tracked_ips"`
	BlockedIPs []string `json:"blocked_ips"`
}

// handleRateLimit returns the current rate limit status.
func (a *AdminAPI) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	rl := a.server.rateLimiter
	if rl == nil {
		writeJSON(w, http.StatusOK, RateLimitResponse{
			Enabled:    false,
			TrackedIPs: 0,
			BlockedIPs: []string{},
		})
		return
	}

	stats := rl.Stats()
	blocked := rl.GetBlockedIPs()
	if blocked == nil {
		blocked = []string{}
	}

	writeJSON(w, http.StatusOK, RateLimitResponse{
		Enabled:    true,
		TrackedIPs: stats.TrackedIPs,
		BlockedIPs: blocked,
	})
}

// UnblockRequest is the request body for unblocking an IP.
type UnblockRequest struct {
	IP string `json:"ip"`
}

// handleUnblockIP unblocks a specific IP address.
func (a *AdminAPI) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	rl := a.server.rateLimiter
	if rl == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "rate limiting is not enabled"})
		return
	}

	var req UnblockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ip is required"})
		return
	}

	rl.Unblock(req.IP)

	log.Info().Str("ip", req.IP).Msg("IP unblocked via admin API")

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "IP unblocked successfully",
		"ip":      req.IP,
	})
}

// TeamResponse is the response for team endpoints.
type TeamResponse struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Tokens    int    `json:"tokens"`
}

// CreateTeamRequest is the request body for creating a team.
type CreateTeamRequest struct {
	Name string `json:"name"`
}

// handleTeams handles GET /teams (list) and POST /teams (create).
func (a *AdminAPI) handleTeams(w http.ResponseWriter, r *http.Request) {
	if a.server.authenticator == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "authentication is not enabled"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		teams := a.server.authenticator.ListTeams()
		response := make([]TeamResponse, 0, len(teams))
		for _, t := range teams {
			response = append(response, TeamResponse{
				Name:      t.Name,
				CreatedAt: t.CreatedAt.Format(time.RFC3339),
				Tokens:    t.Tokens,
			})
		}
		writeJSON(w, http.StatusOK, response)

	case http.MethodPost:
		var req CreateTeamRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
			return
		}

		if err := a.server.authenticator.RegisterTeam(req.Name); err != nil {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}

		log.Info().Str("team", req.Name).Msg("Team created via admin API")

		writeJSON(w, http.StatusCreated, map[string]string{
			"message": "team created successfully",
			"name":    req.Name,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
	}
}

// handleTeamByName handles GET /teams/{name}.
func (a *AdminAPI) handleTeamByName(w http.ResponseWriter, r *http.Request) {
	if a.server.authenticator == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "authentication is not enabled"})
		return
	}

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	// Extract team name from path: /teams/{name}.
	path := strings.TrimPrefix(r.URL.Path, "/teams/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "team name is required"})
		return
	}

	team, err := a.server.authenticator.GetTeam(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, TeamResponse{
		Name:      team.Name,
		CreatedAt: team.CreatedAt.Format(time.RFC3339),
		Tokens:    team.Tokens,
	})
}

// GenerateTokenRequest is the request body for token generation.
type GenerateTokenRequest struct {
	Team string `json:"team"`
	Role string `json:"role"`
}

// GenerateTokenResponse is the response for token generation.
type GenerateTokenResponse struct {
	Token   string `json:"token"`
	Team    string `json:"team"`
	Role    string `json:"role"`
	Expires string `json:"expires,omitempty"`
}

// handleGenerateToken handles POST /tokens/generate.
func (a *AdminAPI) handleGenerateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	if a.server.authenticator == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "authentication is not enabled"})
		return
	}

	var req GenerateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.Team == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "team is required"})
		return
	}

	// Default to member role.
	role := auth.RoleMember
	if req.Role != "" {
		switch req.Role {
		case "admin":
			role = auth.RoleAdmin
		case "member":
			role = auth.RoleMember
		case "viewer":
			role = auth.RoleViewer
		default:
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid role, must be: admin, member, or viewer"})
			return
		}
	}

	token, err := a.server.authenticator.GenerateTeamToken(req.Team, role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate to get expiry.
	claims, _ := a.server.authenticator.ValidateToken(token)
	expires := ""
	if claims != nil && !claims.ExpiresAt.IsZero() {
		expires = claims.ExpiresAt.Format(time.RFC3339)
	}

	log.Info().Str("team", req.Team).Str("role", req.Role).Msg("Token generated via admin API")

	writeJSON(w, http.StatusOK, GenerateTokenResponse{
		Token:   token,
		Team:    req.Team,
		Role:    req.Role,
		Expires: expires,
	})
}

// RevokeTokenRequest is the request body for token revocation.
type RevokeTokenRequest struct {
	Token   string `json:"token,omitempty"`
	TokenID string `json:"token_id,omitempty"`
}

// handleRevokeToken handles POST /tokens/revoke.
func (a *AdminAPI) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	if a.server.authenticator == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "authentication is not enabled"})
		return
	}

	var req RevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.Token == "" && req.TokenID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "token or token_id is required"})
		return
	}

	var tokenID string

	if req.Token != "" {
		// Revoke by token string.
		if err := a.server.authenticator.RevokeTokenByString(req.Token); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		// Extract token ID for logging.
		claims, _ := a.server.authenticator.ValidateToken(req.Token)
		if claims != nil {
			tokenID = claims.TokenID
		}
	} else {
		// Revoke by token ID.
		if err := a.server.authenticator.RevokeToken(req.TokenID, time.Time{}); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		tokenID = req.TokenID
	}

	log.Info().Str("token_id", tokenID).Msg("Token revoked via admin API")

	writeJSON(w, http.StatusOK, map[string]string{
		"message":  "token revoked successfully",
		"token_id": tokenID,
	})
}

// RefreshTokenRequest is the request body for token refresh.
type RefreshTokenRequest struct {
	Token     string `json:"token"`
	RevokeOld bool   `json:"revoke_old"`
	ExtendBy  string `json:"extend_by,omitempty"`
}

// handleRefreshToken handles POST /tokens/refresh.
func (a *AdminAPI) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
		return
	}

	if a.server.authenticator == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "authentication is not enabled"})
		return
	}

	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "token is required"})
		return
	}

	var newToken string
	var err error

	switch {
	case req.ExtendBy != "":
		// Extend token expiry.
		duration, parseErr := time.ParseDuration(req.ExtendBy)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid extend_by duration"})
			return
		}
		newToken, err = a.server.authenticator.ExtendTokenExpiry(req.Token, duration)
	case req.RevokeOld:
		// Refresh and revoke old token.
		newToken, err = a.server.authenticator.RefreshAndRevokeToken(req.Token)
	default:
		// Simple refresh.
		newToken, err = a.server.authenticator.RefreshToken(req.Token)
	}

	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate new token to get claims.
	claims, _ := a.server.authenticator.ValidateToken(newToken)
	expires := ""
	if claims != nil && !claims.ExpiresAt.IsZero() {
		expires = claims.ExpiresAt.Format(time.RFC3339)
	}

	log.Info().
		Str("team", claims.TeamName).
		Bool("revoke_old", req.RevokeOld).
		Msg("Token refreshed via admin API")

	writeJSON(w, http.StatusOK, GenerateTokenResponse{
		Token:   newToken,
		Team:    claims.TeamName,
		Role:    string(claims.Role),
		Expires: expires,
	})
}
