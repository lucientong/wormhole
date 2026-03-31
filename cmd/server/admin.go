package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

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

	return mux
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
