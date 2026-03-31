package inspector

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Handler provides HTTP handlers for the inspector API.
type Handler struct {
	inspector *Inspector
	hub       *WSHub
}

// NewHandler creates a new handler for the inspector.
func NewHandler(inspector *Inspector) *Handler {
	return &Handler{
		inspector: inspector,
		hub:       NewWSHub(inspector),
	}
}

// Close closes the handler and its WebSocket hub.
func (h *Handler) Close() {
	if h.hub != nil {
		h.hub.Close()
	}
}

// RegisterRoutes registers the inspector routes on a ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/inspector/records", h.handleRecords)
	mux.HandleFunc("/api/inspector/records/", h.handleRecordDetail)
	mux.HandleFunc("/api/inspector/stats", h.handleStats)
	mux.HandleFunc("/api/inspector/clear", h.handleClear)
	mux.HandleFunc("/api/inspector/toggle", h.handleToggle)
	mux.HandleFunc("/api/inspector/ws", h.hub.HandleWebSocket)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := r.URL.Path

	switch {
	case path == "/api/inspector/records" || path == "/api/inspector/records/":
		h.handleRecords(w, r)
	case strings.HasPrefix(path, "/api/inspector/records/"):
		h.handleRecordDetail(w, r)
	case path == "/api/inspector/stats":
		h.handleStats(w, r)
	case path == "/api/inspector/clear":
		h.handleClear(w, r)
	case path == "/api/inspector/toggle":
		h.handleToggle(w, r)
	case path == "/api/inspector/ws":
		h.hub.HandleWebSocket(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleRecords handles GET /api/inspector/records.
func (h *Handler) handleRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters.
	limit := parseIntParam(r, "limit", 100)
	offset := parseIntParam(r, "offset", 0)
	detail := r.URL.Query().Get("detail") == "true"

	if detail {
		records := h.inspector.Records(limit, offset)
		writeJSON(w, records)
	} else {
		summaries := h.inspector.RecordSummaries(limit, offset)
		writeJSON(w, summaries)
	}
}

// handleRecordDetail handles GET /api/inspector/records/{id}.
func (h *Handler) handleRecordDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from path.
	id := strings.TrimPrefix(r.URL.Path, "/api/inspector/records/")
	if id == "" {
		http.Error(w, "Record ID required", http.StatusBadRequest)
		return
	}

	record := h.inspector.Get(id)
	if record == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	writeJSON(w, record)
}

// handleStats handles GET /api/inspector/stats.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := struct {
		Count     int  `json:"count"`
		Capacity  int  `json:"capacity"`
		Enabled   bool `json:"enabled"`
		WSClients int  `json:"wsClients"`
	}{
		Count:     h.inspector.Count(),
		Capacity:  h.inspector.storage.Capacity(),
		Enabled:   h.inspector.IsEnabled(),
		WSClients: h.hub.ClientCount(),
	}

	writeJSON(w, stats)
}

// handleClear handles POST /api/inspector/clear.
func (h *Handler) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.inspector.Clear()
	h.hub.broadcast(WSMessage{Type: MsgTypeClear})

	writeJSON(w, map[string]bool{"success": true})
}

// handleToggle handles POST /api/inspector/toggle.
func (h *Handler) handleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Toggle capture state.
	enabled := !h.inspector.IsEnabled()
	h.inspector.SetEnabled(enabled)

	writeJSON(w, map[string]bool{"enabled": enabled})
}

// parseIntParam parses an integer query parameter.
func parseIntParam(r *http.Request, name string, defaultVal int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// writeJSON writes a JSON response with 200 OK status.
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}
