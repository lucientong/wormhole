package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// TunnelInfo is the JSON representation of an active tunnel for the control API.
type TunnelInfo struct {
	Name      string `json:"name"`
	TunnelID  string `json:"tunnel_id"`
	PublicURL string `json:"public_url"`
	LocalPort int    `json:"local_port"`
	LocalHost string `json:"local_host"`
	Protocol  string `json:"protocol"`
	TCPPort   uint32 `json:"tcp_port,omitempty"`
}

// StartControlServer starts a lightweight HTTP control server that exposes
// the running client's tunnel state for use by `wormhole tunnels list`.
//
// The server binds to ctrlHost:ctrlPort. If ctrlPort is 0 this is a no-op.
func (c *Client) StartControlServer(ctrlHost string, ctrlPort int) error {
	if ctrlPort <= 0 {
		return nil
	}

	if ctrlHost == "" {
		ctrlHost = defaultLocalHost
	}

	addr := net.JoinHostPort(ctrlHost, fmt.Sprintf("%d", ctrlPort))
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnels", c.handleCtrlTunnels)
	// Go 1.22+ ServeMux method+wildcard pattern (U1): DELETE /tunnels/{name}.
	mux.HandleFunc("DELETE /tunnels/{name}", c.handleCtrlDeleteTunnel)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("start control server: %w", err)
	}

	c.mu.Lock()
	c.ctrlServer = srv
	c.mu.Unlock()

	go func() {
		log.Info().Str("addr", addr).Msg("Control server started")
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Warn().Err(err).Msg("Control server stopped")
		}
	}()

	return nil
}

// handleCtrlTunnels handles GET (list) and POST (create, U1) on /tunnels.
func (c *Client) handleCtrlTunnels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c.handleCtrlListTunnels(w, r)
	case http.MethodPost:
		c.handleCtrlCreateTunnel(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCtrlListTunnels returns the list of active tunnels as JSON.
func (c *Client) handleCtrlListTunnels(w http.ResponseWriter, _ *http.Request) {
	tunnels := c.ListActiveTunnels()
	infos := make([]TunnelInfo, 0, len(tunnels))
	for _, at := range tunnels {
		infos = append(infos, activeTunnelToInfo(&at))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(infos)
}

// createTunnelRequest is the JSON body accepted by POST /tunnels (U1),
// mirroring the fields of a YAML config file tunnel entry.
type createTunnelRequest struct {
	Name       string `json:"name"`
	LocalPort  int    `json:"local_port"`
	LocalHost  string `json:"local_host"`
	Protocol   string `json:"protocol"`
	Subdomain  string `json:"subdomain"`
	Hostname   string `json:"hostname"`
	PathPrefix string `json:"path_prefix"`
}

// handleCtrlCreateTunnel registers a new tunnel on the running client
// (U1: `wormhole tunnels create`), the imperative counterpart to the
// declarative config-file + SIGHUP reload workflow.
func (c *Client) handleCtrlCreateTunnel(w http.ResponseWriter, r *http.Request) {
	var req createTunnelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if err := ValidateProtocolString(req.Protocol); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	localHost := req.LocalHost
	if localHost == "" {
		localHost = defaultLocalHost
	}
	def := TunnelDef{
		Name:       req.Name,
		LocalPort:  req.LocalPort,
		LocalHost:  localHost,
		Protocol:   req.Protocol,
		Subdomain:  req.Subdomain,
		Hostname:   req.Hostname,
		PathPrefix: req.PathPrefix,
	}

	at, err := c.CreateTunnel(r.Context(), def)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(activeTunnelToInfo(at))
}

// handleCtrlDeleteTunnel closes and removes an active tunnel by name
// (U1: `wormhole tunnels delete`).
func (c *Client) handleCtrlDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := c.DeleteTunnel(r.Context(), name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// activeTunnelToInfo converts client-internal ActiveTunnel state into the
// wire-format TunnelInfo shared by the list/create control API responses.
func activeTunnelToInfo(at *ActiveTunnel) TunnelInfo {
	return TunnelInfo{
		Name:      at.Def.Name,
		TunnelID:  at.TunnelID,
		PublicURL: at.PublicURL,
		LocalPort: at.Def.LocalPort,
		LocalHost: at.Def.LocalHost,
		Protocol:  at.Def.Protocol,
		TCPPort:   at.TCPPort,
	}
}
