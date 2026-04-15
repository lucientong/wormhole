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

// handleCtrlTunnels returns the list of active tunnels as JSON.
func (c *Client) handleCtrlTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnels := c.ListActiveTunnels()
	infos := make([]TunnelInfo, 0, len(tunnels))
	for _, at := range tunnels {
		infos = append(infos, TunnelInfo{
			Name:      at.Def.Name,
			TunnelID:  at.TunnelID,
			PublicURL: at.PublicURL,
			LocalPort: at.Def.LocalPort,
			LocalHost: at.Def.LocalHost,
			Protocol:  at.Def.Protocol,
			TCPPort:   at.TCPPort,
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(infos)
}
