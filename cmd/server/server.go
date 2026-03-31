package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wormhole-tunnel/wormhole/pkg/proto"
	"github.com/wormhole-tunnel/wormhole/pkg/tunnel"
)

// Server is the wormhole server.
type Server struct {
	config Config

	// Listeners
	tunnelListener net.Listener
	httpListener   net.Listener
	adminListener  net.Listener

	// Client management
	clients    map[string]*ClientSession
	clientLock sync.RWMutex

	// Tunnel routing
	routes     map[string]*ClientSession // subdomain -> client
	routesLock sync.RWMutex

	// TCP port allocation
	tcpPorts     map[int]*ClientSession
	tcpPortsLock sync.Mutex
	nextTCPPort  int

	// Stats
	stats ServerStats

	// Shutdown
	closed   uint32
	closeCh  chan struct{}
	closeWg  sync.WaitGroup
}

// ClientSession represents a connected client.
type ClientSession struct {
	ID        string
	Subdomain string
	Mux       *tunnel.Mux
	Tunnels   []*TunnelInfo
	CreatedAt time.Time
	LastSeen  time.Time
	BytesIn   uint64
	BytesOut  uint64
	mu        sync.Mutex
}

// TunnelInfo contains information about a tunnel.
type TunnelInfo struct {
	ID        string
	LocalPort uint32
	Protocol  proto.Protocol
	PublicURL string
	TCPPort   uint32
	CreatedAt time.Time
}

// ServerStats contains server statistics.
type ServerStats struct {
	ActiveClients uint64
	TotalClients  uint64
	ActiveTunnels uint64
	BytesIn       uint64
	BytesOut      uint64
	Requests      uint64
	StartTime     time.Time
}

// NewServer creates a new server instance.
func NewServer(config Config) *Server {
	return &Server{
		config:      config,
		clients:     make(map[string]*ClientSession),
		routes:      make(map[string]*ClientSession),
		tcpPorts:    make(map[int]*ClientSession),
		nextTCPPort: config.TCPPortRangeStart,
		closeCh:     make(chan struct{}),
		stats: ServerStats{
			StartTime: time.Now(),
		},
	}
}

// Start starts the server.
func (s *Server) Start(ctx context.Context) error {
	log.Info().
		Str("tunnel_addr", s.config.ListenAddr).
		Str("http_addr", s.config.HTTPAddr).
		Str("admin_addr", s.config.AdminAddr).
		Msg("Starting Wormhole server")

	// Start tunnel listener
	tunnelLn, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen tunnel: %w", err)
	}
	s.tunnelListener = tunnelLn

	// Start HTTP listener
	httpLn, err := net.Listen("tcp", s.config.HTTPAddr)
	if err != nil {
		tunnelLn.Close()
		return fmt.Errorf("listen http: %w", err)
	}
	s.httpListener = httpLn

	// Start admin listener
	adminLn, err := net.Listen("tcp", s.config.AdminAddr)
	if err != nil {
		tunnelLn.Close()
		httpLn.Close()
		return fmt.Errorf("listen admin: %w", err)
	}
	s.adminListener = adminLn

	// Start accept loops
	s.closeWg.Add(3)
	go s.acceptTunnelLoop()
	go s.serveHTTP()
	go s.serveAdmin()

	log.Info().Msg("Server started successfully")

	// Wait for shutdown
	<-ctx.Done()
	return s.Shutdown()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}

	log.Info().Msg("Shutting down server...")
	close(s.closeCh)

	// Close listeners
	if s.tunnelListener != nil {
		s.tunnelListener.Close()
	}
	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.adminListener != nil {
		s.adminListener.Close()
	}

	// Close all clients
	s.clientLock.Lock()
	for _, client := range s.clients {
		client.Mux.Close()
	}
	s.clientLock.Unlock()

	s.closeWg.Wait()
	log.Info().Msg("Server shutdown complete")
	return nil
}

// acceptTunnelLoop accepts new client connections.
func (s *Server) acceptTunnelLoop() {
	defer s.closeWg.Done()

	for {
		conn, err := s.tunnelListener.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			log.Error().Err(err).Msg("Accept tunnel connection failed")
			continue
		}

		go s.handleClient(conn)
	}
}

// handleClient handles a new client connection.
func (s *Server) handleClient(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Info().Str("remote", remoteAddr).Msg("New client connection")

	// Create multiplexer
	mux, err := tunnel.Server(conn, s.config.MuxConfig)
	if err != nil {
		log.Error().Err(err).Str("remote", remoteAddr).Msg("Failed to create mux")
		conn.Close()
		return
	}

	// Generate session ID and subdomain
	sessionID := generateID()
	subdomain := generateSubdomain()

	// Create client session
	client := &ClientSession{
		ID:        sessionID,
		Subdomain: subdomain,
		Mux:       mux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Register client
	s.clientLock.Lock()
	s.clients[sessionID] = client
	s.clientLock.Unlock()

	s.routesLock.Lock()
	s.routes[subdomain] = client
	s.routesLock.Unlock()

	atomic.AddUint64(&s.stats.ActiveClients, 1)
	atomic.AddUint64(&s.stats.TotalClients, 1)

	log.Info().
		Str("session_id", sessionID).
		Str("subdomain", subdomain).
		Str("remote", remoteAddr).
		Msg("Client registered")

	// Handle client streams
	s.handleClientStreams(client)

	// Client disconnected
	s.removeClient(client)
	log.Info().
		Str("session_id", sessionID).
		Str("subdomain", subdomain).
		Msg("Client disconnected")
}

// handleClientStreams handles streams from a client.
func (s *Server) handleClientStreams(client *ClientSession) {
	for {
		stream, err := client.Mux.AcceptStream()
		if err != nil {
			if !client.Mux.IsClosed() {
				log.Error().Err(err).Str("client", client.ID).Msg("Accept stream failed")
			}
			return
		}

		go s.handleClientStream(client, stream)
	}
}

// handleClientStream handles a single stream from a client.
func (s *Server) handleClientStream(client *ClientSession, stream *tunnel.Stream) {
	defer stream.Close()

	// Read control message
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		log.Error().Err(err).Str("client", client.ID).Msg("Read control message failed")
		return
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		log.Error().Err(err).Str("client", client.ID).Msg("Decode control message failed")
		return
	}

	// Handle message
	switch msg.Type {
	case proto.MessageTypeRegisterRequest:
		s.handleRegister(client, stream, msg.RegisterRequest)
	case proto.MessageTypePingRequest:
		s.handlePing(client, stream, msg.PingRequest)
	default:
		log.Warn().Int("type", int(msg.Type)).Msg("Unknown message type")
	}
}

// handleRegister handles a tunnel registration request.
func (s *Server) handleRegister(client *ClientSession, stream *tunnel.Stream, req *proto.RegisterRequest) {
	tunnelID := generateID()
	publicURL := fmt.Sprintf("http://%s.%s", client.Subdomain, s.config.Domain)

	tunnelInfo := &TunnelInfo{
		ID:        tunnelID,
		LocalPort: req.LocalPort,
		Protocol:  req.Protocol,
		PublicURL: publicURL,
		CreatedAt: time.Now(),
	}

	client.mu.Lock()
	client.Tunnels = append(client.Tunnels, tunnelInfo)
	client.mu.Unlock()

	atomic.AddUint64(&s.stats.ActiveTunnels, 1)

	// Send response
	resp := proto.NewRegisterResponse(true, "", tunnelID, publicURL, 0)
	data, _ := resp.Encode()
	stream.Write(data)

	log.Info().
		Str("tunnel_id", tunnelID).
		Str("public_url", publicURL).
		Uint32("local_port", req.LocalPort).
		Msg("Tunnel registered")
}

// handlePing handles a ping request.
func (s *Server) handlePing(client *ClientSession, stream *tunnel.Stream, req *proto.PingRequest) {
	client.mu.Lock()
	client.LastSeen = time.Now()
	client.mu.Unlock()

	resp := proto.NewPingResponse(req.PingID)
	data, _ := resp.Encode()
	stream.Write(data)
}

// serveHTTP serves HTTP requests.
func (s *Server) serveHTTP() {
	defer s.closeWg.Done()

	handler := http.HandlerFunc(s.httpHandler)
	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	if err := server.Serve(s.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("HTTP server error")
	}
}

// httpHandler handles HTTP requests and routes them to the appropriate client.
func (s *Server) httpHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	subdomain := extractSubdomain(host, s.config.Domain)

	if subdomain == "" {
		http.Error(w, "No tunnel found for this host", http.StatusNotFound)
		return
	}

	// Find client
	s.routesLock.RLock()
	client := s.routes[subdomain]
	s.routesLock.RUnlock()

	if client == nil {
		http.Error(w, "Tunnel not found", http.StatusNotFound)
		return
	}

	// Forward request to client
	if err := s.forwardHTTP(client, w, r); err != nil {
		log.Error().Err(err).Str("subdomain", subdomain).Msg("Forward HTTP failed")
		http.Error(w, "Tunnel error", http.StatusBadGateway)
	}

	atomic.AddUint64(&s.stats.Requests, 1)
}

// forwardHTTP forwards an HTTP request to the client.
func (s *Server) forwardHTTP(client *ClientSession, w http.ResponseWriter, r *http.Request) error {
	// Open stream to client
	stream, err := client.Mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Send stream request
	streamReq := proto.NewStreamRequest("", generateID(), r.RemoteAddr, proto.ProtocolHTTP)
	streamReq.StreamRequest.HTTPMetadata = &proto.HTTPMetadata{
		Method:        r.Method,
		URI:           r.RequestURI,
		Host:          r.Host,
		ContentType:   r.Header.Get("Content-Type"),
		ContentLength: r.ContentLength,
	}
	data, _ := streamReq.Encode()
	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("write stream request: %w", err)
	}

	// Write HTTP request headers
	if err := r.Write(stream); err != nil {
		return fmt.Errorf("write http request: %w", err)
	}

	// Read response
	buf := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			break
		}
		w.Write(buf[:n])
	}

	return nil
}

// serveAdmin serves the admin API.
func (s *Server) serveAdmin() {
	defer s.closeWg.Done()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.adminHealth)
	mux.HandleFunc("/stats", s.adminStats)
	mux.HandleFunc("/clients", s.adminClients)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.Serve(s.adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("Admin server error")
	}
}

// adminHealth returns health status.
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

// adminStats returns server statistics.
func (s *Server) adminStats(w http.ResponseWriter, r *http.Request) {
	stats := s.getStats()
	fmt.Fprintf(w, `{"active_clients":%d,"total_clients":%d,"active_tunnels":%d,"requests":%d,"uptime_seconds":%d}`,
		stats.ActiveClients,
		stats.TotalClients,
		stats.ActiveTunnels,
		stats.Requests,
		int64(time.Since(stats.StartTime).Seconds()))
}

// adminClients returns the list of connected clients.
func (s *Server) adminClients(w http.ResponseWriter, r *http.Request) {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()

	w.Write([]byte("["))
	first := true
	for _, client := range s.clients {
		if !first {
			w.Write([]byte(","))
		}
		first = false
		fmt.Fprintf(w, `{"id":"%s","subdomain":"%s","created_at":"%s"}`,
			client.ID, client.Subdomain, client.CreatedAt.Format(time.RFC3339))
	}
	w.Write([]byte("]"))
}

// removeClient removes a client from the server.
func (s *Server) removeClient(client *ClientSession) {
	s.clientLock.Lock()
	delete(s.clients, client.ID)
	s.clientLock.Unlock()

	s.routesLock.Lock()
	delete(s.routes, client.Subdomain)
	s.routesLock.Unlock()

	atomic.AddUint64(&s.stats.ActiveClients, ^uint64(0)) // Decrement

	client.Mux.Close()
}

// getStats returns server statistics.
func (s *Server) getStats() ServerStats {
	return ServerStats{
		ActiveClients: atomic.LoadUint64(&s.stats.ActiveClients),
		TotalClients:  atomic.LoadUint64(&s.stats.TotalClients),
		ActiveTunnels: atomic.LoadUint64(&s.stats.ActiveTunnels),
		BytesIn:       atomic.LoadUint64(&s.stats.BytesIn),
		BytesOut:      atomic.LoadUint64(&s.stats.BytesOut),
		Requests:      atomic.LoadUint64(&s.stats.Requests),
		StartTime:     s.stats.StartTime,
	}
}

// isClosed returns whether the server is closed.
func (s *Server) isClosed() bool {
	return atomic.LoadUint32(&s.closed) == 1
}

// Helper functions

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSubdomain() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func extractSubdomain(host, domain string) string {
	// Simple extraction: assumes host is subdomain.domain
	// In production, this should be more robust
	if len(host) <= len(domain) {
		return ""
	}
	return host[:len(host)-len(domain)-1]
}
