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

	// Listeners.
	tunnelListener net.Listener
	httpListener   net.Listener
	adminListener  net.Listener

	router        *Router
	httpHandler   *HTTPHandler
	tlsManager    *TLSManager
	adminAPI      *AdminAPI
	portAllocator *TCPPortAllocator

	// Client management.
	clients    map[string]*ClientSession
	clientLock sync.RWMutex

	// Stats.
	stats ServerStats

	// Shutdown.
	closed  uint32
	closeCh chan struct{}
	closeWg sync.WaitGroup
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

	// P2P info.
	P2PPublicAddr string
	P2PNATType    string

	mu sync.Mutex
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
	s := &Server{
		config:  config,
		clients: make(map[string]*ClientSession),
		closeCh: make(chan struct{}),
		stats: ServerStats{
			StartTime: time.Now(),
		},
	}

	// Initialize Phase 2 components.
	s.router = NewRouter(config.Domain)
	s.httpHandler = NewHTTPHandler(s.router, s)
	s.tlsManager = NewTLSManager(config)
	s.adminAPI = NewAdminAPI(s)
	s.portAllocator = NewTCPPortAllocator(config.TCPPortRangeStart, config.TCPPortRangeEnd)

	return s
}

// Start starts the server.
func (s *Server) Start(ctx context.Context) error {
	log.Info().
		Str("tunnel_addr", s.config.ListenAddr).
		Str("http_addr", s.config.HTTPAddr).
		Str("admin_addr", s.config.AdminAddr).
		Str("domain", s.config.Domain).
		Bool("tls", s.config.TLSEnabled).
		Msg("Starting Wormhole server")

	// Start tunnel listener.
	lc := net.ListenConfig{}
	tunnelLn, err := lc.Listen(ctx, "tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen tunnel: %w", err)
	}
	s.tunnelListener = tunnelLn

	// Start HTTP listener (with optional TLS).
	httpLn, err := lc.Listen(ctx, "tcp", s.config.HTTPAddr)
	if err != nil {
		_ = tunnelLn.Close()
		return fmt.Errorf("listen http: %w", err)
	}
	// Wrap with TLS if configured.
	s.httpListener = s.tlsManager.WrapListener(httpLn)

	// Start admin listener.
	adminLn, err := lc.Listen(ctx, "tcp", s.config.AdminAddr)
	if err != nil {
		_ = tunnelLn.Close()
		_ = httpLn.Close()
		return fmt.Errorf("listen admin: %w", err)
	}
	s.adminListener = adminLn

	// Start ACME HTTP-01 challenge server if AutoTLS is enabled.
	if s.config.TLSEnabled && s.config.AutoTLS {
		s.closeWg.Add(1)
		go s.serveACMEChallenge()
	}

	// Start accept loops.
	s.closeWg.Add(3)
	go s.acceptTunnelLoop() //nolint:contextcheck // tunnel accept loop runs as background goroutine
	go s.serveHTTP()
	go s.serveAdmin()

	log.Info().Msg("Server started successfully")

	// Wait for shutdown.
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

	// Close listeners.
	if s.tunnelListener != nil {
		_ = s.tunnelListener.Close()
	}
	if s.httpListener != nil {
		_ = s.httpListener.Close()
	}
	if s.adminListener != nil {
		_ = s.adminListener.Close()
	}

	// Close port allocator.
	if s.portAllocator != nil {
		s.portAllocator.CloseAll()
	}

	// Close all clients.
	s.clientLock.Lock()
	for _, client := range s.clients {
		_ = client.Mux.Close()
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

	// Create multiplexer.
	mux, err := tunnel.Server(conn, s.config.MuxConfig)
	if err != nil {
		log.Error().Err(err).Str("remote", remoteAddr).Msg("Failed to create mux")
		_ = conn.Close()
		return
	}

	// Generate session ID and subdomain.
	sessionID := generateID()
	subdomain := generateSubdomain()

	// Create client session.
	client := &ClientSession{
		ID:        sessionID,
		Subdomain: subdomain,
		Mux:       mux,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Register client.
	s.clientLock.Lock()
	s.clients[sessionID] = client
	s.clientLock.Unlock()

	// Register route via Router.
	if err := s.router.RegisterSubdomain(subdomain, client); err != nil {
		log.Error().Err(err).Str("subdomain", subdomain).Msg("Failed to register subdomain")
	}

	atomic.AddUint64(&s.stats.ActiveClients, 1)
	atomic.AddUint64(&s.stats.TotalClients, 1)

	log.Info().
		Str("session_id", sessionID).
		Str("subdomain", subdomain).
		Str("remote", remoteAddr).
		Msg("Client registered")

	// Handle client streams.
	s.handleClientStreams(client)

	// Client disconnected — clean up.
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

	// Read control message.
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

	// Handle message.
	switch msg.Type {
	case proto.MessageTypeRegisterRequest:
		s.handleRegister(client, stream, msg.RegisterRequest)
	case proto.MessageTypePingRequest:
		s.handlePing(client, stream, msg.PingRequest)
	case proto.MessageTypeP2POfferRequest:
		s.handleP2POffer(client, stream, msg.P2POfferRequest)
	case proto.MessageTypeP2PResult:
		s.handleP2PResult(client, msg.P2PResult)
	default:
		log.Warn().Int("type", int(msg.Type)).Msg("Unknown message type")
	}
}

// handleRegister handles a tunnel registration request.
func (s *Server) handleRegister(client *ClientSession, stream *tunnel.Stream, req *proto.RegisterRequest) {
	tunnelID := generateID()

	// Determine public URL based on TLS config.
	scheme := "http"
	if s.config.TLSEnabled {
		scheme = "https"
	}
	publicURL := fmt.Sprintf("%s://%s.%s", scheme, client.Subdomain, s.config.Domain)

	// Allocate TCP port for TCP tunnels.
	var tcpPort uint32
	if req.Protocol == proto.ProtocolTCP {
		port, ln, allocErr := s.portAllocator.Allocate(context.Background())
		if allocErr != nil {
			log.Error().Err(allocErr).Msg("Failed to allocate TCP port")
		} else {
			tcpPort = uint32(port)
			// Start TCP listener for this tunnel.
			go s.serveTCPTunnel(ln, client)
		}
	}

	tunnelInfo := &TunnelInfo{
		ID:        tunnelID,
		LocalPort: req.LocalPort,
		Protocol:  req.Protocol,
		PublicURL: publicURL,
		TCPPort:   tcpPort,
		CreatedAt: time.Now(),
	}

	client.mu.Lock()
	client.Tunnels = append(client.Tunnels, tunnelInfo)
	client.mu.Unlock()

	atomic.AddUint64(&s.stats.ActiveTunnels, 1)

	// Also register custom hostname/path if requested.
	if req.Hostname != "" {
		if regErr := s.router.RegisterHostname(req.Hostname, client); regErr != nil {
			log.Warn().Err(regErr).Str("hostname", req.Hostname).Msg("Failed to register custom hostname")
		}
	}

	// Send response.
	resp := proto.NewRegisterResponse(true, "", tunnelID, publicURL, tcpPort)
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode register response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Msg("Failed to write register response")
		return
	}

	log.Info().
		Str("tunnel_id", tunnelID).
		Str("public_url", publicURL).
		Uint32("local_port", req.LocalPort).
		Uint32("tcp_port", tcpPort).
		Msg("Tunnel registered")
}

// handlePing handles a ping request.
func (s *Server) handlePing(client *ClientSession, stream *tunnel.Stream, req *proto.PingRequest) {
	client.mu.Lock()
	client.LastSeen = time.Now()
	client.mu.Unlock()

	resp := proto.NewPingResponse(req.PingID)
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode ping response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Msg("Failed to write ping response")
	}
}

// handleP2POffer handles a P2P connection offer from a client.
// It stores the client's P2P info and returns the peer's info if available.
func (s *Server) handleP2POffer(client *ClientSession, stream *tunnel.Stream, req *proto.P2POfferRequest) {
	// Store client's P2P info.
	client.mu.Lock()
	client.P2PPublicAddr = req.PublicAddr
	client.P2PNATType = req.NATType
	client.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("nat_type", req.NATType).
		Str("public_addr", req.PublicAddr).
		Msg("P2P offer received")

	// For now, we store the P2P info for future peer matching.
	// In a multi-client scenario, we would look up the peer and relay the offer.
	// Current single-client-exposes-service model doesn't have a direct peer to
	// match, so we respond with success=false and the client stays in relay mode.
	resp := proto.NewP2POfferResponse(false, "no peer available for P2P", "", "")
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode P2P offer response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Msg("Failed to write P2P offer response")
	}
}

// handleP2PResult handles a P2P result notification from a client.
func (s *Server) handleP2PResult(client *ClientSession, result *proto.P2PResult) {
	if result.Success {
		log.Info().
			Str("client", client.ID).
			Str("peer_addr", result.PeerAddr).
			Msg("P2P connection established")
	} else {
		log.Info().
			Str("client", client.ID).
			Str("error", result.Error).
			Msg("P2P connection failed, using relay")
	}
}

// FindPeerForP2P looks up a peer client that could establish a P2P connection.
// Returns nil if no suitable peer is found.
func (s *Server) FindPeerForP2P(excludeClientID string) *ClientSession {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()

	for _, client := range s.clients {
		if client.ID != excludeClientID && client.P2PPublicAddr != "" {
			return client
		}
	}
	return nil
}

// serveHTTP serves HTTP requests using the new HTTPHandler.
func (s *Server) serveHTTP() {
	defer s.closeWg.Done()

	server := &http.Server{
		Handler:      s.httpHandler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	if err := server.Serve(s.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("HTTP server error")
	}
}

// serveAdmin serves the admin API using the new AdminAPI handler.
func (s *Server) serveAdmin() {
	defer s.closeWg.Done()

	server := &http.Server{
		Handler:      s.adminAPI.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.Serve(s.adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("Admin server error")
	}
}

// serveACMEChallenge serves ACME HTTP-01 challenges on port 80.
func (s *Server) serveACMEChallenge() {
	defer s.closeWg.Done()

	challengeServer := &http.Server{
		Addr:         ":80",
		Handler:      s.tlsManager.HTTPChallengeHandler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	if err := challengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("ACME challenge server error")
	}
}

// serveTCPTunnel handles raw TCP connections for a tunnel.
func (s *Server) serveTCPTunnel(ln net.Listener, client *ClientSession) {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			log.Error().Err(err).Msg("Accept TCP tunnel connection failed")
			continue
		}

		go s.handleTCPConnection(conn, client)
	}
}

// handleTCPConnection handles a single raw TCP connection by proxying it through the tunnel.
func (s *Server) handleTCPConnection(conn net.Conn, client *ClientSession) {
	defer conn.Close()

	// Open stream to client.
	stream, err := client.Mux.OpenStreamContext(context.Background())
	if err != nil {
		log.Error().Err(err).Msg("Open stream for TCP tunnel failed")
		return
	}
	defer stream.Close()

	// Send stream request.
	streamReq := proto.NewStreamRequest("", generateID(), conn.RemoteAddr().String(), proto.ProtocolTCP)
	data, err := streamReq.Encode()
	if err != nil {
		return
	}
	if _, err := stream.Write(data); err != nil {
		return
	}

	// Bidirectional proxy.
	done := make(chan struct{}, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := conn.Read(buf)
			if readErr != nil {
				break
			}
			if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := stream.Read(buf)
			if readErr != nil {
				break
			}
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
}

// removeClient removes a client from the server.
func (s *Server) removeClient(client *ClientSession) {
	s.clientLock.Lock()
	delete(s.clients, client.ID)
	s.clientLock.Unlock()

	// Remove all routes via Router.
	s.router.Unregister(client)

	// Release allocated TCP ports.
	client.mu.Lock()
	for _, t := range client.Tunnels {
		if t.TCPPort > 0 {
			s.portAllocator.Release(int(t.TCPPort))
		}
	}
	client.mu.Unlock()

	atomic.AddUint64(&s.stats.ActiveClients, ^uint64(0)) // Decrement.

	_ = client.Mux.Close()
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

// Helper functions.

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
