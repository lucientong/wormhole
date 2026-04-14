package server

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

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/rs/zerolog/log"
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

	// Authentication.
	authenticator *auth.Auth
	rateLimiter   *auth.RateLimiter

	// Client management.
	clients    map[string]*ClientSession
	clientLock sync.RWMutex

	// Stats.
	stats Stats

	// Prometheus metrics (nil when EnableMetrics is false).
	metrics *Metrics

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

	// Authentication info.
	TeamName string
	Role     auth.Role

	// P2P info.
	P2PPublicAddr string
	P2PNATType    string
	P2PLocalAddr  string
	P2PPublicKey  string // ECDH public key (base64-encoded) for E2E encryption.

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

// Stats contains server statistics.
type Stats struct {
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
		stats: Stats{
			StartTime: time.Now(),
		},
	}

	// Initialize Phase 2 components.
	s.router = NewRouter(config.Domain)
	s.httpHandler = NewHTTPHandler(s.router, s)
	s.tlsManager = NewTLSManager(config)
	s.adminAPI = NewAdminAPI(s)
	s.portAllocator = NewTCPPortAllocator(config.TCPPortRangeStart, config.TCPPortRangeEnd)

	// Initialize Prometheus metrics.
	if config.EnableMetrics {
		s.metrics = NewMetrics()
		log.Info().Msg("Prometheus metrics enabled")
	}

	// Initialize authentication.
	if config.RequireAuth {
		// Initialize storage backend.
		var store auth.Store
		switch config.Persistence {
		case PersistenceSQLite:
			sqliteStore, err := auth.NewSQLiteStore(auth.SQLiteStoreConfig{
				Path:      config.PersistencePath,
				CreateDir: true,
			})
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to initialize SQLite store")
			}
			store = sqliteStore
			log.Info().
				Str("path", config.PersistencePath).
				Msg("Using SQLite persistence for auth data")
		default:
			store = auth.NewMemoryStore()
			log.Info().Msg("Using in-memory storage for auth data (no persistence)")
		}

		switch {
		case config.AuthSecret != "":
			a, err := auth.New(auth.Config{
				Secret:        []byte(config.AuthSecret),
				AllowedTokens: config.AuthTokens,
				Store:         store,
			})
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to initialize authentication")
			}
			s.authenticator = a
			log.Info().Msg("Authentication enabled (HMAC + simple token mode)")
		case len(config.AuthTokens) > 0:
			s.authenticator = auth.NewSimple(config.AuthTokens)
			log.Info().Int("tokens", len(config.AuthTokens)).Msg("Authentication enabled (simple token mode)")
		default:
			log.Warn().Msg("RequireAuth is true but no tokens or secret configured — all connections will be rejected")
		}

		// Initialize rate limiter for auth failures.
		if config.RateLimitEnabled {
			s.rateLimiter = auth.NewRateLimiter(auth.RateLimitConfig{
				MaxFailures:     config.RateLimitMaxFailures,
				Window:          config.RateLimitWindow,
				BlockDuration:   config.RateLimitBlockDuration,
				CleanupInterval: 1 * time.Minute,
			})
			log.Info().
				Int("max_failures", config.RateLimitMaxFailures).
				Dur("window", config.RateLimitWindow).
				Dur("block_duration", config.RateLimitBlockDuration).
				Msg("Authentication rate limiting enabled")
		}
	}

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

	// Wrap tunnel listener with TLS if configured.
	if s.config.TunnelTLSEnabled {
		s.tunnelListener = s.tlsManager.WrapListener(tunnelLn)
	}

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

	// Close rate limiter.
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	// Close authenticator (and its store).
	if s.authenticator != nil {
		_ = s.authenticator.Close()
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

	// Extract IP for rate limiting (strip port).
	clientIP := extractIP(remoteAddr)

	// Check rate limit before proceeding.
	if s.rateLimiter != nil && s.rateLimiter.IsBlocked(clientIP) {
		log.Warn().Str("ip", clientIP).Msg("Connection rejected: IP is blocked due to auth failures")
		_ = conn.Close()
		return
	}

	// Check server capacity.
	if s.config.MaxClients > 0 {
		s.clientLock.RLock()
		count := len(s.clients)
		s.clientLock.RUnlock()
		if count >= s.config.MaxClients {
			log.Warn().
				Str("ip", clientIP).
				Int("max_clients", s.config.MaxClients).
				Int("current", count).
				Msg("Connection rejected: server at capacity")
			_ = conn.Close()
			return
		}
	}

	// Create multiplexer.
	mux, err := tunnel.Server(conn, s.config.MuxConfig)
	if err != nil {
		log.Error().Err(err).Str("remote", remoteAddr).Msg("Failed to create mux")
		_ = conn.Close()
		return
	}

	// Generate session ID early so auth response carries the same ID we register with.
	sessionID := generateID()

	// Perform authentication handshake (if required).
	teamName, role, subdomain, authOK := s.handleClientAuth(mux, sessionID, clientIP, remoteAddr)
	if !authOK {
		_ = mux.Close()
		return
	}

	// Generate subdomain (if not set by auth).
	if subdomain == "" {
		subdomain = generateSubdomain()
	}

	// Create client session.
	client := &ClientSession{
		ID:        sessionID,
		Subdomain: subdomain,
		Mux:       mux,
		TeamName:  teamName,
		Role:      role,
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
	if s.metrics != nil {
		s.metrics.ActiveClients.Inc()
		s.metrics.ConnectionsTotal.Inc()
	}

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

// handleClientAuth performs the authentication handshake for a new client.
// Returns (teamName, role, subdomain, ok). If ok is false, the caller should close the mux.
func (s *Server) handleClientAuth(mux *tunnel.Mux, sessionID, clientIP, remoteAddr string) (string, auth.Role, string, bool) {
	if !s.config.RequireAuth || s.authenticator == nil {
		return "", "", "", true
	}

	claims, subdomain, authErr := s.authenticateClient(mux, sessionID)
	if authErr != nil {
		log.Warn().Err(authErr).Str("remote", remoteAddr).Msg("Authentication failed")

		// Record auth failure for rate limiting.
		if s.rateLimiter != nil {
			blocked := s.rateLimiter.RecordFailure(clientIP)
			if blocked {
				log.Warn().Str("ip", clientIP).Msg("IP blocked due to repeated auth failures")
			}
		}

		// Record auth failure metric.
		if s.metrics != nil {
			s.metrics.AuthAttemptsTotal.WithLabelValues("failure").Inc()
		}

		return "", "", "", false
	}

	// Auth successful — clear any failure history.
	if s.rateLimiter != nil {
		s.rateLimiter.RecordSuccess(clientIP)
	}

	// Record auth success metric.
	if s.metrics != nil {
		s.metrics.AuthAttemptsTotal.WithLabelValues("success").Inc()
	}

	log.Info().
		Str("team", claims.TeamName).
		Str("role", string(claims.Role)).
		Str("remote", remoteAddr).
		Msg("Client authenticated")

	return claims.TeamName, claims.Role, subdomain, true
}

// authenticateClient performs the authentication handshake with a client.
// It waits for an AuthRequest on the first stream and responds with AuthResponse.
// The sessionID parameter is the pre-generated ID to include in the response.
func (s *Server) authenticateClient(mux *tunnel.Mux, sessionID string) (*auth.Claims, string, error) {
	// Accept the auth stream with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), s.config.AuthTimeout)
	defer cancel()

	stream, err := mux.AcceptStreamContext(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("accept auth stream: %w", err)
	}
	defer stream.Close()

	// Set read deadline.
	if deadlineErr := stream.SetDeadline(time.Now().Add(s.config.AuthTimeout)); deadlineErr != nil {
		return nil, "", fmt.Errorf("set auth deadline: %w", deadlineErr)
	}

	// Read auth request.
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return nil, "", fmt.Errorf("read auth request: %w", err)
	}

	msg, err := proto.DecodeControlMessage(buf[:n])
	if err != nil {
		return nil, "", fmt.Errorf("decode auth request: %w", err)
	}

	if msg.Type != proto.MessageTypeAuthRequest || msg.AuthRequest == nil {
		// Send rejection and return error.
		resp := proto.NewAuthResponse(false, "expected auth request", "", "", "")
		if data, encErr := resp.Encode(); encErr == nil {
			_, _ = stream.Write(data)
		}
		return nil, "", fmt.Errorf("expected auth request, got type %d", msg.Type)
	}

	authReq := msg.AuthRequest

	// Validate token.
	claims, err := s.authenticator.ValidateToken(authReq.Token)
	if err != nil {
		// Send failure response.
		resp := proto.NewAuthResponse(false, "authentication failed: "+err.Error(), "", "", "")
		if data, encErr := resp.Encode(); encErr == nil {
			_, _ = stream.Write(data)
		}
		return nil, "", fmt.Errorf("validate token: %w", err)
	}

	// Check connect permission.
	if !auth.HasPermission(claims, auth.PermissionConnect) {
		resp := proto.NewAuthResponse(false, "insufficient permissions", "", "", "")
		if data, encErr := resp.Encode(); encErr == nil {
			_, _ = stream.Write(data)
		}
		return nil, "", fmt.Errorf("role %s lacks connect permission", claims.Role)
	}

	// Generate subdomain from auth request (or assign a random one).
	subdomain := authReq.Subdomain
	if subdomain == "" {
		subdomain = generateSubdomain()
	}

	// Send success response with the pre-generated session ID.
	resp := proto.NewAuthResponse(true, "", subdomain, "", sessionID)
	data, err := resp.Encode()
	if err != nil {
		return nil, "", fmt.Errorf("encode auth response: %w", err)
	}
	if _, writeErr := stream.Write(data); writeErr != nil {
		return nil, "", fmt.Errorf("write auth response: %w", writeErr)
	}

	log.Debug().
		Str("team", claims.TeamName).
		Str("role", string(claims.Role)).
		Str("version", authReq.Version).
		Str("subdomain", subdomain).
		Msg("Authentication successful")

	return claims, subdomain, nil
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
	case proto.MessageTypeStatsRequest:
		s.handleStats(client, stream, msg.StatsRequest)
	case proto.MessageTypeCloseRequest:
		s.handleClose(client, stream, msg.CloseRequest)
	case proto.MessageTypeP2POfferRequest:
		s.handleP2POffer(client, stream, msg.P2POfferRequest)
	case proto.MessageTypeP2PResult:
		s.handleP2PResult(client, msg.P2PResult)
	default:
		log.Warn().
			Int("type", int(msg.Type)).
			Str("client", client.ID).
			Msg("Unknown control message type")
	}
}

// handleRegister handles a tunnel registration request.
func (s *Server) handleRegister(client *ClientSession, stream *tunnel.Stream, req *proto.RegisterRequest) {
	// Check per-client tunnel limit.
	if s.config.MaxTunnelsPerClient > 0 {
		client.mu.Lock()
		tunnelCount := len(client.Tunnels)
		client.mu.Unlock()
		if tunnelCount >= s.config.MaxTunnelsPerClient {
			log.Warn().
				Str("client", client.ID).
				Int("max_tunnels", s.config.MaxTunnelsPerClient).
				Int("current", tunnelCount).
				Msg("Tunnel registration rejected: per-client limit reached")
			resp := proto.NewRegisterResponse(false, "per-client tunnel limit reached", "", "", 0)
			data, err := resp.Encode()
			if err != nil {
				log.Error().Err(err).Msg("Failed to encode register response")
				return
			}
			if _, err := stream.Write(data); err != nil {
				log.Error().Err(err).Msg("Failed to write register response")
			}
			return
		}
	}

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
			tcpPort = uint32(port) // #nosec G115 -- port from allocator is always in valid range (1024-65535)
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
	if s.metrics != nil {
		s.metrics.ActiveTunnels.Inc()
	}

	// Also register custom hostname/path if requested.
	if req.Hostname != "" {
		if regErr := s.router.RegisterHostname(req.Hostname, client); regErr != nil {
			log.Warn().Err(regErr).Str("hostname", req.Hostname).Msg("Failed to register custom hostname")
		}
	}
	if req.PathPrefix != "" {
		if regErr := s.router.RegisterPath(req.PathPrefix, client); regErr != nil {
			log.Warn().Err(regErr).Str("path_prefix", req.PathPrefix).Msg("Failed to register path prefix")
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

// handleStats handles a stats request from a client.
// It returns the client's session statistics including active tunnels,
// byte counters, and uptime.
func (s *Server) handleStats(client *ClientSession, stream *tunnel.Stream, _ *proto.StatsRequest) {
	client.mu.Lock()
	tunnelCount := uint32(len(client.Tunnels)) // #nosec G115 -- len() is always non-negative and small.
	bytesIn := client.BytesIn
	bytesOut := client.BytesOut
	createdAt := client.CreatedAt
	client.mu.Unlock()

	uptimeSeconds := uint64(time.Since(createdAt).Seconds())

	resp := proto.NewStatsResponse(
		tunnelCount,
		0, // ActiveConnections — not tracked per-client yet.
		bytesOut,
		bytesIn,
		0, // RequestsHandled — not tracked per-client yet.
		uptimeSeconds,
	)
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Str("client", client.ID).Msg("Failed to encode stats response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Str("client", client.ID).Msg("Failed to write stats response")
	}
}

// handleClose handles a close request from a client.
// It finds the specified tunnel, cleans up its routes and TCP port,
// removes it from the client session, and returns a CloseResponse.
func (s *Server) handleClose(client *ClientSession, stream *tunnel.Stream, req *proto.CloseRequest) {
	if req == nil || req.TunnelID == "" {
		log.Warn().Str("client", client.ID).Msg("Close request with empty tunnel ID")
		resp := proto.NewCloseResponse(false)
		data, err := resp.Encode()
		if err != nil {
			return
		}
		_, _ = stream.Write(data)
		return
	}

	log.Info().
		Str("client", client.ID).
		Str("tunnel_id", req.TunnelID).
		Str("reason", req.Reason).
		Msg("Close request received")

	// Find and remove the tunnel from the client session.
	client.mu.Lock()
	var removed *TunnelInfo
	for i, t := range client.Tunnels {
		if t.ID == req.TunnelID {
			removed = t
			// Remove from slice by swapping with last element.
			client.Tunnels[i] = client.Tunnels[len(client.Tunnels)-1]
			client.Tunnels = client.Tunnels[:len(client.Tunnels)-1]
			break
		}
	}
	client.mu.Unlock()

	if removed == nil {
		log.Warn().
			Str("client", client.ID).
			Str("tunnel_id", req.TunnelID).
			Msg("Tunnel not found for close request")
		resp := proto.NewCloseResponse(false)
		data, err := resp.Encode()
		if err != nil {
			return
		}
		_, _ = stream.Write(data)
		return
	}

	// Release allocated TCP port if any.
	if removed.TCPPort > 0 {
		s.portAllocator.Release(int(removed.TCPPort))
	}

	// Decrement active tunnel counter.
	atomic.AddUint64(&s.stats.ActiveTunnels, ^uint64(0))
	if s.metrics != nil {
		s.metrics.ActiveTunnels.Dec()
		s.metrics.TunnelDurationSeconds.Observe(time.Since(removed.CreatedAt).Seconds())
	}

	log.Info().
		Str("client", client.ID).
		Str("tunnel_id", req.TunnelID).
		Str("public_url", removed.PublicURL).
		Msg("Tunnel closed successfully")

	// Send success response.
	resp := proto.NewCloseResponse(true)
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Str("client", client.ID).Msg("Failed to encode close response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Str("client", client.ID).Msg("Failed to write close response")
	}
}

// handleP2POffer handles a P2P connection offer from a client.
// It stores the client's P2P info and returns the peer's info if available.
func (s *Server) handleP2POffer(client *ClientSession, stream *tunnel.Stream, req *proto.P2POfferRequest) {
	// Store client's P2P info (including ECDH public key).
	client.mu.Lock()
	client.P2PPublicAddr = req.PublicAddr
	client.P2PNATType = req.NATType
	client.P2PLocalAddr = req.LocalAddr
	client.P2PPublicKey = req.PublicKey
	client.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("nat_type", req.NATType).
		Str("public_addr", req.PublicAddr).
		Str("local_addr", req.LocalAddr).
		Bool("has_public_key", req.PublicKey != "").
		Msg("P2P offer received")

	// Try to find a peer that can establish P2P connection.
	peer := s.FindPeerForP2P(client.ID)
	if peer == nil {
		resp := proto.NewP2POfferResponse(false, "no peer available for P2P", "", "", "")
		data, err := resp.Encode()
		if err != nil {
			log.Error().Err(err).Msg("Failed to encode P2P offer response")
			return
		}
		if _, err := stream.Write(data); err != nil {
			log.Error().Err(err).Msg("Failed to write P2P offer response")
		}
		return
	}

	// Check if both NAT types are traversable.
	if !s.isP2PCompatible(req.NATType, peer.P2PNATType) {
		log.Info().
			Str("client_nat", req.NATType).
			Str("peer_nat", peer.P2PNATType).
			Msg("NAT types not compatible for P2P")
		resp := proto.NewP2POfferResponse(false, "NAT types not compatible", "", "", "")
		data, _ := resp.Encode()
		_, _ = stream.Write(data)
		return
	}

	// Found a compatible peer! Return peer info to initiator.
	peer.mu.Lock()
	peerAddr := peer.P2PPublicAddr
	peerNATType := peer.P2PNATType
	peerPublicKey := peer.P2PPublicKey
	peer.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("peer", peer.ID).
		Str("peer_addr", peerAddr).
		Bool("has_peer_key", peerPublicKey != "").
		Msg("P2P peer matched")

	// Send peer info (including ECDH public key) to initiating client.
	resp := proto.NewP2POfferResponse(true, "", peerAddr, peerNATType, peerPublicKey)
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode P2P offer response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Msg("Failed to write P2P offer response")
		return
	}

	// Notify the peer about the incoming P2P request (via a new stream).
	go s.notifyPeerOfP2P(peer, client)
}

// isP2PCompatible checks if two NAT types can establish a P2P connection.
func (s *Server) isP2PCompatible(natType1, natType2 string) bool {
	// Symmetric NAT on both sides is generally not traversable.
	symmetric := "Symmetric"
	if natType1 == symmetric && natType2 == symmetric {
		return false
	}
	// At least one side should be traversable (non-symmetric).
	return true
}

// notifyPeerOfP2P sends a P2P offer notification to the peer client.
func (s *Server) notifyPeerOfP2P(peer *ClientSession, initiator *ClientSession) {
	initiator.mu.Lock()
	initiatorAddr := initiator.P2PPublicAddr
	initiatorNATType := initiator.P2PNATType
	initiatorPublicKey := initiator.P2PPublicKey
	initiator.mu.Unlock()

	// Open a stream to the peer to notify them.
	stream, err := peer.Mux.OpenStreamContext(context.Background())
	if err != nil {
		log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to open stream to notify peer of P2P")
		return
	}
	defer stream.Close()

	// Send P2P offer response (as a notification) with the initiator's info and public key.
	msg := proto.NewP2POfferResponse(true, "", initiatorAddr, initiatorNATType, initiatorPublicKey)
	data, err := msg.Encode()
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode P2P notification")
		return
	}

	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Error().Err(err).Msg("Failed to set P2P notification deadline")
		return
	}

	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to write P2P notification")
		return
	}

	log.Debug().
		Str("peer", peer.ID).
		Str("initiator_addr", initiatorAddr).
		Bool("has_key", initiatorPublicKey != "").
		Msg("P2P notification sent to peer")
}

// handleP2PResult handles a P2P result notification from a client.
func (s *Server) handleP2PResult(client *ClientSession, result *proto.P2PResult) {
	if result.Success {
		log.Info().
			Str("client", client.ID).
			Str("peer_addr", result.PeerAddr).
			Msg("P2P connection established")
		if s.metrics != nil {
			s.metrics.P2PConnectionsTotal.WithLabelValues("success").Inc()
		}
	} else {
		log.Info().
			Str("client", client.ID).
			Str("error", result.Error).
			Msg("P2P connection failed, using relay")
		if s.metrics != nil {
			s.metrics.P2PConnectionsTotal.WithLabelValues("fallback").Inc()
		}
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
		Handler:        s.httpHandler,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		IdleTimeout:    s.config.IdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1 MB — mitigate large-header DoS.
	}

	if err := server.Serve(s.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("HTTP server error")
	}
}

// serveAdmin serves the admin API using the new AdminAPI handler.
func (s *Server) serveAdmin() {
	defer s.closeWg.Done()

	server := &http.Server{
		Handler:        s.adminAPI.Handler(),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB — mitigate large-header DoS.
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
	if err := proto.WriteControlMessage(stream, streamReq); err != nil {
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
	if s.metrics != nil {
		s.metrics.ActiveClients.Dec()
		// Record tunnel durations for all tunnels being removed.
		for _, t := range client.Tunnels {
			s.metrics.TunnelDurationSeconds.Observe(time.Since(t.CreatedAt).Seconds())
		}
	}

	_ = client.Mux.Close()
}

// getStats returns server statistics.
func (s *Server) getStats() Stats {
	return Stats{
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
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// extractIP extracts the IP address from a remote address string.
// It handles both IPv4 (host:port) and IPv6 ([host]:port) formats.
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Couldn't parse, return as-is (might be IP without port).
		return remoteAddr
	}
	return host
}
