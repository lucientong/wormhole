package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/lucientong/wormhole/pkg/version"
	"github.com/rs/zerolog/log"
)

// NAT type strings as reported by pkg/p2p NAT detection and carried in
// P2POfferRequest/P2POfferResponse.P2PNATType.
const (
	natTypeSymmetric          = "Symmetric"
	natTypeFullCone           = "Full Cone"
	natTypeRestrictedCone     = "Restricted Cone"
	natTypePortRestrictedCone = "Port Restricted Cone"
)

// defaultShutdownTimeout is used when Config.ShutdownTimeout is unset
// (DP-26): it bounds how long Shutdown waits for http.Server.Shutdown
// to drain in-flight HTTP/admin requests before forcing them closed.
const defaultShutdownTimeout = 15 * time.Second

// Server is the wormhole server.
type Server struct {
	config Config

	// Listeners.
	tunnelListener net.Listener
	httpListener   net.Listener
	adminListener  net.Listener

	// httpServer/adminServer are held so Shutdown can call their
	// Shutdown(ctx) instead of just closing the underlying listener
	// (DP-26): closing the listener alone stops new connections but
	// hard-cuts in-flight requests, since http.Server.Serve returns
	// immediately on a closed listener without draining anything.
	httpServer  *http.Server
	adminServer *http.Server

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

	// Audit logger (nil when AuditEnabled is false).
	auditLogger *auth.AuditLogger

	// Cluster state store (nil for single-node mode).
	stateStore StateStore

	// stateStoreHealthy tracks whether the most recent heartbeat/route
	// refresh against stateStore succeeded, surfaced via /health (H9).
	stateStoreHealthy atomic.Bool

	// activeDataStreams counts data-plane streams currently proxying
	// (HTTP forward, WebSocket, TCP tunnel) across all clients, bounded
	// by config.MaxConcurrentStreams (DP-03). Manipulated only via
	// tryAcquireStreamSlot/releaseStreamSlot.
	activeDataStreams int64

	// listenersReady is closed once Start has bound tunnelListener,
	// httpListener and adminListener (and built httpServer/adminServer),
	// giving callers/tests a race-detector-safe way to wait for startup
	// instead of a fixed sleep.
	listenersReady chan struct{}

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
	P2PTunnelID   string // Tunnel ID from the latest P2P offer.

	// clusterRoutes records every cluster StateStore route entry this
	// client currently owns (connect-time subdomain plus any per-tunnel
	// hostname/path entries), so the heartbeat loop can periodically
	// re-register them to refresh their TTL (H1) without needing to
	// recompute what should still be registered from scratch.
	clusterRoutes []RouteEntry

	// activeDataStreams counts this client's own in-flight data-plane
	// streams, bounded by config.MaxStreamsPerClient (DP-27) independent
	// of the global activeDataStreams cap on Server.
	activeDataStreams int32

	mu sync.Mutex
}

// remoteAddr returns the client's remote network address for audit
// logging, or "" if unavailable (e.g. in unit tests with no real Mux).
func (c *ClientSession) remoteAddr() string {
	if c.Mux == nil {
		return ""
	}
	if addr := c.Mux.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

// TunnelInfo contains information about a tunnel.
type TunnelInfo struct {
	ID        string
	LocalPort uint32
	Protocol  proto.Protocol
	PublicURL string
	TCPPort   uint32
	CreatedAt time.Time

	// Routing metadata, used to disambiguate which tunnel a given HTTP
	// request targets when a client has registered multiple tunnels
	// (see resolveTunnelID in handler.go), and to clean up the
	// corresponding Router entries when this tunnel is individually closed.
	Subdomain  string
	Hostname   string
	PathPrefix string
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
	applyClusterNodeIDDefault(&config)

	s := &Server{
		config:         config,
		clients:        make(map[string]*ClientSession),
		closeCh:        make(chan struct{}),
		listenersReady: make(chan struct{}),
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

	// Initialize audit logger.
	if config.AuditEnabled {
		auditStore := initAuditStore(config)
		s.auditLogger = auth.NewAuditLogger(auth.AuditLoggerConfig{
			Enabled: true,
			Store:   auditStore,
		})
		log.Info().
			Str("persistence", string(config.AuditPersistence)).
			Msg("Audit logging enabled")
	}

	// Initialize cluster state store.
	s.stateStore = initStateStore(config)
	if s.stateStore != nil {
		// Optimistic default: assume healthy until the first heartbeat
		// (sent moments after Start()) proves otherwise, so /health
		// doesn't report "degraded" for the brief startup window before
		// the cluster heartbeat goroutine gets its first tick in (H9).
		s.stateStoreHealthy.Store(true)
	}

	// Initialize authentication.
	if config.RequireAuth {
		// Initialize storage backend.
		store := initAuthStore(config)

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

		// Initialize OIDC validator (if configured). This must come after
		// s.authenticator is constructed above — it previously ran before
		// the authenticator existed, so the `s.authenticator != nil` guard
		// was always false and OIDC was silently never wired up server-side
		// no matter what --oidc-issuer was set to (uncovered by any test).
		if config.OIDCIssuer != "" && s.authenticator != nil {
			oidcCfg := auth.OIDCConfig{
				Issuer:   config.OIDCIssuer,
				ClientID: config.OIDCClientID,
				ClaimMapping: auth.OIDCClaimMapping{
					TeamClaim:   config.OIDCTeamClaim,
					RoleClaim:   config.OIDCRoleClaim,
					DefaultRole: auth.RoleMember,
				},
			}
			if v, err := auth.NewOIDCValidator(oidcCfg); err != nil {
				log.Fatal().Err(err).Msg("Failed to initialize OIDC validator")
			} else {
				s.authenticator.SetOIDCValidator(v)
				log.Info().
					Str("issuer", config.OIDCIssuer).
					Str("client_id", config.OIDCClientID).
					Msg("OIDC JWT validation enabled")
			}
		}
	}

	return s
}

// applyClusterNodeIDDefault implements H4: ClusterNodeID "defaults to
// hostname" was documented but never implemented — an operator who enables
// clustering without explicitly setting --cluster-node-id got an empty
// NodeID, which breaks isLocalNode() (every route looks "remote") and
// produces ambiguous wormhole:node: entries in the state store if more
// than one such node exists. Falls back to os.Hostname() only when
// clustering is actually enabled, to avoid a surprising hostname leak for
// single-node setups.
func applyClusterNodeIDDefault(config *Config) {
	if config.ClusterStateBackend == "" || config.ClusterNodeID != "" {
		return
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		log.Warn().Err(err).Msg("Cluster: ClusterNodeID not set and hostname lookup failed; " +
			"node identity will be empty, which breaks cross-node route ownership checks")
		return
	}
	config.ClusterNodeID = hostname
	log.Info().Str("cluster_node_id", hostname).
		Msg("Cluster: ClusterNodeID not set, defaulting to hostname")
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

	// Wrap tunnel listener with TLS if configured (S4: decoupled from
	// Config.TLSEnabled — see TunnelTLSConfig's doc comment). When
	// RequireAuth is set, a TLS config error is fatal rather than a
	// silent fallback to plaintext: auth tokens travel over this
	// channel, and continuing unencrypted would violate the guarantee
	// operators asked for by combining --require-auth with --tunnel-tls
	// (or the RequireAuth-driven default enabled below in
	// buildServerConfig).
	if s.config.TunnelTLSEnabled {
		wrapped, tlsErr := s.tlsManager.WrapTunnelListenerStrict(tunnelLn)
		if tlsErr != nil {
			if s.config.RequireAuth {
				_ = tunnelLn.Close()
				return fmt.Errorf("tunnel control channel TLS required (RequireAuth is enabled) but could not be configured: %w", tlsErr)
			}
			log.Error().Err(tlsErr).Msg("Failed to enable tunnel TLS, continuing with plaintext control channel")
		} else {
			s.tunnelListener = wrapped
		}
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

	// Build the *http.Server instances synchronously, before the
	// goroutines that call Serve() on them are spawned below, so
	// Shutdown (DP-26) can safely read s.httpServer/s.adminServer
	// without racing their assignment.
	s.httpServer = &http.Server{
		Handler:        s.httpHandler,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		IdleTimeout:    s.config.IdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1 MB — mitigate large-header DoS.
	}
	s.adminServer = &http.Server{
		Handler:        s.adminAPI.Handler(),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB — mitigate large-header DoS.
	}
	close(s.listenersReady)

	// Start ACME HTTP-01 challenge server if AutoTLS is enabled. This is
	// needed whenever *either* the HTTP or the tunnel listener sources its
	// certificate from AutoTLS (S4 can enable AutoTLS purely to serve the
	// tunnel control channel, with TLSEnabled/HTTP TLS left off) — Let's
	// Encrypt's HTTP-01 challenge has to be answered regardless of which
	// listener ultimately presents the resulting certificate.
	if s.config.AutoTLS && (s.config.TLSEnabled || s.config.TunnelTLSEnabled) {
		s.closeWg.Add(1)
		go s.serveACMEChallenge()
	}

	// Start cluster heartbeat (no-op for single-node / nil store).
	s.startClusterHeartbeat(ctx)

	// S10: periodically purge expired entries from the token revocation
	// blacklist. CleanupRevokedTokens() existed and was fully implemented,
	// but nothing ever called it, so the blacklist (and, with SQLite
	// persistence, its backing table) grew without bound over the life of
	// a long-running server.
	if s.authenticator != nil {
		s.closeWg.Add(1)
		go s.runRevokedTokenCleanup()
	}

	// A5: periodically purge audit events older than the configured
	// retention window, so long-running servers with --audit enabled don't
	// grow the (potentially SQLite-backed) audit log without bound.
	if s.auditLogger != nil && s.config.AuditRetentionDays > 0 {
		s.closeWg.Add(1)
		go s.runAuditRetention()
	}

	// Start accept loops.
	s.closeWg.Add(3)
	go s.acceptTunnelLoop() //nolint:contextcheck // tunnel accept loop runs as background goroutine
	go s.serveHTTP()
	go s.serveAdmin()

	log.Info().Msg("Server started successfully")

	// Wait for shutdown.
	<-ctx.Done()
	// ctx is already Done here, so there's nothing meaningful left to
	// propagate to Shutdown; it deliberately derives its own bounded
	// context.WithTimeout(context.Background(), ShutdownTimeout) for the
	// graceful drain instead (DP-26).
	return s.Shutdown() //nolint:contextcheck // ctx already canceled; Shutdown uses its own bounded timeout
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}

	log.Info().Msg("Shutting down server...")
	close(s.closeCh)

	// Close the tunnel listener directly: it's a raw net.Listener (the
	// tunnel protocol is our own framing, not net/http), so there's no
	// http.Server to ask for a graceful drain.
	if s.tunnelListener != nil {
		_ = s.tunnelListener.Close()
	}

	// Gracefully drain the HTTP and admin API servers (DP-26): unlike
	// closing the listener directly, http.Server.Shutdown(ctx) stops
	// accepting new connections immediately but lets in-flight handlers
	// finish (up to ShutdownTimeout) before returning, so a request that's
	// mid-flight when an operator sends SIGTERM completes normally instead
	// of getting its connection yanked out from under it.
	shutdownTimeout := s.config.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = defaultShutdownTimeout
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var httpShutdownWg sync.WaitGroup
	if s.httpServer != nil {
		httpShutdownWg.Go(func() {
			if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
				log.Warn().Err(err).Msg("HTTP server did not shut down gracefully within ShutdownTimeout; forcing close")
				_ = s.httpServer.Close()
			}
		})
	}
	if s.adminServer != nil {
		httpShutdownWg.Go(func() {
			if err := s.adminServer.Shutdown(shutdownCtx); err != nil {
				log.Warn().Err(err).Msg("Admin server did not shut down gracefully within ShutdownTimeout; forcing close")
				_ = s.adminServer.Close()
			}
		})
	}
	httpShutdownWg.Wait()

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

	// Close audit store.
	if s.auditLogger != nil {
		if store := s.auditLogger.Store(); store != nil {
			_ = store.Close()
		}
	}

	// Close cluster state store.
	if s.stateStore != nil {
		_ = s.stateStore.Close()
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
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
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

	// A1: record successful authentication events, not just failures — the
	// audit log previously only ever saw auth_failure entries, making it
	// impossible to answer "who successfully authenticated, from where,
	// and when" from the audit trail.
	if s.config.RequireAuth && s.auditLogger != nil {
		s.auditLogger.LogAuthSuccess(clientIP, teamName, role, sessionID, subdomain)
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

	// Register route via Router and (if clustered) the shared state store
	// *before* exposing the client anywhere else. F6/H6/S3: a subdomain
	// conflict here previously only got logged, and the connection was
	// allowed to proceed — but the client had already been told (in the
	// AuthResponse) that it owns `subdomain`, so it would silently receive
	// zero traffic for it while believing it was live. Reject the
	// connection instead so the client's reconnect/retry logic kicks in.
	if !s.registerClientRoute(client, clientIP) {
		_ = mux.Close()
		return
	}

	// Register client.
	s.clientLock.Lock()
	s.clients[sessionID] = client
	s.clientLock.Unlock()

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

	if s.auditLogger != nil {
		s.auditLogger.LogClientConnected(clientIP, sessionID, subdomain, teamName, role)
	}

	connectedAt := time.Now()

	// Handle client streams.
	s.handleClientStreams(client)

	// Client disconnected — clean up.
	s.removeClient(client)

	if s.auditLogger != nil {
		s.auditLogger.LogClientDisconnected(sessionID, subdomain, time.Since(connectedAt))
	}

	log.Info().
		Str("session_id", sessionID).
		Str("subdomain", subdomain).
		Msg("Client disconnected")
}

// registerClientRoute reserves client.Subdomain in the local Router and, if
// clustered, the shared state store. It returns false if the subdomain is
// already claimed by another client (locally or cluster-wide), in which
// case the caller must reject the connection rather than let it proceed
// silently unrouted (F6/H6/S3 — see handleClient's call site for context).
func (s *Server) registerClientRoute(client *ClientSession, clientIP string) bool {
	subdomain, sessionID := client.Subdomain, client.ID

	// H10: Router.RegisterSubdomain (below) already reclaims a
	// subdomain locally when its current owner's mux has died but
	// hasn't been cleaned up yet — e.g. a client reconnecting faster
	// than the old session's death was detected. Proactively evict that
	// stale owner's cluster-side entry too, so the reclaim isn't
	// immediately undone by RegisterRoute finding the old (still
	// TTL-live) entry and reporting a conflict against the new
	// connection's own former self.
	if existing := s.router.LookupSubdomain(subdomain); existing != nil && isStaleOwner(existing, client) && s.stateStore != nil {
		if err := s.stateStore.UnregisterRoute(existing.ID); err != nil {
			log.Warn().Err(err).Str("client", existing.ID).Msg("Cluster: failed to evict stale route before reclaim")
		}
	}

	if err := s.router.RegisterSubdomain(subdomain, client); err != nil {
		log.Error().Err(err).Str("subdomain", subdomain).Str("session_id", sessionID).
			Msg("Subdomain registration conflict — rejecting connection")
		if s.auditLogger != nil {
			s.auditLogger.LogAuthFailure(clientIP, fmt.Sprintf("subdomain %q already in use", subdomain))
		}
		return false
	}

	// H6/S3: RegisterRoute atomically reserves the subdomain cluster-wide
	// (Redis SETNX) instead of last-writer-wins; a genuine conflict with a
	// live owner on another node must reject the connection too, for the
	// same reason as the local check above. RouteID defaults to
	// sessionID/ClientID, matching this connection's primary route.
	ok, err := s.registerClusterRoute(client, RouteEntry{ClientID: sessionID, Subdomain: subdomain})
	if ok {
		return true
	}
	log.Error().Err(err).Str("subdomain", subdomain).Str("session_id", sessionID).
		Msg("Cluster: subdomain already claimed by another node — rejecting connection")
	s.router.UnregisterSubdomain(subdomain)
	if s.auditLogger != nil {
		s.auditLogger.LogAuthFailure(clientIP, fmt.Sprintf("subdomain %q already claimed cluster-wide", subdomain))
	}
	return false
}

// registerClusterRoute reserves entry in the shared state store (a no-op,
// always-true success when running single-node) and, on success, appends
// it to client.clusterRoutes so the heartbeat loop keeps refreshing its TTL
// (H1). NodeID/NodeAddr are filled in from the server's own config. Returns
// (false, ErrSubdomainConflict-wrapping err) only for a genuine live
// conflict; a state-store error unrelated to conflict resolution is logged
// and treated as non-fatal (matches the previous behavior — losing cluster
// visibility temporarily is preferable to rejecting every connection
// whenever Redis hiccups).
func (s *Server) registerClusterRoute(client *ClientSession, entry RouteEntry) (bool, error) {
	if s.stateStore == nil {
		return true, nil
	}

	entry.NodeID = s.config.ClusterNodeID
	entry.NodeAddr = s.config.ClusterNodeAddr

	err := s.stateStore.RegisterRoute(entry)
	if err == nil {
		client.mu.Lock()
		client.clusterRoutes = append(client.clusterRoutes, entry)
		client.mu.Unlock()
		return true, nil
	}
	if !errors.Is(err, ErrSubdomainConflict) {
		log.Warn().Err(err).Str("route", entry.Key()).Msg("Cluster: failed to register route in state store")
		return true, nil
	}
	return false, err
}

// unregisterClusterRoute removes entry from the state store and from
// client.clusterRoutes, undoing registerClusterRoute. Used when an
// individual tunnel (rather than the whole connection) is closed.
func (s *Server) unregisterClusterRoute(client *ClientSession, routeID string) {
	if s.stateStore == nil {
		return
	}
	if err := s.stateStore.UnregisterRouteEntry(routeID); err != nil {
		log.Warn().Err(err).Str("route", routeID).Msg("Cluster: failed to unregister route from state store")
	}
	client.mu.Lock()
	for i, e := range client.clusterRoutes {
		if e.Key() == routeID {
			client.clusterRoutes = append(client.clusterRoutes[:i], client.clusterRoutes[i+1:]...)
			break
		}
	}
	client.mu.Unlock()
}

// registerTunnelRoutes registers a tunnel's extra routing keys (any of
// subdomain/hostname/pathPrefix that's non-empty) in both the local Router
// and, if clustered, the shared state store (H3). Cluster route IDs are
// scoped to tunnelID (":sub"/":host"/":path" suffixes) so multiple tunnels
// on the same client don't collide with each other or with the client's
// primary connect-time subdomain entry (which uses ClientID as its
// RouteID). On any conflict — local or cluster-wide — everything already
// registered by this call is rolled back and a human-readable rejection
// reason is returned; "" means every requested key was registered.
func (s *Server) registerTunnelRoutes(client *ClientSession, tunnelID, subdomain, hostname, pathPrefix string) string {
	if subdomain != "" {
		if err := s.router.RegisterSubdomain(subdomain, client); err != nil {
			return fmt.Sprintf("subdomain %q already in use", subdomain)
		}
		routeID := tunnelID + ":sub"
		if ok, _ := s.registerClusterRoute(client, RouteEntry{RouteID: routeID, ClientID: client.ID, Subdomain: subdomain}); !ok {
			s.router.UnregisterSubdomain(subdomain)
			return fmt.Sprintf("subdomain %q already claimed cluster-wide", subdomain)
		}
	}

	if hostname != "" {
		if err := s.router.RegisterHostname(hostname, client); err != nil {
			s.unregisterTunnelRoutes(client, tunnelID, subdomain, "", "")
			return fmt.Sprintf("hostname %q already in use", hostname)
		}
		routeID := tunnelID + ":host"
		if ok, _ := s.registerClusterRoute(client, RouteEntry{RouteID: routeID, ClientID: client.ID, Hostname: hostname}); !ok {
			s.router.UnregisterHostname(hostname)
			s.unregisterTunnelRoutes(client, tunnelID, subdomain, "", "")
			return fmt.Sprintf("hostname %q already claimed cluster-wide", hostname)
		}
	}

	if pathPrefix != "" {
		if err := s.router.RegisterPath(pathPrefix, client); err != nil {
			s.unregisterTunnelRoutes(client, tunnelID, subdomain, hostname, "")
			return fmt.Sprintf("path prefix %q already in use", pathPrefix)
		}
		routeID := tunnelID + ":path"
		if ok, _ := s.registerClusterRoute(client, RouteEntry{RouteID: routeID, ClientID: client.ID, PathPrefix: pathPrefix}); !ok {
			s.router.UnregisterPath(pathPrefix)
			s.unregisterTunnelRoutes(client, tunnelID, subdomain, hostname, "")
			return fmt.Sprintf("path prefix %q already claimed cluster-wide", pathPrefix)
		}
	}

	return ""
}

// unregisterTunnelRoutes removes the local Router entries and cluster
// state-store entries (if any) for a tunnel's extra subdomain/hostname/path
// routes, undoing registerTunnelRoutes. Used both when TCP port allocation
// fails right after registration and when the tunnel is later closed
// individually (see releaseTunnelResources).
func (s *Server) unregisterTunnelRoutes(client *ClientSession, tunnelID, subdomain, hostname, pathPrefix string) {
	if subdomain != "" {
		s.router.UnregisterSubdomain(subdomain)
		s.unregisterClusterRoute(client, tunnelID+":sub")
	}
	if hostname != "" {
		s.router.UnregisterHostname(hostname)
		s.unregisterClusterRoute(client, tunnelID+":host")
	}
	if pathPrefix != "" {
		s.router.UnregisterPath(pathPrefix)
		s.unregisterClusterRoute(client, tunnelID+":path")
	}
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
				// A2: this was previously never recorded in the audit
				// trail — only the auth_failure events were, with no
				// signal that they had escalated into an IP-level block.
				if s.auditLogger != nil {
					s.auditLogger.LogIPBlocked(clientIP, s.config.RateLimitMaxFailures)
				}
			}
		}

		// Record auth failure metric.
		if s.metrics != nil {
			s.metrics.AuthAttemptsTotal.WithLabelValues("failure").Inc()
		}

		if s.auditLogger != nil {
			s.auditLogger.LogAuthFailure(clientIP, authErr.Error())
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
		s.sendAuthFailure(stream, "expected auth request")
		return nil, "", fmt.Errorf("expected auth request, got type %d", msg.Type)
	}

	authReq := msg.AuthRequest

	// Reject clients reporting a version older than MinClientVersion, if
	// configured (DP-30). Unparseable versions (e.g. "dev" builds) are
	// never rejected — see Config.MinClientVersion doc.
	if rejectMsg := s.checkClientVersion(authReq.Version); rejectMsg != "" {
		s.sendAuthFailure(stream, rejectMsg)
		return nil, "", fmt.Errorf("client version %q rejected: %s", authReq.Version, rejectMsg)
	}

	// Validate token.
	claims, err := s.authenticator.ValidateToken(authReq.Token)
	if err != nil {
		s.sendAuthFailure(stream, "authentication failed: "+err.Error())
		return nil, "", fmt.Errorf("validate token: %w", err)
	}

	// Check connect permission.
	if !auth.HasPermission(claims, auth.PermissionConnect) {
		s.sendAuthFailure(stream, "insufficient permissions")
		return nil, "", fmt.Errorf("role %s lacks connect permission", claims.Role)
	}

	// Generate subdomain from auth request (or assign a random one).
	subdomain := authReq.Subdomain
	if subdomain == "" {
		subdomain = generateSubdomain()
	}

	// Send success response with the pre-generated session ID and this
	// node's real feature set (DP-33), so clients can gate optional
	// behavior (e.g. P2P offers) on what the server actually supports
	// instead of assuming.
	resp := proto.NewAuthResponse(true, "", subdomain, "", sessionID)
	resp.AuthResponse.Capabilities = s.capabilities()
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

// sendAuthFailure encodes and best-effort writes a failure AuthResponse
// to the auth stream. Errors are intentionally swallowed: the caller
// already has (or is about to construct) a more specific error to
// return, and the peer will observe the closed/EOF'd stream either way
// if the write itself fails.
func (s *Server) sendAuthFailure(stream *tunnel.Stream, reason string) {
	resp := proto.NewAuthResponse(false, reason, "", "", "")
	if data, encErr := resp.Encode(); encErr == nil {
		_, _ = stream.Write(data)
	}
}

// checkClientVersion returns a non-empty human-readable rejection reason
// if clientVersion is older than Config.MinClientVersion, and "" if the
// client should be allowed to proceed (either the check is disabled, the
// client is new enough, or the version isn't a parseable semver — e.g. a
// "dev" build, which we always allow rather than guess).
func (s *Server) checkClientVersion(clientVersion string) string {
	if s.config.MinClientVersion == "" {
		return ""
	}
	cmp, err := version.Compare(clientVersion, s.config.MinClientVersion)
	if err != nil || cmp >= 0 {
		return ""
	}
	return fmt.Sprintf("client version %s is older than the minimum supported version %s; please upgrade wormhole",
		clientVersion, s.config.MinClientVersion)
}

// capabilities returns the set of optional protocol features this server
// instance actually supports (DP-33), reported to clients via
// AuthResponse.Capabilities so they can gate optional behavior instead of
// assuming a fixed feature set. "p2p" and "multi-tunnel" relay/routing are
// unconditional server-side; cluster/audit reflect this node's config.
func (s *Server) capabilities() []string {
	caps := []string{"p2p", "multi-tunnel"}
	if s.stateStore != nil {
		caps = append(caps, "cluster")
	}
	if s.auditLogger != nil {
		caps = append(caps, "audit")
	}
	return caps
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

// requireWritePermission enforces RBAC (S2) on tunnel-mutating control
// messages. Role/permission checks previously only ran at the connection
// handshake (PermissionConnect) — once connected, a RoleViewer token could
// still register or close tunnels and claim subdomains, because
// handleRegister/handleClose never consulted auth.HasPermission at all.
// When authentication is disabled, client.Role is always empty and every
// operation is allowed, matching pre-P3-4 behavior.
func (s *Server) requireWritePermission(client *ClientSession) bool {
	if !s.config.RequireAuth {
		return true
	}
	return auth.HasPermission(&auth.Claims{Role: client.Role}, auth.PermissionWrite)
}

// rejectInsufficientPermission logs and audits an RBAC rejection, shared by
// handleRegister and handleClose.
func (s *Server) rejectInsufficientPermission(client *ClientSession, action string) {
	log.Warn().
		Str("client", client.ID).
		Str("role", string(client.Role)).
		Str("action", action).
		Msg("Rejected: role lacks write permission")
	if s.auditLogger != nil {
		s.auditLogger.LogAuthFailure(client.remoteAddr(), fmt.Sprintf("role %s lacks write permission for %s", client.Role, action))
	}
}

// handleRegister handles a tunnel registration request.
//
//nolint:gocyclo // registration coordinates TLS, TCP, routing and audit in one flow
func (s *Server) handleRegister(client *ClientSession, stream *tunnel.Stream, req *proto.RegisterRequest) {
	// S2: RoleViewer (and any other role without PermissionWrite) must not
	// be able to register tunnels or claim subdomains — previously RBAC was
	// only checked once, at the PermissionConnect stage of the handshake.
	if !s.requireWritePermission(client) {
		s.rejectInsufficientPermission(client, "register tunnel")
		resp := proto.NewRegisterResponse(false, "insufficient permissions: role lacks write access", "", "", 0)
		if data, err := resp.Encode(); err == nil {
			_, _ = stream.Write(data)
		}
		return
	}

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

	// Determine the subdomain for THIS tunnel. Each RegisterRequest may ask
	// for its own subdomain (multi-tunnel mode); when omitted, fall back to
	// the connection-level subdomain assigned at auth time (legacy
	// single-tunnel behavior).
	subdomain := req.Subdomain
	if subdomain == "" {
		subdomain = client.Subdomain
	}

	// Determine public URL: prefer a custom hostname when the tunnel
	// requested one, otherwise fall back to the subdomain-based URL.
	scheme := "http"
	if s.config.TLSEnabled {
		scheme = "https"
	}
	publicURL := fmt.Sprintf("%s://%s.%s", scheme, subdomain, s.config.Domain)
	if req.Hostname != "" {
		publicURL = fmt.Sprintf("%s://%s", scheme, req.Hostname)
	}

	// Register this tunnel's routing keys — subdomain (if it differs from
	// the connection's default, which is already routed at auth time),
	// custom hostname, and path prefix — in both the local Router and, if
	// clustered, the shared state store (H3: hostname/path routes were
	// previously local-only, so cluster peers had no way to find them and
	// silently 404'd cross-node hostname/path requests). A conflict on any
	// of them, local or cluster-wide, rejects the whole registration.
	extraSubdomain := ""
	if subdomain != "" && subdomain != client.Subdomain {
		extraSubdomain = subdomain
	}
	if failMsg := s.registerTunnelRoutes(client, tunnelID, extraSubdomain, req.Hostname, req.PathPrefix); failMsg != "" {
		log.Warn().Str("client", client.ID).Str("tunnel_id", tunnelID).Msg("Tunnel registration rejected: " + failMsg)
		resp := proto.NewRegisterResponse(false, failMsg, "", "", 0)
		if data, encErr := resp.Encode(); encErr == nil {
			_, _ = stream.Write(data)
		}
		return
	}

	// Allocate TCP port for TCP tunnels. Unlike HTTP tunnels (which can
	// share the existing HTTP listener via routing), a TCP tunnel is
	// useless without its own dedicated port — registering it as
	// "successful" with TCPPort 0 would silently advertise a tunnel that
	// can never receive traffic (DP-18). Reject the registration instead
	// so the client can surface the failure and retry.
	var tcpPort uint32
	if req.Protocol == proto.ProtocolTCP {
		port, ln, allocErr := s.portAllocator.Allocate(context.Background())
		if allocErr != nil {
			log.Error().Err(allocErr).Msg("Failed to allocate TCP port")
			s.unregisterTunnelRoutes(client, tunnelID, extraSubdomain, req.Hostname, req.PathPrefix)
			resp := proto.NewRegisterResponse(false, fmt.Sprintf("failed to allocate TCP port: %v", allocErr), "", "", 0)
			data, encErr := resp.Encode()
			if encErr != nil {
				return
			}
			_, _ = stream.Write(data)
			return
		}
		tcpPort = uint32(port) // #nosec G115 -- port from allocator is always in valid range (1024-65535)
		// Start TCP listener for this tunnel.
		go s.serveTCPTunnel(ln, client, tunnelID)
	}

	tunnelInfo := &TunnelInfo{
		ID:         tunnelID,
		LocalPort:  req.LocalPort,
		Protocol:   req.Protocol,
		PublicURL:  publicURL,
		TCPPort:    tcpPort,
		CreatedAt:  time.Now(),
		Subdomain:  subdomain,
		Hostname:   req.Hostname,
		PathPrefix: req.PathPrefix,
	}

	client.mu.Lock()
	client.Tunnels = append(client.Tunnels, tunnelInfo)
	client.mu.Unlock()

	atomic.AddUint64(&s.stats.ActiveTunnels, 1)
	if s.metrics != nil {
		s.metrics.ActiveTunnels.Inc()
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

	if s.auditLogger != nil {
		s.auditLogger.LogTunnelCreated(client.ID, tunnelID, req.Protocol.String(), publicURL)
	}
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
	// S2: closing/deleting a tunnel is a write operation just like
	// registering one — enforce the same RBAC gate.
	if !s.requireWritePermission(client) {
		s.rejectInsufficientPermission(client, "close tunnel")
		writeCloseResponse(stream, client.ID, false)
		return
	}

	if req == nil || req.TunnelID == "" {
		log.Warn().Str("client", client.ID).Msg("Close request with empty tunnel ID")
		writeCloseResponse(stream, client.ID, false)
		return
	}

	log.Info().
		Str("client", client.ID).
		Str("tunnel_id", req.TunnelID).
		Str("reason", req.Reason).
		Msg("Close request received")

	removed := removeTunnelFromClient(client, req.TunnelID)
	if removed == nil {
		log.Warn().
			Str("client", client.ID).
			Str("tunnel_id", req.TunnelID).
			Msg("Tunnel not found for close request")
		writeCloseResponse(stream, client.ID, false)
		return
	}

	s.releaseTunnelResources(client, removed)

	log.Info().
		Str("client", client.ID).
		Str("tunnel_id", req.TunnelID).
		Str("public_url", removed.PublicURL).
		Msg("Tunnel closed successfully")

	if s.auditLogger != nil {
		s.auditLogger.LogTunnelClosed(client.ID, removed.ID, removed.Protocol.String(), req.Reason)
	}

	writeCloseResponse(stream, client.ID, true)
}

// writeCloseResponse encodes and writes a CloseResponse, logging any
// encode/write failure instead of propagating it (the client will simply
// time out waiting for a response it never receives).
func writeCloseResponse(stream *tunnel.Stream, clientID string, success bool) {
	resp := proto.NewCloseResponse(success)
	data, err := resp.Encode()
	if err != nil {
		log.Error().Err(err).Str("client", clientID).Msg("Failed to encode close response")
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Error().Err(err).Str("client", clientID).Msg("Failed to write close response")
	}
}

// removeTunnelFromClient finds and removes the tunnel with the given ID from
// client.Tunnels, returning the removed TunnelInfo or nil if not found.
func removeTunnelFromClient(client *ClientSession, tunnelID string) *TunnelInfo {
	client.mu.Lock()
	defer client.mu.Unlock()

	for i, t := range client.Tunnels {
		if t.ID == tunnelID {
			removed := t
			// Remove from slice by swapping with the last element.
			client.Tunnels[i] = client.Tunnels[len(client.Tunnels)-1]
			client.Tunnels = client.Tunnels[:len(client.Tunnels)-1]
			return removed
		}
	}
	return nil
}

// releaseTunnelResources releases the TCP port and unregisters the routes
// owned by a closed tunnel, and updates tunnel metrics. The connection-level
// default subdomain is left registered until full disconnect (removeClient),
// matching legacy single-tunnel behavior.
func (s *Server) releaseTunnelResources(client *ClientSession, removed *TunnelInfo) {
	if removed.TCPPort > 0 {
		s.portAllocator.Release(int(removed.TCPPort))
	}

	extraSubdomain := ""
	if removed.Subdomain != "" && removed.Subdomain != client.Subdomain {
		extraSubdomain = removed.Subdomain
	}
	s.unregisterTunnelRoutes(client, removed.ID, extraSubdomain, removed.Hostname, removed.PathPrefix)

	atomic.AddUint64(&s.stats.ActiveTunnels, ^uint64(0))
	if s.metrics != nil {
		s.metrics.ActiveTunnels.Dec()
		s.metrics.TunnelDurationSeconds.Observe(time.Since(removed.CreatedAt).Seconds())
	}
}

// P2P offer rejection reasons. errP2PNoTarget is the expected, silent
// outcome for a client that's only exposing a tunnel and never asked to
// reach a peer (TargetSubdomain == "") — the client treats it as a no-op
// rather than a P2P failure worth falling back from (see
// Client.handleP2POfferResponse).
const (
	errP2PNoTarget         = "no target specified"
	errP2PTargetNotFound   = "target not found: no client with that subdomain is currently connected"
	errP2PTargetIsSelf     = "cannot connect to your own tunnel via P2P"
	errP2PNATIncompatible  = "NAT types not compatible"
	errP2PTargetTunnelMeta = "target tunnel metadata unavailable"
)

// handleP2POffer handles a P2P connection offer from a client.
//
// It always stores the sender's P2P reachability info (public/local
// address, NAT type, ECDH public key) so it's available if some other
// client later requests a match against one of this client's subdomains.
// A match is only searched for when req.TargetSubdomain is set (i.e. this
// is a `wormhole connect <subdomain>` request) — an empty target is just
// presence registration and gets a quiet errP2PNoTarget response.
func (s *Server) handleP2POffer(client *ClientSession, stream *tunnel.Stream, req *proto.P2POfferRequest) {
	client.mu.Lock()
	client.P2PPublicAddr = req.PublicAddr
	client.P2PNATType = req.NATType
	client.P2PLocalAddr = req.LocalAddr
	client.P2PPublicKey = req.PublicKey
	client.P2PTunnelID = req.TunnelID
	client.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("nat_type", req.NATType).
		Str("public_addr", req.PublicAddr).
		Str("local_addr", req.LocalAddr).
		Bool("has_public_key", req.PublicKey != "").
		Str("target_subdomain", req.TargetSubdomain).
		Msg("P2P offer received")

	if req.TargetSubdomain == "" {
		resp := proto.NewP2POfferResponse(false, errP2PNoTarget, "", "", "", "")
		if err := proto.WriteControlMessage(stream, resp); err != nil {
			log.Error().Err(err).Msg("Failed to write P2P offer response")
		}
		return
	}

	peer, peerTunnelID, findErr := s.findPeerBySubdomain(req.TargetSubdomain, client)
	if findErr != "" {
		log.Info().Str("client", client.ID).Str("target", req.TargetSubdomain).Str("reason", findErr).
			Msg("P2P connect request could not be matched")
		resp := proto.NewP2POfferResponse(false, findErr, "", "", "", "")
		_ = proto.WriteControlMessage(stream, resp)
		return
	}

	// Check if both NAT types are traversable.
	if !s.isP2PCompatible(req.NATType, peer.P2PNATType) {
		log.Info().
			Str("client_nat", req.NATType).
			Str("peer_nat", peer.P2PNATType).
			Msg("NAT types not compatible for P2P")
		resp := proto.NewP2POfferResponse(false, errP2PNATIncompatible, "", "", "", "")
		_ = proto.WriteControlMessage(stream, resp)
		return
	}

	// Found the target! Return peer info to initiator.
	peer.mu.Lock()
	peerAddr := peer.P2PPublicAddr
	peerNATType := peer.P2PNATType
	peerPublicKey := peer.P2PPublicKey
	peer.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("peer", peer.ID).
		Str("target_subdomain", req.TargetSubdomain).
		Str("peer_addr", peerAddr).
		Str("client_nat", req.NATType).
		Str("peer_nat", peerNATType).
		Bool("has_peer_key", peerPublicKey != "").
		Msg("P2P peer matched")

	// For Symmetric+Symmetric NAT, generate port prediction candidates and
	// send them as a P2PCandidates message before the offer response.
	// Both messages are length-prefixed (proto.WriteControlMessage) so the
	// client can reliably distinguish and decode each one in turn — see
	// Client.sendP2POffer, which now loop-reads framed messages instead of
	// doing a single raw stream.Read() (DP-24).
	bothSymmetric := req.NATType == natTypeSymmetric && peerNATType == natTypeSymmetric
	if bothSymmetric {
		initiatorCandidates := predictCandidatesForSymmetric(req.PublicAddr, req.NATType, 8)
		peerCandidates := predictCandidatesForSymmetric(peerAddr, peerNATType, 8)

		// Send peer's predicted candidates to the initiating client.
		if len(peerCandidates) > 0 {
			candidatesMsg := proto.NewP2PCandidates(peerTunnelID, peerCandidates)
			if err := proto.WriteControlMessage(stream, candidatesMsg); err != nil {
				log.Error().Err(err).Msg("Failed to write P2P candidates")
			}
		}
		// Initiator's predicted candidates will be forwarded to peer in notifyPeerOfP2P.
		_ = initiatorCandidates

		log.Info().
			Str("client", client.ID).
			Str("peer", peer.ID).
			Int("peer_candidates", len(peerCandidates)).
			Int("initiator_candidates", len(initiatorCandidates)).
			Msg("Symmetric+Symmetric NAT: using port prediction for P2P")
	}

	// Send peer info (including ECDH public key) to initiating client.
	resp := proto.NewP2POfferResponse(true, "", peerAddr, peerNATType, peerPublicKey, peerTunnelID)
	if err := proto.WriteControlMessage(stream, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write P2P offer response")
		return
	}

	// Notify the peer about the incoming P2P request (via a new stream).
	go s.notifyPeerOfP2P(peer, client)
}

// isP2PCompatible checks if two NAT types can establish a P2P connection.
// With port prediction, Symmetric-Symmetric is attempted (lower success rate).
func (s *Server) isP2PCompatible(natType1, natType2 string) bool {
	// Any combination that includes at least one non-Symmetric NAT is traversable.
	// Symmetric+Symmetric is also attempted using port prediction heuristics.
	return natPriority(natType1) > 0 && natPriority(natType2) > 0
}

// predictCandidatesForSymmetric generates port candidates for the given
// Symmetric NAT address using the port predictor.
// Returns nil if the address is not Symmetric NAT or prediction is not possible.
func predictCandidatesForSymmetric(addr string, natType string, count int) []string {
	if natType != natTypeSymmetric || addr == "" {
		return nil
	}

	host, portStr, err := splitHostPort(addr)
	if err != nil {
		return nil
	}

	port := 0
	if _, scanErr := fmt.Sscanf(portStr, "%d", &port); scanErr != nil || port <= 0 {
		return nil
	}

	pred := p2p.NewPredictor()
	pred.AddSample(port)
	ports := pred.Predict(count)

	candidates := make([]string, 0, len(ports))
	for _, p := range ports {
		candidates = append(candidates, fmt.Sprintf("%s:%d", host, p))
	}
	return candidates
}

// splitHostPort is a thin wrapper around net.SplitHostPort that returns
// ("", "", err) on failure so callers can handle it cleanly.
func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}

// notifyPeerOfP2P sends a P2P offer notification to the peer client.
// For Symmetric+Symmetric NAT pairs it also sends predicted port candidates
// for the initiator side so the peer can attempt hole punching.
func (s *Server) notifyPeerOfP2P(peer *ClientSession, initiator *ClientSession) {
	initiator.mu.Lock()
	initiatorAddr := initiator.P2PPublicAddr
	initiatorNATType := initiator.P2PNATType
	initiatorPublicKey := initiator.P2PPublicKey
	initiatorTunnelID := initiator.P2PTunnelID
	initiator.mu.Unlock()

	peer.mu.Lock()
	peerNATType := peer.P2PNATType
	peer.mu.Unlock()

	// Open a stream to the peer to notify them.
	stream, err := peer.Mux.OpenStreamContext(context.Background())
	if err != nil {
		log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to open stream to notify peer of P2P")
		return
	}
	defer stream.Close()

	if deadlineErr := stream.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
		log.Error().Err(deadlineErr).Msg("Failed to set P2P notification deadline")
		return
	}

	// For Symmetric+Symmetric, send initiator's predicted candidates first.
	// Framed with proto.WriteControlMessage (length-prefixed) to match the
	// client's Client.handleStream, which loop-reads framed control
	// messages off this notification stream (DP-24).
	if initiatorNATType == natTypeSymmetric && peerNATType == natTypeSymmetric {
		candidates := predictCandidatesForSymmetric(initiatorAddr, initiatorNATType, 8)
		if len(candidates) > 0 {
			candidatesMsg := proto.NewP2PCandidates(initiatorTunnelID, candidates)
			if err := proto.WriteControlMessage(stream, candidatesMsg); err != nil {
				log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to write P2P candidates to peer")
			} else {
				log.Debug().
					Str("peer", peer.ID).
					Int("candidates", len(candidates)).
					Msg("Sent initiator port prediction candidates to peer")
			}
		}
	}

	// Send P2P offer response (as a notification) with the initiator's info and public key.
	// PeerTunnelID is only meaningful for the initiator (addressing outgoing
	// streams to a specific tunnel on the target); the notified side accepts
	// P2P streams generically, so it's left empty here.
	msg := proto.NewP2POfferResponse(true, "", initiatorAddr, initiatorNATType, initiatorPublicKey, "")
	if err := proto.WriteControlMessage(stream, msg); err != nil {
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
		if s.auditLogger != nil {
			s.auditLogger.LogP2PEstablished(client.ID, result.PeerAddr)
		}
	} else {
		log.Info().
			Str("client", client.ID).
			Str("error", result.Error).
			Msg("P2P connection failed, using relay")
		if s.metrics != nil {
			s.metrics.P2PConnectionsTotal.WithLabelValues("fallback").Inc()
		}
		if s.auditLogger != nil {
			s.auditLogger.LogP2PFallback(client.ID, result.Error)
		}
	}
}

// natPriority returns a priority score for a NAT type.
// Higher score = more traversal-friendly = preferred peer.
func natPriority(natType string) int {
	switch natType {
	case natTypeFullCone:
		return 4
	case natTypeRestrictedCone:
		return 3
	case natTypePortRestrictedCone:
		return 2
	case natTypeSymmetric:
		return 1
	default:
		return 0
	}
}

// findPeerBySubdomain looks up the client session that owns targetSubdomain
// (via the router, which is kept in sync with tunnel registration/teardown)
// and the specific TunnelInfo.ID serving it, for a `wormhole connect`
// request from initiator. Returns a non-empty reason string instead of an
// error when no match can be made, suitable for direct use as the
// P2POfferResponse.Error field.
func (s *Server) findPeerBySubdomain(targetSubdomain string, initiator *ClientSession) (peer *ClientSession, tunnelID string, reason string) {
	peer = s.router.LookupSubdomain(targetSubdomain)
	if peer == nil {
		return nil, "", errP2PTargetNotFound
	}
	if peer == initiator {
		return nil, "", errP2PTargetIsSelf
	}

	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.P2PPublicAddr == "" {
		return nil, "", errP2PTargetNotFound
	}
	for _, t := range peer.Tunnels {
		if t.Subdomain == targetSubdomain {
			return peer, t.ID, ""
		}
	}
	return nil, "", errP2PTargetTunnelMeta
}

// serveHTTP serves HTTP requests on the already-constructed s.httpServer
// (built synchronously in Start, before this goroutine is spawned, so
// Shutdown never races on s.httpServer being nil-vs-assigned).
func (s *Server) serveHTTP() {
	defer s.closeWg.Done()

	if err := s.httpServer.Serve(s.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Err(err).Msg("HTTP server error")
	}
}

// serveAdmin serves the admin API on the already-constructed s.adminServer.
func (s *Server) serveAdmin() {
	defer s.closeWg.Done()

	if err := s.adminServer.Serve(s.adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// revokedTokenCleanupInterval controls how often runRevokedTokenCleanup
// sweeps expired entries from the token revocation blacklist (S10).
const revokedTokenCleanupInterval = 10 * time.Minute

// runRevokedTokenCleanup periodically calls Auth.CleanupRevokedTokens()
// until the server shuts down.
func (s *Server) runRevokedTokenCleanup() {
	defer s.closeWg.Done()

	ticker := time.NewTicker(revokedTokenCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			if n := s.authenticator.CleanupRevokedTokens(); n > 0 {
				log.Debug().Int("cleaned", n).Msg("Cleaned up expired revoked-token entries")
			}
		}
	}
}

// auditRetentionSweepInterval controls how often runAuditRetention checks
// for audit events past the configured retention window (A5).
const auditRetentionSweepInterval = 1 * time.Hour

// runAuditRetention periodically deletes audit events older than
// Config.AuditRetentionDays until the server shuts down. It runs once
// immediately on startup (so a server that's rarely restarted doesn't wait
// a full sweep interval before its first cleanup) and then on every tick.
func (s *Server) runAuditRetention() {
	defer s.closeWg.Done()

	sweep := func() {
		store := s.auditLogger.Store()
		if store == nil {
			return
		}
		cutoff := time.Now().AddDate(0, 0, -s.config.AuditRetentionDays)
		n, err := store.DeleteOlderThan(cutoff)
		if err != nil {
			log.Warn().Err(err).Msg("Audit retention sweep failed")
			return
		}
		if n > 0 {
			log.Info().Int64("deleted", n).Int("retention_days", s.config.AuditRetentionDays).
				Msg("Audit retention: purged expired events")
		}
	}

	sweep()

	ticker := time.NewTicker(auditRetentionSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// serveTCPTunnel handles raw TCP connections for a tunnel.
func (s *Server) serveTCPTunnel(ln net.Listener, client *ClientSession, tunnelID string) {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error().Err(err).Msg("Accept TCP tunnel connection failed")
			continue
		}

		go s.handleTCPConnection(conn, client, tunnelID)
	}
}

// errStreamSlotSaturated is returned by tryAcquireStreamSlot when either
// the global or per-client data-plane stream cap (DP-03/DP-27) is full.
var errStreamSlotSaturated = errors.New("server: concurrent stream limit reached")

// tryAcquireStreamSlot reserves one concurrent data-plane stream slot for
// client, enforcing both config.MaxConcurrentStreams (global) and
// config.MaxStreamsPerClient (per-client). On success it returns a release
// func that MUST be called exactly once when the stream finishes. On
// failure it returns errStreamSlotSaturated and a nil release func; the
// caller should reject the request (503 for HTTP, drop for raw TCP)
// instead of queuing, so a saturated server fails fast rather than piling
// up unbounded goroutines/memory behind the limit.
func (s *Server) tryAcquireStreamSlot(client *ClientSession) (release func(), err error) {
	if s.config.MaxConcurrentStreams > 0 && !tryIncrementBounded64(&s.activeDataStreams, int64(s.config.MaxConcurrentStreams)) {
		return nil, errStreamSlotSaturated
	}
	if s.config.MaxStreamsPerClient > 0 && !tryIncrementBounded32(&client.activeDataStreams, int32(s.config.MaxStreamsPerClient)) {
		if s.config.MaxConcurrentStreams > 0 {
			atomic.AddInt64(&s.activeDataStreams, -1)
		}
		return nil, errStreamSlotSaturated
	}

	var released atomic.Bool
	return func() {
		if !released.CompareAndSwap(false, true) {
			return
		}
		if s.config.MaxStreamsPerClient > 0 {
			atomic.AddInt32(&client.activeDataStreams, -1)
		}
		if s.config.MaxConcurrentStreams > 0 {
			atomic.AddInt64(&s.activeDataStreams, -1)
		}
	}, nil
}

// tryIncrementBounded64 atomically increments *counter and returns true,
// unless it is already >= limit, in which case it leaves *counter
// unchanged and returns false.
func tryIncrementBounded64(counter *int64, limit int64) bool {
	for {
		cur := atomic.LoadInt64(counter)
		if cur >= limit {
			return false
		}
		if atomic.CompareAndSwapInt64(counter, cur, cur+1) {
			return true
		}
	}
}

// tryIncrementBounded32 is tryIncrementBounded64 for int32 counters.
func tryIncrementBounded32(counter *int32, limit int32) bool {
	for {
		cur := atomic.LoadInt32(counter)
		if cur >= limit {
			return false
		}
		if atomic.CompareAndSwapInt32(counter, cur, cur+1) {
			return true
		}
	}
}

// handleTCPConnection handles a single raw TCP connection by proxying it through the tunnel.
func (s *Server) handleTCPConnection(conn net.Conn, client *ClientSession, tunnelID string) {
	defer conn.Close()

	// DP-03/DP-27: bound concurrent TCP tunnel streams before opening one.
	release, slotErr := s.tryAcquireStreamSlot(client)
	if slotErr != nil {
		log.Warn().Str("client", client.ID).Msg("TCP tunnel connection rejected: concurrent stream limit reached")
		return
	}
	defer release()

	// Open stream to client.
	stream, err := client.Mux.OpenStreamContext(context.Background())
	if err != nil {
		log.Error().Err(err).Msg("Open stream for TCP tunnel failed")
		return
	}
	defer stream.Close()

	// Send stream request. TunnelID lets the client dispatch to the
	// correct local port in multi-tunnel mode (see Client.resolveLocalAddr).
	streamReq := proto.NewStreamRequest(tunnelID, generateID(), conn.RemoteAddr().String(), proto.ProtocolTCP)
	if err := proto.WriteControlMessage(stream, streamReq); err != nil {
		return
	}

	// Bidirectional proxy. tunnel.Stream has no CloseWrite/CloseRead, so
	// the only way to unblock a still-running direction once its peer
	// direction has errored out is to close both ends (DP-04): waiting
	// on just the first-to-finish direction and relying on the deferred
	// conn.Close()/stream.Close() at function return left the other
	// direction's io loop running (and its goroutine leaked past this
	// function's scope) until that deferred close happened to land.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufPtr := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, readErr := conn.Read(buf)
			if readErr != nil {
				break
			}
			if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		_ = stream.Close()
	}()

	go func() {
		defer wg.Done()
		bufPtr := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, readErr := stream.Read(buf)
			if readErr != nil {
				break
			}
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		_ = conn.Close()
	}()

	wg.Wait()
}

// removeClient removes a client from the server.
func (s *Server) removeClient(client *ClientSession) {
	s.clientLock.Lock()
	delete(s.clients, client.ID)
	s.clientLock.Unlock()

	// Remove all routes via Router.
	s.router.Unregister(client)

	// Remove route from cluster state store.
	if s.stateStore != nil {
		if err := s.stateStore.UnregisterRoute(client.ID); err != nil {
			log.Warn().Err(err).Str("client", client.ID).Msg("Cluster: failed to unregister route from state store")
		}
	}

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

// initStateStore creates the appropriate StateStore based on config.
// Returns nil (single-node) when no cluster backend is configured.
func initStateStore(config Config) StateStore {
	switch config.ClusterStateBackend {
	case ClusterBackendRedis:
		if config.ClusterRedisAddr == "" {
			log.Fatal().Msg("Cluster: ClusterRedisAddr must be set when using redis state backend")
		}
		store, err := NewRedisStateStore(RedisStateStoreConfig{
			Addr:     config.ClusterRedisAddr,
			Password: config.ClusterRedisPassword,
			DB:       config.ClusterRedisDB,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Cluster: failed to connect to Redis state store")
		}
		log.Info().Str("addr", config.ClusterRedisAddr).Msg("Cluster: using Redis state store")
		return store
	case ClusterBackendMemory:
		log.Info().Msg("Cluster: using in-memory state store (single-node)")
		return NewMemoryStateStore()
	default:
		// No clustering — operate as a single-node server.
		return nil
	}
}

// initAuthStore creates the appropriate auth.Store based on config.Persistence.
func initAuthStore(config Config) auth.Store {
	switch config.Persistence {
	case PersistenceSQLite:
		sqliteStore, err := auth.NewSQLiteStore(auth.SQLiteStoreConfig{
			Path:      config.PersistencePath,
			CreateDir: true,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize SQLite store")
		}
		log.Info().
			Str("path", config.PersistencePath).
			Msg("Using SQLite persistence for auth data")
		return sqliteStore
	case PersistenceRedis:
		// H5: default to the cluster Redis connection when a dedicated
		// one isn't configured, so enabling clustering with a Redis
		// backend and shared revocation only requires one Redis address
		// in the common case of using a single instance for both.
		addr, password, db := config.AuthRedisAddr, config.AuthRedisPassword, config.AuthRedisDB
		if addr == "" {
			addr, password, db = config.ClusterRedisAddr, config.ClusterRedisPassword, config.ClusterRedisDB
		}
		if addr == "" {
			log.Fatal().Msg("Auth: --persistence redis requires --auth-redis-addr or --cluster-redis-addr")
		}
		redisStore, err := auth.NewRedisStore(auth.RedisStoreConfig{Addr: addr, Password: password, DB: db})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize Redis auth store")
		}
		log.Info().Str("addr", addr).Msg("Using Redis persistence for auth data (shared token revocation, H5)")
		return redisStore
	default:
		log.Info().Msg("Using in-memory storage for auth data (no persistence)")
		return auth.NewMemoryStore()
	}
}

// initAuditStore creates the appropriate AuditStore based on config.
func initAuditStore(config Config) auth.AuditStore {
	switch config.AuditPersistence {
	case PersistenceSQLite:
		store, err := auth.NewSQLiteAuditStore(auth.SQLiteAuditStoreConfig{
			Path:      config.AuditPath,
			CreateDir: true,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize SQLite audit store")
		}
		log.Info().Str("path", config.AuditPath).Msg("Using SQLite persistence for audit logs")
		return store
	default:
		return auth.NewMemoryAuditStore(config.AuditBufferSize)
	}
}
