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
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/lucientong/wormhole/pkg/version"
	"github.com/rs/zerolog/log"
)

// defaultShutdownTimeout is used when Config.ShutdownTimeout is unset
// (DP-26): it bounds how long Shutdown waits for http.Server.Shutdown
// to drain in-flight HTTP/admin requests before forcing them closed.
const defaultShutdownTimeout = 15 * time.Second

// Server is the wormhole server. It is the composition root for three
// independently-owned components (P3-6 Batch D): TunnelRegistry (which
// clients are connected and what routes they own), ProxyService (data
// forwarding: HTTP/WebSocket/TCP), and P2PBroker (`wormhole connect`
// signaling). Server itself is left holding only connection lifecycle,
// auth/rate-limiting, and the shared cross-cutting concerns (metrics,
// audit, stats) that all three components may need.
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

	tlsManager *TLSManager
	adminAPI   *AdminAPI

	// registry/proxy/broker are held as their concrete types (not the
	// TunnelRegistry/ProxyService/P2PBroker interfaces) since Server is
	// the composition root that constructs them; other consumers
	// (HTTPHandler's successor, AdminAPI, tests) depend on the narrower
	// interfaces where that's useful.
	registry *tunnelRegistry
	proxy    *proxyService
	broker   *p2pBroker

	// Authentication.
	authenticator *auth.Auth
	rateLimiter   *auth.RateLimiter

	// Stats.
	stats Stats

	// Prometheus metrics (nil when EnableMetrics is false).
	metrics *Metrics

	// Audit logger (nil when AuditEnabled is false).
	auditLogger *auth.AuditLogger

	// listenersReady is closed once Start has bound tunnelListener,
	// httpListener and adminListener (and built httpServer/adminServer),
	// giving callers/tests a race-detector-safe way to wait for startup
	// instead of a fixed sleep.
	listenersReady chan struct{}

	// Shutdown.
	closed  uint32
	closeCh chan struct{}
	closeWg sync.WaitGroup

	// rootCtx/rootCancel back the lifecycle context handed to hot-path
	// operations deep in the call tree (auth handshake, port allocation,
	// P2P notification, TCP tunnel stream open — DP-05) so Shutdown can
	// interrupt them immediately instead of leaving them to block out
	// their own fixed timeouts. Set by Start; nil until then, so
	// serverCtx() falls back to context.Background() for callers (mostly
	// unit tests) that invoke handlers directly without Start.
	rootCtx    context.Context
	rootCancel context.CancelFunc
}

// serverCtx returns the server's root lifecycle context (DP-05):
// derived from the ctx passed to Start and canceled as the first step of
// Shutdown, so long-running or blocking operations initiated deep in the
// handler call tree (auth handshake waits, TCP port allocation, P2P
// notification stream opens) observe cancellation immediately instead of
// only via their own fixed timeouts. Returns context.Background() if
// called before Start (e.g. tests invoking handlers directly).
func (s *Server) serverCtx() context.Context {
	if s.rootCtx != nil {
		return s.rootCtx
	}
	return context.Background()
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
	// of the global activeDataStreams cap on ProxyService.
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
	// (see ProxyService.resolveTunnelID), and to clean up the
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
		closeCh:        make(chan struct{}),
		listenersReady: make(chan struct{}),
		stats: Stats{
			StartTime: time.Now(),
		},
	}

	// TunnelRegistry owns the router, client directory, TCP port
	// allocator and (if configured) the cluster state store.
	s.registry = newTunnelRegistry(config)

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

	// ProxyService (data plane) and P2PBroker (`wormhole connect`
	// signaling) both depend on the registry for route/peer resolution,
	// plus the metrics/audit logger just initialized above.
	s.proxy = newProxyService(s.registry.router, s.registry, config, s.metrics, &s.stats, s.serverCtx)
	s.broker = newP2PBroker(s.registry, s.metrics, s.auditLogger, s.serverCtx)

	s.tlsManager = NewTLSManager(config)
	s.adminAPI = NewAdminAPI(s)

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
	// DP-05: derive the root lifecycle context up front so every
	// goroutine spawned below (and the handlers they call, several
	// layers deep) can observe cancellation the instant Shutdown runs,
	// rather than only via their own AuthTimeout/etc. deadlines.
	s.rootCtx, s.rootCancel = context.WithCancel(ctx)

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
		Handler:        s.proxy,
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
	s.registry.StartHeartbeat(ctx)

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
	// DP-05: cancel the root context first so anything blocked on it deep
	// in the handler tree (auth stream accept, TCP port allocation, P2P
	// notify stream open) unblocks immediately instead of running out
	// its own fixed timeout while the rest of Shutdown proceeds below.
	if s.rootCancel != nil {
		s.rootCancel()
	}

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
	s.drainHTTPServers()

	s.closeAncillaryResources()

	// Close all clients.
	for _, client := range s.registry.Snapshot() {
		_ = client.Mux.Close()
	}

	s.closeWg.Wait()
	log.Info().Msg("Server shutdown complete")
	return nil
}

// drainHTTPServers gracefully shuts down the HTTP and admin API servers
// within Config.ShutdownTimeout (or defaultShutdownTimeout), falling back
// to a hard Close for whichever one doesn't drain in time. Split out of
// Shutdown to keep its cyclomatic complexity in check.
func (s *Server) drainHTTPServers() {
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
}

// closeAncillaryResources closes the server's supporting subsystems
// (TunnelRegistry — port allocator + cluster state store —, rate limiter,
// authenticator, audit store) as part of Shutdown. Split out to keep
// Shutdown's cyclomatic complexity in check.
func (s *Server) closeAncillaryResources() {
	s.registry.Close()

	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	if s.authenticator != nil {
		_ = s.authenticator.Close()
	}

	if s.auditLogger != nil {
		if store := s.auditLogger.Store(); store != nil {
			_ = store.Close()
		}
	}
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
	if s.config.MaxClients > 0 && s.registry.Count() >= s.config.MaxClients {
		log.Warn().
			Str("ip", clientIP).
			Int("max_clients", s.config.MaxClients).
			Int("current", s.registry.Count()).
			Msg("Connection rejected: server at capacity")
		_ = conn.Close()
		return
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

	// Register route via TunnelRegistry and (if clustered) the shared
	// state store *before* exposing the client anywhere else. F6/H6/S3: a
	// subdomain conflict here previously only got logged, and the
	// connection was allowed to proceed — but the client had already been
	// told (in the AuthResponse) that it owns `subdomain`, so it would
	// silently receive zero traffic for it while believing it was live.
	// Reject the connection instead so the client's reconnect/retry logic
	// kicks in. On success, registerClientRoute also adds client to the
	// registry's directory.
	if !s.registerClientRoute(client, clientIP) {
		_ = mux.Close()
		return
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

// registerClientRoute is a thin wrapper around
// TunnelRegistry.registerClientRoute that additionally records an audit
// event on rejection — audit logging is a Server-level cross-cutting
// concern the registry itself doesn't need to know about.
func (s *Server) registerClientRoute(client *ClientSession, clientIP string) bool {
	ok, reason := s.registry.registerClientRoute(client)
	if !ok && s.auditLogger != nil {
		s.auditLogger.LogAuthFailure(clientIP, reason)
	}
	return ok
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
	// Accept the auth stream with a timeout, bounded on the short side by
	// AuthTimeout and on the long side by server shutdown (DP-05): a
	// client mid-handshake when the server shuts down no longer holds up
	// the accept for the full AuthTimeout.
	ctx, cancel := context.WithTimeout(s.serverCtx(), s.config.AuthTimeout)
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

	// Read auth request. ReadContext (DP-06) additionally wakes up on ctx
	// cancellation, so a shutdown mid-handshake unblocks this immediately
	// rather than waiting out the AuthTimeout deadline set above.
	buf := make([]byte, 4096)
	n, err := stream.ReadContext(ctx, buf)
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
	if s.registry.stateStore != nil {
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
		s.broker.HandleOffer(client, stream, msg.P2POfferRequest)
	case proto.MessageTypeP2PResult:
		s.broker.HandleResult(client, msg.P2PResult)
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
	scheme := schemeHTTP
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
	if failMsg := s.registry.RegisterTunnel(client, tunnelID, extraSubdomain, req.Hostname, req.PathPrefix); failMsg != "" {
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
		port, ln, allocErr := s.registry.AllocatePort(s.serverCtx())
		if allocErr != nil {
			log.Error().Err(allocErr).Msg("Failed to allocate TCP port")
			s.registry.UnregisterTunnel(client, tunnelID, extraSubdomain, req.Hostname, req.PathPrefix)
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
		go s.proxy.ServeTCPTunnel(ln, client, tunnelID)
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
// owned by a closed tunnel (via TunnelRegistry), and updates tunnel
// metrics. The connection-level default subdomain is left registered
// until full disconnect (removeClient), matching legacy single-tunnel
// behavior.
func (s *Server) releaseTunnelResources(client *ClientSession, removed *TunnelInfo) {
	s.registry.ReleaseTunnel(client, removed)

	atomic.AddUint64(&s.stats.ActiveTunnels, ^uint64(0))
	if s.metrics != nil {
		s.metrics.ActiveTunnels.Dec()
		s.metrics.TunnelDurationSeconds.Observe(time.Since(removed.CreatedAt).Seconds())
	}
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

// removeClient removes a client from the server: TunnelRegistry.RemoveClient
// handles route/directory/TCP-port cleanup, and this wrapper adds the
// Server-level cross-cutting bits (stats, metrics, closing the mux) that
// the registry itself doesn't need to know about.
func (s *Server) removeClient(client *ClientSession) {
	s.registry.RemoveClient(client)

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
