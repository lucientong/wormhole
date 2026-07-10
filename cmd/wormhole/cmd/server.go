package cmd

import (
	"context"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/lucientong/wormhole/pkg/server"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// defaultDomain is the fallback domain when none is specified.
const defaultDomain = "localhost"

var (
	serverPort               int
	serverHost               string
	serverDomain             string
	serverTLSEnabled         bool
	serverTLSCert            string
	serverTLSKey             string
	serverHTTPPort           int
	serverAdminPort          int
	serverRequireAuth        bool
	serverAuthTokens         []string
	serverAuthSecret         string
	serverAdminToken         string
	serverPersistence        string
	serverPersistencePath    string
	serverTunnelTLS          bool
	serverAdminHost          string
	serverMaxClients         int
	serverMaxTunnelsPerCli   int
	serverAuditEnabled       bool
	serverAuditPersistence   string
	serverAuditPath          string
	serverAuditBufferSize    int
	serverAuditRetentionDays int
	serverOIDCIssuer         string
	serverOIDCClientID       string
	serverOIDCTeamClaim      string
	serverOIDCRoleClaim      string

	// Cluster / HA flags.
	serverClusterNodeID        string
	serverClusterNodeAddr      string
	serverClusterStateBackend  string
	serverClusterRedisAddr     string
	serverClusterRedisPassword string
	serverClusterRedisDB       int
	serverClusterSecret        string
	serverAuthRedisAddr        string
	serverAuthRedisPassword    string
	serverAuthRedisDB          int
)

// serverCmd represents the server command.
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Wormhole server",
	Long: `Start the Wormhole server to accept client connections and proxy requests.

The server should be run on a machine with a public IP address. It listens for
client connections and forwards incoming HTTP/TCP traffic to the appropriate
connected client.

Examples:
  # Start server on default port
  wormhole server

  # Start server on custom port with domain
  wormhole server --port 7000 --domain tunnel.example.com

  # Start server with TLS
  wormhole server --tls --cert /path/to/cert.pem --key /path/to/key.pem

  # Start server with Let's Encrypt auto-cert
  wormhole server --tls --domain tunnel.example.com

  # Start server with authentication
  wormhole server --require-auth --auth-tokens token1,token2

  # Start server with HMAC signed tokens
  wormhole server --require-auth --auth-secret my-secret-key-at-least-16

  # Start server with admin API protection
  wormhole server --admin-token my-admin-secret

  # Start server with SQLite persistence for auth data
  wormhole server --require-auth --auth-secret my-secret --persistence sqlite

  # Specify custom database path
  wormhole server --require-auth --auth-secret my-secret --persistence sqlite --persistence-path /var/lib/wormhole/data.db`,
	Run: runServer,
}

func init() {
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 7000, "Port to listen on for client connections")
	serverCmd.Flags().StringVar(&serverHost, "host", "0.0.0.0", "Host to bind to")
	serverCmd.Flags().StringVarP(&serverDomain, "domain", "d", "", "Domain for generating tunnel URLs (env: WORMHOLE_DOMAIN)")
	serverCmd.Flags().BoolVar(&serverTLSEnabled, "tls", false, "Enable TLS (auto-cert with Let's Encrypt if domain is set)")
	serverCmd.Flags().StringVar(&serverTLSCert, "cert", "", "Path to TLS certificate file")
	serverCmd.Flags().StringVar(&serverTLSKey, "key", "", "Path to TLS private key file")
	serverCmd.Flags().IntVar(&serverHTTPPort, "http-port", 80, "Port for HTTP traffic")
	serverCmd.Flags().IntVar(&serverAdminPort, "admin-port", 7001, "Port for admin API")
	serverCmd.Flags().BoolVar(&serverRequireAuth, "require-auth", false, "Require authentication for client connections")
	serverCmd.Flags().StringSliceVar(&serverAuthTokens, "auth-tokens", nil, "Comma-separated list of valid authentication tokens")
	serverCmd.Flags().StringVar(&serverAuthSecret, "auth-secret", "", "HMAC secret for signed tokens (min 16 chars)")
	serverCmd.Flags().StringVar(&serverAdminToken, "admin-token", "", "Token for admin API authentication")
	serverCmd.Flags().StringVar(&serverPersistence, "persistence", "memory", "Storage backend for auth data: memory (default), sqlite, or redis (H5: shared team/revocation state across cluster nodes)")
	serverCmd.Flags().StringVar(&serverPersistencePath, "persistence-path", "", "Path to SQLite database (default: ~/.wormhole/wormhole.db)")
	serverCmd.Flags().BoolVar(&serverTunnelTLS, "tunnel-tls", false, "Enable TLS for the tunnel control listener (default: same as --tls, or true when --require-auth is set with a real --domain)")
	serverCmd.Flags().StringVar(&serverAdminHost, "admin-host", "127.0.0.1", "Host for admin API (default: 127.0.0.1 for safety)")
	serverCmd.Flags().IntVar(&serverMaxClients, "max-clients", 1000, "Maximum concurrent clients (0 = unlimited)")
	serverCmd.Flags().IntVar(&serverMaxTunnelsPerCli, "max-tunnels-per-client", 0, "Maximum tunnels per client (0 = unlimited)")
	serverCmd.Flags().BoolVar(&serverAuditEnabled, "audit", false, "Enable structured audit logging")
	serverCmd.Flags().StringVar(&serverAuditPersistence, "audit-persistence", "memory", "Audit storage backend: memory (default) or sqlite")
	serverCmd.Flags().StringVar(&serverAuditPath, "audit-path", "", "Path to SQLite audit database (default: ~/.wormhole/audit.db)")
	serverCmd.Flags().IntVar(&serverAuditBufferSize, "audit-buffer-size", 10_000, "In-memory audit ring buffer size (events)")
	serverCmd.Flags().IntVar(&serverAuditRetentionDays, "audit-retention-days", 90, "Delete audit events older than this many days (0 = keep forever)")
	serverCmd.Flags().StringVar(&serverOIDCIssuer, "oidc-issuer", "", "OIDC issuer URL for JWT validation (e.g. https://accounts.google.com)")
	serverCmd.Flags().StringVar(&serverOIDCClientID, "oidc-client-id", "", "OAuth2 client ID for OIDC audience validation")
	serverCmd.Flags().StringVar(&serverOIDCTeamClaim, "oidc-team-claim", "email", "JWT claim to use as team name (default: email)")
	serverCmd.Flags().StringVar(&serverOIDCRoleClaim, "oidc-role-claim", "", "JWT claim to use as Wormhole role (optional)")

	// Cluster / HA flags.
	serverCmd.Flags().StringVar(&serverClusterNodeID, "cluster-node-id", "", "Unique ID for this node in the cluster (default: hostname)")
	serverCmd.Flags().StringVar(&serverClusterNodeAddr, "cluster-node-addr", "", "Address other nodes use to reach this node (host:port)")
	serverCmd.Flags().StringVar(&serverClusterStateBackend, "cluster-backend", "", "Cluster state backend: memory or redis (default: disabled)")
	serverCmd.Flags().StringVar(&serverClusterRedisAddr, "cluster-redis-addr", "", "Redis address for cluster state (e.g. localhost:6379)")
	serverCmd.Flags().StringVar(&serverClusterRedisPassword, "cluster-redis-password", "", "Redis AUTH password")
	serverCmd.Flags().IntVar(&serverClusterRedisDB, "cluster-redis-db", 0, "Redis database number")
	serverCmd.Flags().StringVar(&serverClusterSecret, "cluster-secret", "", "Shared secret validated on requests forwarded between cluster nodes (S1)")
	serverCmd.Flags().StringVar(&serverAuthRedisAddr, "auth-redis-addr", "", "Redis address for shared auth/revocation state when --persistence=redis (default: --cluster-redis-addr)")
	serverCmd.Flags().StringVar(&serverAuthRedisPassword, "auth-redis-password", "", "Redis AUTH password for --auth-redis-addr (default: --cluster-redis-password)")
	serverCmd.Flags().IntVar(&serverAuthRedisDB, "auth-redis-db", 0, "Redis database number for --auth-redis-addr (default: --cluster-redis-db)")
}

// applyTunnelTLSDefaults implements S4: it decides whether the tunnel
// control channel should default to TLS, independently of the operator's
// --tunnel-tls flag, and enables AutoTLS when needed to serve it.
//
// Defaults (only applied when --tunnel-tls was not explicitly passed):
//   - Mirror --tls, as before.
//   - Additionally default to true when --require-auth is set and a real
//     domain is configured — the control channel carries auth tokens, so
//     requiring auth without encrypting it would let those tokens leak to
//     any on-path observer. A real domain is required because AutoTLS (the
//     only certificate source available here) can't issue for "localhost".
//
// If, after defaulting, --require-auth is still on but the channel ends up
// plaintext (no domain, no manual cert/key), a warning is logged so the
// operator knows tokens are transmitted unencrypted.
func applyTunnelTLSDefaults(cmd *cobra.Command, config *server.Config) {
	hasRealDomain := config.Domain != "" && config.Domain != defaultDomain

	config.TunnelTLSEnabled = serverTunnelTLS
	if !cmd.Flags().Changed("tunnel-tls") {
		config.TunnelTLSEnabled = config.TLSEnabled || (config.RequireAuth && hasRealDomain)
	}

	// Enable auto-TLS when either the HTTP or the tunnel listener needs
	// TLS, a real domain is set, and no manual cert/key was provided.
	if (config.TLSEnabled || config.TunnelTLSEnabled) && hasRealDomain &&
		config.TLSCertFile == "" && config.TLSKeyFile == "" {
		config.AutoTLS = true
	}

	if config.RequireAuth && !config.TunnelTLSEnabled {
		log.Warn().Msg("--require-auth is enabled but the tunnel control channel is not using TLS " +
			"(no domain for auto-TLS and no --cert/--key provided) — authentication tokens will be " +
			"transmitted in plaintext. Set --domain to a real hostname or pass --cert/--key, or use " +
			"--tunnel-tls with manual certs, to encrypt the control channel.")
	}
}

// buildServerConfig assembles a server.Config from CLI flags.
func buildServerConfig(cmd *cobra.Command) server.Config {
	// Support WORMHOLE_DOMAIN environment variable as default for --domain.
	if serverDomain == "" {
		if envDomain := os.Getenv("WORMHOLE_DOMAIN"); envDomain != "" {
			serverDomain = envDomain
		} else {
			serverDomain = defaultDomain
		}
	}

	config := server.DefaultConfig()
	config.ListenAddr = net.JoinHostPort(serverHost, strconv.Itoa(serverPort))
	config.HTTPAddr = net.JoinHostPort(serverHost, strconv.Itoa(serverHTTPPort))
	config.AdminAddr = net.JoinHostPort(serverAdminHost, strconv.Itoa(serverAdminPort))
	config.Domain = serverDomain
	config.TLSEnabled = serverTLSEnabled
	config.TLSCertFile = serverTLSCert
	config.TLSKeyFile = serverTLSKey
	config.RequireAuth = serverRequireAuth
	config.AuthTokens = serverAuthTokens
	config.AuthSecret = serverAuthSecret
	config.AdminToken = serverAdminToken
	config.PersistencePath = serverPersistencePath
	config.MaxClients = serverMaxClients
	config.MaxTunnelsPerClient = serverMaxTunnelsPerCli

	applyTunnelTLSDefaults(cmd, &config)

	switch serverPersistence {
	case "sqlite":
		config.Persistence = server.PersistenceSQLite
	case "redis":
		config.Persistence = server.PersistenceRedis
	}
	config.AuthRedisAddr = serverAuthRedisAddr
	config.AuthRedisPassword = serverAuthRedisPassword
	config.AuthRedisDB = serverAuthRedisDB

	config.AuditEnabled = serverAuditEnabled
	config.AuditPath = serverAuditPath
	config.AuditBufferSize = serverAuditBufferSize
	config.AuditRetentionDays = serverAuditRetentionDays
	if serverAuditPersistence == "sqlite" {
		config.AuditPersistence = server.PersistenceSQLite
	}

	config.OIDCIssuer = serverOIDCIssuer
	config.OIDCClientID = serverOIDCClientID
	config.OIDCTeamClaim = serverOIDCTeamClaim
	config.OIDCRoleClaim = serverOIDCRoleClaim

	config.ClusterNodeID = serverClusterNodeID
	config.ClusterNodeAddr = serverClusterNodeAddr
	config.ClusterStateBackend = serverClusterStateBackend
	config.ClusterRedisAddr = serverClusterRedisAddr
	config.ClusterRedisPassword = serverClusterRedisPassword
	config.ClusterRedisDB = serverClusterRedisDB
	config.ClusterSecret = serverClusterSecret

	return config
}

func runServer(cmd *cobra.Command, _ []string) {
	config := buildServerConfig(cmd)

	// Warn if admin API is exposed on non-loopback without a token.
	if config.AdminToken == "" && serverAdminHost != "127.0.0.1" && serverAdminHost != "::1" && serverAdminHost != "localhost" {
		log.Warn().
			Str("admin_addr", config.AdminAddr).
			Msg("WARNING: Admin API is bound to a non-loopback address without --admin-token; " +
				"unauthenticated access will be restricted to loopback clients only")
	}

	srv := server.NewServer(config)

	// Handle shutdown signals.
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	if err := srv.Start(ctx); err != nil {
		cancel()
		log.Fatal().Err(err).Msg("Server failed")
	}
	cancel()
}
