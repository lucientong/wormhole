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
	serverPort             int
	serverHost             string
	serverDomain           string
	serverTLSEnabled       bool
	serverTLSCert          string
	serverTLSKey           string
	serverHTTPPort         int
	serverAdminPort        int
	serverRequireAuth      bool
	serverAuthTokens       []string
	serverAuthSecret       string
	serverAdminToken       string
	serverPersistence      string
	serverPersistencePath  string
	serverTunnelTLS        bool
	serverAdminHost        string
	serverMaxClients       int
	serverMaxTunnelsPerCli int
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
	serverCmd.Flags().StringVar(&serverPersistence, "persistence", "memory", "Storage backend: memory (default) or sqlite")
	serverCmd.Flags().StringVar(&serverPersistencePath, "persistence-path", "", "Path to SQLite database (default: ~/.wormhole/wormhole.db)")
	serverCmd.Flags().BoolVar(&serverTunnelTLS, "tunnel-tls", false, "Enable TLS for the tunnel control listener (default: same as --tls)")
	serverCmd.Flags().StringVar(&serverAdminHost, "admin-host", "127.0.0.1", "Host for admin API (default: 127.0.0.1 for safety)")
	serverCmd.Flags().IntVar(&serverMaxClients, "max-clients", 1000, "Maximum concurrent clients (0 = unlimited)")
	serverCmd.Flags().IntVar(&serverMaxTunnelsPerCli, "max-tunnels-per-client", 0, "Maximum tunnels per client (0 = unlimited)")
}

func runServer(cmd *cobra.Command, _ []string) {
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

	// Tunnel TLS defaults to the global TLS setting unless explicitly overridden.
	config.TunnelTLSEnabled = serverTunnelTLS
	if !cmd.Flags().Changed("tunnel-tls") {
		config.TunnelTLSEnabled = config.TLSEnabled
	}

	// Enable auto-TLS when TLS is enabled, a real domain is set, and no manual cert/key provided.
	if config.TLSEnabled && config.Domain != "" && config.Domain != defaultDomain &&
		config.TLSCertFile == "" && config.TLSKeyFile == "" {
		config.AutoTLS = true
	}

	switch serverPersistence {
	case "sqlite":
		config.Persistence = server.PersistenceSQLite
	default:
		config.Persistence = server.PersistenceMemory
	}

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
