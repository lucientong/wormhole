// Package main provides the standalone server entry point.
package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/lucientong/wormhole/pkg/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Network flags.
	port := flag.Int("port", 7000, "Tunnel listen port")
	host := flag.String("host", "", "Bind address for all listeners (e.g. 0.0.0.0)")
	domain := flag.String("domain", "localhost", "Base domain for tunnel URLs")
	httpPort := flag.Int("http-port", 80, "HTTP listener port")
	adminPort := flag.Int("admin-port", 7001, "Admin API listener port")

	// TLS flags.
	tlsEnabled := flag.Bool("tls", false, "Enable TLS")
	certFile := flag.String("cert", "", "TLS certificate file path")
	keyFile := flag.String("key", "", "TLS private key file path")

	// Auth flags.
	requireAuth := flag.Bool("require-auth", false, "Require authentication for client connections")
	authTokens := flag.String("auth-tokens", "", "Comma-separated list of valid authentication tokens")
	authSecret := flag.String("auth-secret", "", "HMAC secret for signed tokens (min 16 chars)")
	adminToken := flag.String("admin-token", "", "Token for admin API authentication")

	// Persistence flags.
	persistence := flag.String("persistence", "memory", "Storage backend: memory or sqlite")
	persistencePath := flag.String("persistence-path", "", "SQLite database path (defaults to ~/.wormhole/wormhole.db)")

	flag.Parse()

	// Configure logging.
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
		With().
		Timestamp().
		Logger()

	// Build server config.
	config := server.DefaultConfig()
	config.ListenAddr = net.JoinHostPort(*host, strconv.Itoa(*port))
	config.HTTPAddr = net.JoinHostPort(*host, strconv.Itoa(*httpPort))
	config.AdminAddr = net.JoinHostPort(*host, strconv.Itoa(*adminPort))
	config.Domain = *domain
	config.TLSEnabled = *tlsEnabled
	config.TLSCertFile = *certFile
	config.TLSKeyFile = *keyFile
	config.RequireAuth = *requireAuth
	if *authTokens != "" {
		config.AuthTokens = strings.Split(*authTokens, ",")
	}
	config.AuthSecret = *authSecret
	config.AdminToken = *adminToken

	switch *persistence {
	case "sqlite":
		config.Persistence = server.PersistenceSQLite
	default:
		config.Persistence = server.PersistenceMemory
	}
	config.PersistencePath = *persistencePath

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

	// Start server.
	if err := srv.Start(ctx); err != nil {
		cancel()
		log.Fatal().Err(err).Msg("Server failed")
	}
	cancel()
}
