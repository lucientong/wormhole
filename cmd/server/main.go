// Package main provides the server entry point.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Parse flags.
	requireAuth := flag.Bool("require-auth", false, "Require authentication for client connections")
	authTokens := flag.String("auth-tokens", "", "Comma-separated list of valid authentication tokens")
	authSecret := flag.String("auth-secret", "", "HMAC secret for signed tokens (min 16 chars)")
	adminToken := flag.String("admin-token", "", "Token for admin API authentication")
	flag.Parse()

	// Configure logging
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
		With().
		Timestamp().
		Logger()

	// Create server
	config := DefaultConfig()
	config.RequireAuth = *requireAuth
	if *authTokens != "" {
		config.AuthTokens = strings.Split(*authTokens, ",")
	}
	config.AuthSecret = *authSecret
	config.AdminToken = *adminToken

	server := NewServer(config)

	// Handle shutdown signals
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Start server
	if err := server.Start(ctx); err != nil {
		cancel()
		log.Fatal().Err(err).Msg("Server failed")
	}
	cancel()
}
