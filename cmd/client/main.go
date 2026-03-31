// Package main provides the client entry point.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Parse flags
	serverAddr := flag.String("server", "localhost:7000", "Server address")
	localPort := flag.Int("local", 8080, "Local port to expose")
	localHost := flag.String("local-host", "127.0.0.1", "Local host to forward to")
	subdomain := flag.String("subdomain", "", "Requested subdomain")
	token := flag.String("token", "", "Authentication token")
	inspectorPort := flag.Int("inspector", 0, "Inspector UI port (0 to disable)")
	p2pEnabled := flag.Bool("p2p", true, "Enable P2P direct connection when possible")
	flag.Parse()

	// Configure logging
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
		With().
		Timestamp().
		Logger()

	// Create client config
	config := DefaultConfig()
	config.ServerAddr = *serverAddr
	config.LocalPort = *localPort
	config.LocalHost = *localHost
	config.Subdomain = *subdomain
	config.Token = *token
	config.InspectorPort = *inspectorPort
	config.P2PEnabled = *p2pEnabled

	// Create client
	client := NewClient(config)

	// Start inspector if enabled.
	if err := client.StartInspector(config.InspectorPort); err != nil {
		log.Fatal().Err(err).Msg("Failed to start inspector")
	}

	// Handle shutdown signals
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Start client
	if err := client.Start(ctx); err != nil {
		cancel()
		log.Fatal().Err(err).Msg("Client failed")
	}
	cancel()
}
