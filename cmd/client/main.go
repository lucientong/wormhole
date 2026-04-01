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
	saveConfig := flag.Bool("save", false, "Save configuration to ~/.wormhole/config.yaml")
	clearToken := flag.Bool("clear-token", false, "Clear saved token and exit")
	flag.Parse()

	// Configure logging
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
		With().
		Timestamp().
		Logger()

	// Handle clear-token command.
	if *clearToken {
		if err := ClearToken(); err != nil {
			log.Fatal().Err(err).Msg("Failed to clear token")
		}
		log.Info().Msg("Saved token cleared")
		return
	}

	// Load persistent configuration.
	persistent, err := LoadPersistentConfig()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load persistent config, using defaults")
		persistent = &PersistentConfig{}
	}

	// Track which flags were explicitly set.
	flags := &FlagValues{}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			flags.ServerAddrSet = true
		case "token":
			flags.TokenSet = true
		case "subdomain":
			flags.SubdomainSet = true
		case "inspector":
			flags.InspectorPortSet = true
		case "p2p":
			flags.P2PEnabledSet = true
		}
	})

	// Create client config from defaults.
	config := DefaultConfig()
	config.ServerAddr = *serverAddr
	config.LocalPort = *localPort
	config.LocalHost = *localHost
	config.Subdomain = *subdomain
	config.Token = *token
	config.InspectorPort = *inspectorPort
	config.P2PEnabled = *p2pEnabled

	// Apply persistent config (only for fields not explicitly set via flags).
	ApplyPersistentConfig(&config, persistent, flags)

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

	// Save config on successful connection if requested.
	if *saveConfig {
		if err := UpdatePersistentConfig(&config, true); err != nil {
			log.Warn().Err(err).Msg("Failed to save config")
		} else {
			log.Info().Msg("Configuration saved to ~/.wormhole/config.yaml")
		}
	}

	cancel()
}
