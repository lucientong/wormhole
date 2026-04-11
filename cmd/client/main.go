// Package main provides the standalone client entry point.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/lucientong/wormhole/pkg/client"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// trackSetFlags records which CLI flags were explicitly provided.
func trackSetFlags() *client.FlagValues {
	flags := &client.FlagValues{}
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
		case "tls":
			flags.TLSSet = true
		case "tls-insecure":
			flags.TLSInsecureSet = true
		case "tls-ca":
			flags.TLSCACertSet = true
		}
	})
	return flags
}

func main() {
	// Parse flags.
	serverAddr := flag.String("server", "localhost:7000", "Server address")
	localPort := flag.Int("local", 8080, "Local port to expose")
	localHost := flag.String("local-host", "127.0.0.1", "Local host to forward to")
	subdomain := flag.String("subdomain", "", "Requested subdomain")
	token := flag.String("token", "", "Authentication token")
	inspectorPort := flag.Int("inspector", 0, "Inspector UI port (0 to disable)")
	inspectorHost := flag.String("inspector-host", "127.0.0.1", "Host for inspector UI (default: 127.0.0.1)")
	p2pEnabled := flag.Bool("p2p", true, "Enable P2P direct connection when possible")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS for server connection")
	tlsInsecure := flag.Bool("tls-insecure", false, "Skip TLS certificate verification (dev only)")
	tlsCA := flag.String("tls-ca", "", "Path to custom CA certificate for TLS verification")
	protocol := flag.String("protocol", "http", "Tunnel protocol: http, https, tcp, udp, ws, grpc")
	hostname := flag.String("hostname", "", "Custom hostname for routing")
	pathPrefix := flag.String("path-prefix", "", "Path-based routing prefix")
	saveConfig := flag.Bool("save", false, "Save configuration to ~/.wormhole/config.yaml")
	clearToken := flag.Bool("clear-token", false, "Clear saved token and exit")
	flag.Parse()

	// Configure logging.
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
		With().
		Timestamp().
		Logger()

	// Handle clear-token command.
	if *clearToken {
		if err := client.ClearToken(); err != nil {
			log.Fatal().Err(err).Msg("Failed to clear token")
		}
		log.Info().Msg("Saved token cleared")
		return
	}

	// Load persistent configuration.
	persistent, err := client.LoadPersistentConfig()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load persistent config, using defaults")
		persistent = &client.PersistentConfig{}
	}

	// Track which flags were explicitly set.
	flags := trackSetFlags()

	// Create client config from defaults.
	config := client.DefaultConfig()
	config.ServerAddr = *serverAddr
	config.LocalPort = *localPort
	config.LocalHost = *localHost
	config.Subdomain = *subdomain
	config.Token = *token
	config.InspectorPort = *inspectorPort
	config.InspectorHost = *inspectorHost
	config.P2PEnabled = *p2pEnabled
	config.TLSEnabled = *tlsEnabled
	config.TLSInsecure = *tlsInsecure
	config.TLSCACert = *tlsCA
	config.Protocol = *protocol
	config.Hostname = *hostname
	config.PathPrefix = *pathPrefix

	// Apply persistent config (only for fields not explicitly set via flags).
	client.ApplyPersistentConfig(&config, persistent, flags)

	// Create client.
	c := client.NewClient(config)

	// Start inspector if enabled.
	if err := c.StartInspector(config.InspectorPort); err != nil {
		log.Fatal().Err(err).Msg("Failed to start inspector")
	}

	// Handle shutdown signals.
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Start client.
	if err := c.Start(ctx); err != nil {
		cancel()
		log.Fatal().Err(err).Msg("Client failed")
	}

	// Save config on successful connection if requested.
	if *saveConfig {
		if err := client.UpdatePersistentConfig(&config, true); err != nil {
			log.Warn().Err(err).Msg("Failed to save config")
		} else {
			log.Info().Msg("Configuration saved to ~/.wormhole/config.yaml")
		}
	}

	cancel()
}
