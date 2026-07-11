package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	clientServer        string
	clientLocalPort     int
	clientLocalHost     string
	clientSubdomain     string
	clientToken         string
	clientInspectorPort int
	clientInspectorHost string
	clientP2PEnabled    bool
	clientTLS           bool
	clientTLSInsecure   bool
	clientTLSCA         string
	clientProtocol      string
	clientHostname      string
	clientPathPrefix    string
	clientConfigFile    string
	clientCtrlPort      int
)

// clientCmd represents the client command.
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start the Wormhole client to expose a local service",
	Long: `Start the Wormhole client to connect to a server and expose a local service.

The client establishes a tunnel to the server and forwards incoming requests
to your local service. It supports HTTP, WebSocket, gRPC, and raw TCP.

Examples:
  # Expose local port 8080 using default server
  wormhole client --local 8080

  # Expose local service with custom subdomain
  wormhole client --local 8080 --subdomain myapp

  # Connect to a specific server
  wormhole client --server tunnel.example.com:7000 --local 8080

  # Enable traffic inspector
  wormhole client --local 8080 --inspector 4040

  # Use team token for authentication
  wormhole client --local 8080 --token your-team-token`,
	Run: runClient,
}

func init() {
	clientCmd.Flags().StringVarP(&clientServer, "server", "s", "localhost:7000", "Server address to connect to")
	clientCmd.Flags().IntVarP(&clientLocalPort, "local", "l", 0, "Local port to expose")
	clientCmd.Flags().StringVar(&clientLocalHost, "local-host", "127.0.0.1", "Local host to forward to")
	clientCmd.Flags().StringVar(&clientSubdomain, "subdomain", "", "Request a specific subdomain")
	clientCmd.Flags().StringVarP(&clientToken, "token", "t", "", "Team token for authentication")
	clientCmd.Flags().IntVar(&clientInspectorPort, "inspector", 0, "Port for traffic inspector UI (0 to disable)")
	clientCmd.Flags().StringVar(&clientInspectorHost, "inspector-host", "127.0.0.1", "Host for inspector UI (default: 127.0.0.1)")
	clientCmd.Flags().BoolVar(&clientP2PEnabled, "p2p", true, "Enable P2P direct connection when possible")
	clientCmd.Flags().BoolVar(&clientTLS, "tls", false, "Enable TLS for server connection")
	clientCmd.Flags().BoolVar(&clientTLSInsecure, "tls-insecure", false, "Skip TLS certificate verification (dev only)")
	clientCmd.Flags().StringVar(&clientTLSCA, "tls-ca", "", "Path to custom CA certificate for TLS verification")
	clientCmd.Flags().StringVarP(&clientProtocol, "protocol", "P", "http", "Tunnel protocol: http, https, tcp, ws, grpc")
	clientCmd.Flags().StringVar(&clientHostname, "hostname", "", "Custom hostname for routing")
	clientCmd.Flags().StringVar(&clientPathPrefix, "path-prefix", "", "Path-based routing prefix")
	clientCmd.Flags().StringVarP(&clientConfigFile, "config", "c", "", "Path to YAML config file (enables multi-tunnel mode)")
	clientCmd.Flags().IntVar(&clientCtrlPort, "ctrl-port", 0, "Local control server port for 'wormhole tunnels list' (0 = disabled)")
	// Note: --local/--config requiredness is validated manually in runClient
	// (not via MarkFlagsOneRequired) so that neither flag being set can fall
	// through to default tunnel-config-file discovery (U3) before erroring.
}

func runClient(cmd *cobra.Command, _ []string) {
	cfgFile := clientConfigFile
	if cfgFile == "" && !cmd.Flags().Changed("local") {
		if defaultPath := client.DefaultTunnelConfigPath(); defaultPath != "" {
			if _, err := os.Stat(defaultPath); err == nil {
				log.Info().Str("path", defaultPath).Msg("No --local/--config given; using default tunnel config file")
				cfgFile = defaultPath
			}
		}
	}

	if cfgFile != "" {
		runClientFromConfig(cfgFile, clientCtrlPort)
		return
	}
	// --local is required when not using --config and no default config file exists.
	if !cmd.Flags().Changed("local") {
		log.Fatal().Msg("required flag(s) \"local\" not set (or use --config for multi-tunnel mode, or create ~/.wormhole/wormhole.yml)")
	}
	if err := client.ValidateProtocolString(clientProtocol); err != nil {
		log.Fatal().Err(err).Msg("Invalid --protocol")
	}
	startClient(clientLocalPort, clientServer, clientLocalHost, clientSubdomain,
		clientToken, cmd.Flags().Changed("token"), clientInspectorPort, clientInspectorHost, clientP2PEnabled, clientTLS, clientTLSInsecure, clientTLSCA,
		clientProtocol, clientHostname, clientPathPrefix, clientCtrlPort)
}

// runClientFromConfig starts the client using a YAML config file.
func runClientFromConfig(cfgPath string, ctrlPort int) {
	fc, err := client.LoadFileConfig(cfgPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", cfgPath).Msg("Failed to load config file")
	}

	cfg := fc.ToClientConfig(client.DefaultConfig())
	if ctrlPort > 0 {
		cfg.CtrlPort = ctrlPort
	}
	resolveClientCredentials(&cfg, fc.Token != "")

	c := client.NewClient(cfg)

	if err := c.StartControlServer(cfg.CtrlHost, cfg.CtrlPort); err != nil {
		log.Fatal().Err(err).Msg("Failed to start control server")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				log.Info().Msg("SIGHUP received — reloading config file")
				newFC, loadErr := client.LoadFileConfig(cfgPath)
				if loadErr != nil {
					log.Error().Err(loadErr).Msg("Failed to reload config file; keeping current config")
					continue
				}
				newCfg := newFC.ToClientConfig(client.DefaultConfig())
				c.ReloadTunnels(ctx, newCfg.Tunnels)
			default:
				log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
				cancel()
				return
			}
		}
	}()

	if err := c.Start(ctx); err != nil {
		cancel()
		_ = c.Close()
		log.Fatal().Err(err).Msg("Client failed")
	}
	cancel()
	_ = c.Close()
}

// startClient creates and starts a Wormhole client with the given parameters.
// It is shared by both the client subcommand and the root quick-mode handler.
func startClient(localPort int, serverAddr, localHost, subdomain, token string, tokenExplicitlySet bool, inspectorPort int, inspectorHost string, p2pEnabled, tlsEnabled, tlsInsecure bool, tlsCA, protocol, hostname, pathPrefix string, ctrlPort int) {
	config := client.DefaultConfig()
	config.ServerAddr = serverAddr
	config.LocalPort = localPort
	config.LocalHost = localHost
	config.Subdomain = subdomain
	config.Token = token
	config.InspectorPort = inspectorPort
	config.InspectorHost = inspectorHost
	config.P2PEnabled = p2pEnabled
	config.TLSEnabled = tlsEnabled
	config.TLSInsecure = tlsInsecure
	config.TLSCACert = tlsCA
	config.Protocol = protocol
	config.Hostname = hostname
	config.PathPrefix = pathPrefix
	config.CtrlPort = ctrlPort
	resolveClientCredentials(&config, tokenExplicitlySet)

	c := client.NewClient(config)

	// Start inspector if enabled.
	if err := c.StartInspector(config.InspectorPort); err != nil {
		log.Fatal().Err(err).Msg("Failed to start inspector")
	}

	// Start control server if enabled.
	if err := c.StartControlServer(config.CtrlHost, config.CtrlPort); err != nil {
		log.Fatal().Err(err).Msg("Failed to start control server")
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

	if err := c.Start(ctx); err != nil {
		cancel()
		// Graceful shutdown: send CloseRequest to server before exiting.
		_ = c.Close()
		log.Fatal().Err(err).Msg("Client failed")
	}
	cancel()
	// Graceful shutdown: send CloseRequest to server before exiting.
	_ = c.Close()
}

// resolveClientCredentials loads saved OIDC credentials for cfg.ServerAddr
// when no --token was explicitly given (and the YAML config didn't set one
// either), transparently refreshing an expired access token if a
// refresh_token is available (S5, O1-O4). It also wires cfg.OnAuthFailure so
// a token that expires mid-session or across a reconnect is refreshed
// automatically without requiring the user to run `wormhole login` again.
func resolveClientCredentials(cfg *client.Config, tokenExplicitlySet bool) {
	if tokenExplicitlySet || cfg.Token != "" {
		// Explicit --token, or a token already set from a YAML config file,
		// takes precedence over saved login credentials.
		return
	}

	creds, err := auth.LoadCredentials("", cfg.ServerAddr)
	if err == nil {
		if !creds.IsExpired() {
			cfg.Token = creds.Token
			log.Info().Str("server", cfg.ServerAddr).Msg("Loaded saved credentials from wormhole login")
		} else if refreshed := refreshSavedCredentials(context.Background(), creds); refreshed != nil {
			cfg.Token = refreshed.Token
		} else {
			log.Warn().Str("server", cfg.ServerAddr).
				Msg("Saved credentials expired and could not be refreshed; run 'wormhole login' again")
		}
	}

	// Wire automatic refresh for tokens that expire mid-session or across a
	// reconnect, regardless of whether the initial load above succeeded
	// (credentials may be created later via `wormhole login` while this
	// client keeps running).
	cfg.OnAuthFailure = func(ctx context.Context) (string, bool) {
		latest, loadErr := auth.LoadCredentials("", cfg.ServerAddr)
		if loadErr != nil {
			return "", false
		}
		refreshed := refreshSavedCredentials(ctx, latest)
		if refreshed == nil {
			return "", false
		}
		return refreshed.Token, true
	}
}

// refreshSavedCredentials attempts an OAuth2 refresh_token grant for creds
// and, on success, persists the renewed credentials to disk. Returns nil if
// creds can't be refreshed or the refresh request fails.
func refreshSavedCredentials(ctx context.Context, creds *auth.Credentials) *auth.Credentials {
	if !creds.CanRefresh() {
		return nil
	}

	result, err := auth.RefreshAccessToken(ctx, creds.TokenEndpoint, creds.ClientID, creds.RefreshToken)
	if err != nil {
		log.Warn().Err(err).Str("server", creds.Server).Msg("Failed to refresh access token")
		return nil
	}

	token := result.Token()
	expiresAt := auth.ParseJWTExpiry(token)
	if expiresAt.IsZero() && result.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}

	updated := auth.Credentials{
		Server:        creds.Server,
		Token:         token,
		ExpiresAt:     expiresAt,
		RefreshToken:  result.RefreshToken,
		OIDCIssuer:    creds.OIDCIssuer,
		ClientID:      creds.ClientID,
		TokenEndpoint: creds.TokenEndpoint,
	}
	if saveErr := auth.SaveCredentialsFull("", updated); saveErr != nil {
		log.Warn().Err(saveErr).Msg("Failed to persist refreshed credentials")
	}
	log.Info().Str("server", creds.Server).Msg("Refreshed access token using saved refresh token")
	return &updated
}
