package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

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
	clientCmd.Flags().StringVarP(&clientProtocol, "protocol", "P", "http", "Tunnel protocol: http, https, tcp, udp, ws, grpc")
	clientCmd.Flags().StringVar(&clientHostname, "hostname", "", "Custom hostname for routing")
	clientCmd.Flags().StringVar(&clientPathPrefix, "path-prefix", "", "Path-based routing prefix")

	_ = clientCmd.MarkFlagRequired("local")
}

func runClient(_ *cobra.Command, _ []string) {
	startClient(clientLocalPort, clientServer, clientLocalHost, clientSubdomain,
		clientToken, clientInspectorPort, clientInspectorHost, clientP2PEnabled, clientTLS, clientTLSInsecure, clientTLSCA,
		clientProtocol, clientHostname, clientPathPrefix)
}

// startClient creates and starts a Wormhole client with the given parameters.
// It is shared by both the client subcommand and the root quick-mode handler.
func startClient(localPort int, serverAddr, localHost, subdomain, token string, inspectorPort int, inspectorHost string, p2pEnabled, tlsEnabled, tlsInsecure bool, tlsCA, protocol, hostname, pathPrefix string) {
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
