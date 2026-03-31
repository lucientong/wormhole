package cmd

import (
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
	clientP2PEnabled    bool
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
	clientCmd.Flags().BoolVar(&clientP2PEnabled, "p2p", true, "Enable P2P direct connection when possible")

	_ = clientCmd.MarkFlagRequired("local")
}

func runClient(_ *cobra.Command, _ []string) {
	log.Info().
		Str("server", clientServer).
		Int("local_port", clientLocalPort).
		Str("local_host", clientLocalHost).
		Str("subdomain", clientSubdomain).
		Int("inspector_port", clientInspectorPort).
		Bool("p2p", clientP2PEnabled).
		Msg("Starting Wormhole client")

	// TODO: Implement client startup after client package is ready
	log.Warn().Msg("Client implementation pending")
}
