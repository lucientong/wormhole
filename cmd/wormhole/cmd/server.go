package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	serverPort       int
	serverHost       string
	serverDomain     string
	serverTLSEnabled bool
	serverTLSCert    string
	serverTLSKey     string
	serverAdminPort  int
)

// serverCmd represents the server command
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
  wormhole server --tls --domain tunnel.example.com`,
	Run: runServer,
}

func init() {
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 7000, "Port to listen on for client connections")
	serverCmd.Flags().StringVar(&serverHost, "host", "0.0.0.0", "Host to bind to")
	serverCmd.Flags().StringVarP(&serverDomain, "domain", "d", "", "Domain for generating tunnel URLs")
	serverCmd.Flags().BoolVar(&serverTLSEnabled, "tls", false, "Enable TLS (auto-cert with Let's Encrypt if domain is set)")
	serverCmd.Flags().StringVar(&serverTLSCert, "cert", "", "Path to TLS certificate file")
	serverCmd.Flags().StringVar(&serverTLSKey, "key", "", "Path to TLS private key file")
	serverCmd.Flags().IntVar(&serverAdminPort, "admin-port", 7001, "Port for admin API")
}

func runServer(cmd *cobra.Command, args []string) {
	log.Info().
		Str("host", serverHost).
		Int("port", serverPort).
		Str("domain", serverDomain).
		Bool("tls", serverTLSEnabled).
		Msg("Starting Wormhole server")

	// TODO: Implement server startup after server package is ready
	log.Warn().Msg("Server implementation pending")
}
