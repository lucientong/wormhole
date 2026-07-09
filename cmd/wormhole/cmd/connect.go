package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lucientong/wormhole/pkg/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	connectServer      string
	connectLocalPort   int
	connectLocalHost   string
	connectToken       string
	connectTLS         bool
	connectTLSInsecure bool
	connectTLSCA       string
)

// connectCmd implements `wormhole connect`, which reaches another wormhole
// client's exposed service directly over P2P — bypassing the server relay
// for the actual traffic entirely (the server is only used to signal and
// match the two clients). Unlike `wormhole client`, this command doesn't
// expose anything of its own; it just opens a local listener that forwards
// to the peer.
var connectCmd = &cobra.Command{
	Use:   "connect <target-subdomain>",
	Short: "Connect directly to another wormhole client's tunnel via P2P (bypasses the server relay)",
	Long: `Connect directly to another wormhole client's exposed service via a P2P
UDP channel, without the traffic ever passing through the server relay.

Both sides must run wormhole against the same server with --p2p enabled
(the default). The target must currently be connected and have registered
a tunnel under the given subdomain. If a direct P2P path can't be
established (e.g. incompatible NAT types on both sides), this command
fails outright — unlike normal tunnels, connect mode has no relay fallback,
since the server has no tunnel registered for this session to relay
through.

Examples:
  # Reach the peer exposing subdomain "myapp" on localhost:9000
  wormhole connect myapp --local 9000

  # Connect to a peer on a specific server
  wormhole connect myapp --server tunnel.example.com:7000 --local 9000`,
	Args: cobra.ExactArgs(1),
	Run:  runConnect,
}

func init() {
	connectCmd.Flags().StringVarP(&connectServer, "server", "s", "localhost:7000", "Server address to connect to")
	connectCmd.Flags().IntVarP(&connectLocalPort, "local", "l", 0, "Local port to listen on (required)")
	connectCmd.Flags().StringVar(&connectLocalHost, "local-host", "127.0.0.1", "Local host to bind the listener to")
	connectCmd.Flags().StringVarP(&connectToken, "token", "t", "", "Authentication token")
	connectCmd.Flags().BoolVar(&connectTLS, "tls", false, "Enable TLS for the server control connection")
	connectCmd.Flags().BoolVar(&connectTLSInsecure, "tls-insecure", false, "Skip TLS certificate verification (dev only)")
	connectCmd.Flags().StringVar(&connectTLSCA, "tls-ca", "", "Path to custom CA certificate for TLS verification")
	_ = connectCmd.MarkFlagRequired("local")
}

func runConnect(cmd *cobra.Command, args []string) {
	target := args[0]

	cfg := client.DefaultConfig()
	cfg.ServerAddr = connectServer
	cfg.LocalPort = connectLocalPort
	cfg.LocalHost = connectLocalHost
	cfg.Token = connectToken
	cfg.ConnectTarget = target
	cfg.TLSEnabled = connectTLS
	cfg.TLSInsecure = connectTLSInsecure
	cfg.TLSCACert = connectTLSCA
	// Connect mode has no relay fallback — P2P is the only transport, so it
	// must stay on regardless of any global default.
	cfg.P2PEnabled = true
	resolveClientCredentials(&cfg, cmd.Flags().Changed("token"))

	c := client.NewClient(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	fmt.Printf("Connecting to %s, requesting P2P match for %q...\n", cfg.ServerAddr, target)

	if err := c.Start(ctx); err != nil {
		cancel()
		_ = c.Close()
		log.Fatal().Err(err).Msg("wormhole connect failed")
	}
	cancel()
	_ = c.Close()
}
