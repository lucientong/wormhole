package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/lucientong/wormhole/pkg/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tunnelsCtrlPort int

// Flags for `wormhole tunnels create` (U1).
var (
	tunnelsCreateLocalPort  int
	tunnelsCreateLocalHost  string
	tunnelsCreateProtocol   string
	tunnelsCreateSubdomain  string
	tunnelsCreateHostname   string
	tunnelsCreatePathPrefix string
)

// tunnelsCmd is the parent command for tunnel management.
var tunnelsCmd = &cobra.Command{
	Use:   "tunnels",
	Short: "Manage active tunnels on a running wormhole client",
	Long: `Query and manage tunnels on a running wormhole client.

The client must be started with --ctrl-port (or ctrl_port in the config file)
to expose its control API.

Examples:
  # List tunnels on the default control port
  wormhole tunnels list

  # Add a new tunnel to an already-running client, without restarting it
  wormhole tunnels create db --local 5432 --protocol tcp

  # Remove a tunnel from a running client
  wormhole tunnels delete db

  # Manage a client on a custom control port
  wormhole tunnels list --ctrl-port 7010`,
}

// tunnelsListCmd lists active tunnels.
var tunnelsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active tunnels on a running client",
	Run:   runTunnelsList,
}

// tunnelsCreateCmd registers a new tunnel on a running client (U1), the
// imperative counterpart to editing the YAML config file and sending
// SIGHUP. Useful for scripting/ad-hoc tunnels without touching the
// client's config file at all.
var tunnelsCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Add a new tunnel to a running client",
	Long: `Register a new tunnel on an already-running wormhole client, without
restarting it or touching its config file.

The tunnel is only known to the running client process — it is not
persisted, so it won't survive a client restart unless you also add it to
the client's config file.`,
	Args: cobra.ExactArgs(1),
	Run:  runTunnelsCreate,
}

// tunnelsDeleteCmd removes an active tunnel from a running client (U1).
var tunnelsDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Remove a tunnel from a running client",
	Args:  cobra.ExactArgs(1),
	Run:   runTunnelsDelete,
}

func init() {
	tunnelsCmd.PersistentFlags().IntVar(&tunnelsCtrlPort, "ctrl-port", 7010, "Control server port of the running client")

	tunnelsCreateCmd.Flags().IntVarP(&tunnelsCreateLocalPort, "local", "l", 0, "Local port to expose (required)")
	tunnelsCreateCmd.Flags().StringVar(&tunnelsCreateLocalHost, "local-host", "127.0.0.1", "Local host to forward to")
	tunnelsCreateCmd.Flags().StringVarP(&tunnelsCreateProtocol, "protocol", "P", "http", "Tunnel protocol: http, https, tcp, ws, grpc")
	tunnelsCreateCmd.Flags().StringVar(&tunnelsCreateSubdomain, "subdomain", "", "Request a specific subdomain")
	tunnelsCreateCmd.Flags().StringVar(&tunnelsCreateHostname, "hostname", "", "Custom hostname for routing")
	tunnelsCreateCmd.Flags().StringVar(&tunnelsCreatePathPrefix, "path-prefix", "", "Path-based routing prefix")

	tunnelsCmd.AddCommand(tunnelsListCmd, tunnelsCreateCmd, tunnelsDeleteCmd)
}

// ctrlRequest sends an HTTP request to the running client's control
// server and returns the response status and body, terminating the
// process via log.Fatal on any transport-level failure (connection
// refused, etc.) — mirroring the existing runTunnelsList behavior so all
// `tunnels` subcommands report the same actionable hint when the control
// server isn't reachable.
func ctrlRequest(method, path string, body io.Reader) (int, []byte) {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", tunnelsCtrlPort, path)

	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to build request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req) // #nosec G107 -- loopback only
	if err != nil {
		log.Fatal().Err(err).
			Int("ctrl_port", tunnelsCtrlPort).
			Msg("Failed to connect to client control server; is the client running with --ctrl-port?")
	}

	respBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		log.Fatal().Err(readErr).Msg("Failed to read response")
	}
	return resp.StatusCode, respBody
}

func runTunnelsList(_ *cobra.Command, _ []string) {
	status, body := ctrlRequest(http.MethodGet, "/tunnels", nil)
	if status != http.StatusOK {
		log.Fatal().Int("status", status).Str("body", string(body)).Msg("Control server returned an error")
	}

	var tunnels []client.TunnelInfo
	if err := json.Unmarshal(body, &tunnels); err != nil {
		log.Fatal().Err(err).Msg("Failed to parse response")
	}

	if len(tunnels) == 0 {
		fmt.Println("No active tunnels.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPROTOCOL\tPUBLIC URL\tLOCAL")
	for _, t := range tunnels {
		local := fmt.Sprintf("%s:%d", t.LocalHost, t.LocalPort)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Name, t.Protocol, t.PublicURL, local)
	}
	_ = w.Flush()
}

func runTunnelsCreate(_ *cobra.Command, args []string) {
	name := args[0]
	if tunnelsCreateLocalPort <= 0 {
		log.Fatal().Msg("--local is required and must be a positive port number")
	}

	reqBody := map[string]any{
		"name":        name,
		"local_port":  tunnelsCreateLocalPort,
		"local_host":  tunnelsCreateLocalHost,
		"protocol":    tunnelsCreateProtocol,
		"subdomain":   tunnelsCreateSubdomain,
		"hostname":    tunnelsCreateHostname,
		"path_prefix": tunnelsCreatePathPrefix,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to encode request")
	}

	status, body := ctrlRequest(http.MethodPost, "/tunnels", bytes.NewReader(data))
	if status != http.StatusCreated {
		log.Fatal().Int("status", status).Str("body", string(body)).Msg("Failed to create tunnel")
	}

	var info client.TunnelInfo
	if err := json.Unmarshal(body, &info); err != nil {
		log.Fatal().Err(err).Msg("Failed to parse response")
	}
	fmt.Printf("Tunnel %q created: %s → %s:%d\n", info.Name, info.PublicURL, info.LocalHost, info.LocalPort)
}

func runTunnelsDelete(_ *cobra.Command, args []string) {
	name := args[0]
	status, body := ctrlRequest(http.MethodDelete, "/tunnels/"+url.PathEscape(name), nil)
	if status != http.StatusNoContent {
		log.Fatal().Int("status", status).Str("body", string(body)).Msg("Failed to delete tunnel")
	}
	fmt.Printf("Tunnel %q deleted.\n", name)
}
