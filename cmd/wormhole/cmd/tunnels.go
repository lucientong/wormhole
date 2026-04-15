package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tunnelsCtrlPort int

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

  # List tunnels on a custom control port
  wormhole tunnels list --ctrl-port 7010`,
}

// tunnelsListCmd lists active tunnels.
var tunnelsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active tunnels on a running client",
	Run:   runTunnelsList,
}

func init() {
	tunnelsCmd.PersistentFlags().IntVar(&tunnelsCtrlPort, "ctrl-port", 7010, "Control server port of the running client")
	tunnelsCmd.AddCommand(tunnelsListCmd)
}

func runTunnelsList(_ *cobra.Command, _ []string) {
	url := fmt.Sprintf("http://127.0.0.1:%d/tunnels", tunnelsCtrlPort)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to build request")
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 -- loopback only
	if err != nil {
		log.Fatal().Err(err).
			Int("ctrl_port", tunnelsCtrlPort).
			Msg("Failed to connect to client control server; is the client running with --ctrl-port?")
	}

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		log.Fatal().Err(readErr).Msg("Failed to read response")
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatal().
			Int("status", resp.StatusCode).
			Str("body", string(body)).
			Msg("Control server returned an error")
	}

	type tunnelInfo struct {
		Name      string `json:"name"`
		TunnelID  string `json:"tunnel_id"`
		PublicURL string `json:"public_url"`
		LocalPort int    `json:"local_port"`
		LocalHost string `json:"local_host"`
		Protocol  string `json:"protocol"`
		TCPPort   uint32 `json:"tcp_port,omitempty"`
	}

	var tunnels []tunnelInfo
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
