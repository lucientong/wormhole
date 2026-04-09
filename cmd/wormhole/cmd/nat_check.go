package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/spf13/cobra"
)

var (
	natCheckTimeout int
)

// natCheckCmd represents the nat-check command.
var natCheckCmd = &cobra.Command{
	Use:   "nat-check",
	Short: "Diagnose your NAT type for P2P connectivity",
	Long: `Perform a NAT type diagnosis using STUN servers.

This helps you understand whether P2P direct connections will work
from your current network. The command queries two STUN servers
and classifies your NAT type.

NAT Types (from most to least P2P-friendly):
  • None (Public IP)      - Direct P2P always works
  • Full Cone             - P2P works with any peer
  • Restricted Cone       - P2P works with any peer
  • Port Restricted Cone  - P2P works with any peer
  • Symmetric             - P2P only works if the other peer is NOT Symmetric
  • Unknown               - Could not determine NAT type

Examples:
  # Quick NAT check
  wormhole nat-check

  # With custom timeout
  wormhole nat-check --timeout 15`,
	Run: runNATCheck,
}

func init() {
	natCheckCmd.Flags().IntVar(&natCheckTimeout, "timeout", 10, "Timeout in seconds for STUN discovery")
	rootCmd.AddCommand(natCheckCmd)
}

func runNATCheck(cmd *cobra.Command, _ []string) {
	cmd.Println("🔍 Diagnosing NAT type...")
	cmd.Println()

	// Create STUN client with default config.
	config := p2p.DefaultSTUNConfig()
	client := p2p.NewSTUNClient(config)

	// Run discovery with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(natCheckTimeout)*time.Second)
	defer cancel()

	start := time.Now()
	info, err := client.Discover(ctx)
	elapsed := time.Since(start)

	if err != nil {
		cmd.PrintErrln()
		cmd.PrintErrf("  ❌ NAT discovery failed: %v\n", err)
		cmd.PrintErrln()
		cmd.PrintErrln("  Possible causes:")
		cmd.PrintErrln("    • Firewall blocking outbound UDP traffic")
		cmd.PrintErrln("    • STUN servers unreachable (no internet?)")
		cmd.PrintErrln("    • UDP port 19302 blocked by your network")
		cmd.PrintErrln()
		return
	}

	// Display results.
	traversable := info.Type.IsTraversable()
	cmd.Println("  NAT Discovery Results")
	cmd.Println("  ─────────────────────────────────────")
	cmd.Printf("  NAT Type:      %s\n", info.Type)
	cmd.Printf("  Public IP:     %s\n", info.PublicAddr.IP)
	cmd.Printf("  Public Port:   %d\n", info.PublicAddr.Port)
	cmd.Printf("  Local IP:      %s\n", info.LocalAddr.IP)
	cmd.Printf("  Local Port:    %d\n", info.LocalAddr.Port)
	cmd.Printf("  Traversable:   %s\n", formatBool(traversable))
	cmd.Printf("  Discovery:     %s\n", elapsed.Round(time.Millisecond))
	cmd.Println("  ─────────────────────────────────────")
	cmd.Println()

	// P2P compatibility analysis.
	cmd.Println("  P2P Compatibility")
	cmd.Println("  ─────────────────────────────────────")

	if !traversable {
		cmd.Println("  ⚠️  Your NAT type makes P2P difficult.")
		cmd.Println()
		cmd.Println("  P2P will work ONLY if the other peer has")
		cmd.Println("  a non-Symmetric NAT (Cone type or Public IP).")
		cmd.Println()
		cmd.Println("  If both peers are behind Symmetric NAT,")
		cmd.Println("  traffic will be relayed through the server.")
	} else {
		cmd.Println("  ✅ Your NAT type supports P2P connections!")
		cmd.Println()
		cmd.Printf("  You can establish direct P2P with peers\n")
		cmd.Printf("  behind any NAT type.\n")
	}

	cmd.Println()
	cmd.Println("  Common Network Environments")
	cmd.Println("  ─────────────────────────────────────")
	cmd.Println(formatEnvironmentTable())
	cmd.Println()
}

// formatBool returns a user-friendly boolean representation.
func formatBool(v bool) string {
	if v {
		return "✅ Yes"
	}
	return "❌ No"
}

// formatEnvironmentTable returns a pre-formatted table of common network environments.
func formatEnvironmentTable() string {
	return fmt.Sprintf("  %-22s %-18s %s\n", "Environment", "Typical NAT", "P2P?") +
		fmt.Sprintf("  %-22s %-18s %s\n", "──────────────────────", "──────────────────", "────") +
		fmt.Sprintf("  %-22s %-18s %s\n", "Home broadband", "Port Restricted", "✅") +
		fmt.Sprintf("  %-22s %-18s %s\n", "Carrier-grade NAT", "Symmetric", "⚠️") +
		fmt.Sprintf("  %-22s %-18s %s\n", "Corporate/campus", "Symmetric", "⚠️") +
		fmt.Sprintf("  %-22s %-18s %s\n", "Mobile 4G/5G", "Symmetric", "⚠️") +
		fmt.Sprintf("  %-22s %-18s %s\n", "Cloud VPS/server", "None (Public IP)", "✅") +
		fmt.Sprintf("  %-22s %-18s %s\n", "VPN", "Varies", "❓")
}
