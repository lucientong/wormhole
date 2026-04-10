// Package cmd provides the CLI commands for Wormhole.
package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/lucientong/wormhole/pkg/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	// Flags.
	verbose bool
	debug   bool
)

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "wormhole",
	Short: "A zero-config tunnel tool to expose local services to the internet",
	Long: `Wormhole is a zero-config tunnel tool that folds network space like a wormhole,
allowing developers to expose local services to the internet with a single command.

Examples:
  # Expose local port 8080 to the internet
  wormhole 8080

  # Start as a server (requires public IP)
  wormhole server --port 7000

  # Connect to a specific server
  wormhole client --server wormhole.example.com:7000 --local 8080`,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		// Configure logging
		configureLogging()
	},
	// Quick mode: wormhole <port> is equivalent to wormhole client --local <port>.
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil // show help
		}
		if len(args) > 1 {
			return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
		}
		port, err := strconv.Atoi(args[0])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %s (must be 1-65535)", args[0])
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			port, _ := strconv.Atoi(args[0])
			log.Info().Int("port", port).Msg("Quick mode - exposing local port")
			startClient(port, "localhost:7000", "127.0.0.1", "", "", 0, true)
			return
		}
		// No args, show help.
		_ = cmd.Help()
	},
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug mode")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)
}

// configureLogging sets up the zerolog logger.
func configureLogging() {
	// Use console writer for pretty output
	output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}

	// Set log level
	level := zerolog.InfoLevel
	if verbose {
		level = zerolog.DebugLevel
	}
	if debug {
		level = zerolog.TraceLevel
	}

	log.Logger = zerolog.New(output).
		With().
		Timestamp().
		Logger().
		Level(level)
}

// versionCmd shows version information.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, _ []string) {
		info := version.Get()
		cmd.Printf("Wormhole %s\n", info.Version)
		cmd.Printf("  Commit:     %s\n", info.Commit)
		cmd.Printf("  Built:      %s\n", info.BuildTime)
		cmd.Printf("  Go version: %s\n", info.GoVersion)
		cmd.Printf("  OS/Arch:    %s/%s\n", info.OS, info.Arch)
	},
}
