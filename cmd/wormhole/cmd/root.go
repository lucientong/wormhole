// Package cmd provides the CLI commands for Wormhole.
package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/wormhole-tunnel/wormhole/pkg/version"
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
	// Quick mode: wormhole <port> is equivalent to wormhole client --local <port>
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			// Quick mode: wormhole <port>
			// TODO: Implement quick mode after client is ready
			log.Info().Str("port", args[0]).Msg("Quick mode - exposing local port")
			log.Warn().Msg("Quick mode not yet implemented")
			return
		}
		// No args, show help
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
