package cmd

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigureLogging_Levels verifies --verbose/--debug select the
// expected zerolog level, restoring the real global logger afterward so
// other tests in this package aren't affected by whichever level ran last.
func TestConfigureLogging_Levels(t *testing.T) {
	origLogger := log.Logger
	origVerbose, origDebug := verbose, debug
	t.Cleanup(func() {
		log.Logger = origLogger
		verbose, debug = origVerbose, origDebug
	})

	verbose, debug = false, false
	configureLogging()
	assert.Equal(t, zerolog.InfoLevel, log.Logger.GetLevel())

	verbose, debug = true, false
	configureLogging()
	assert.Equal(t, zerolog.DebugLevel, log.Logger.GetLevel())

	// --debug takes precedence over --verbose when both are set.
	verbose, debug = true, true
	configureLogging()
	assert.Equal(t, zerolog.TraceLevel, log.Logger.GetLevel())
}

// TestExecute_VersionCommand exercises Execute() end to end (the actual
// entry point cmd/wormhole/main.go calls) via the side-effect-free
// "version" subcommand, rather than testing rootCmd.Execute wiring
// indirectly.
func TestExecute_VersionCommand(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"version"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	require.NoError(t, Execute())
	assert.Contains(t, out.String(), "Wormhole")
}
