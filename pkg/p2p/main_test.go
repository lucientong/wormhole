package p2p

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestMain(m *testing.M) {
	// Suppress debug/info logs during tests to keep output readable.
	// Set WORMHOLE_TEST_LOG=debug to re-enable verbose logging.
	level := zerolog.WarnLevel
	if os.Getenv("WORMHOLE_TEST_LOG") == "debug" {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)
	os.Exit(m.Run())
}
