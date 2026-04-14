package client

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestMain(m *testing.M) {
	level := zerolog.WarnLevel
	if os.Getenv("WORMHOLE_TEST_LOG") == "debug" {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)
	os.Exit(m.Run())
}
