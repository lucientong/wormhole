package version

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	info := Get()

	assert.Equal(t, Version, info.Version)
	assert.Equal(t, Commit, info.Commit)
	assert.Equal(t, BuildTime, info.BuildTime)
	assert.Equal(t, runtime.Version(), info.GoVersion)
	assert.Equal(t, runtime.GOOS, info.OS)
	assert.Equal(t, runtime.GOARCH, info.Arch)
}

func TestGet_WithCustomValues(t *testing.T) {
	// Save originals.
	origVersion := Version
	origCommit := Commit
	origBuildTime := BuildTime
	defer func() {
		Version = origVersion
		Commit = origCommit
		BuildTime = origBuildTime
	}()

	// Set custom values.
	Version = "1.2.3"
	Commit = "abc123"
	BuildTime = "2025-01-01T00:00:00Z"

	info := Get()
	assert.Equal(t, "1.2.3", info.Version)
	assert.Equal(t, "abc123", info.Commit)
	assert.Equal(t, "2025-01-01T00:00:00Z", info.BuildTime)
}

func TestInfo_String(t *testing.T) {
	info := Info{
		Version:   "1.0.0",
		Commit:    "abc123",
		BuildTime: "2025-01-01",
		GoVersion: "go1.22.0",
		OS:        "linux",
		Arch:      "amd64",
	}

	s := info.String()
	assert.Contains(t, s, "Wormhole 1.0.0")
	assert.Contains(t, s, "abc123")
	assert.Contains(t, s, "2025-01-01")
	assert.Contains(t, s, "go1.22.0")
	assert.Contains(t, s, "linux/amd64")
}

func TestShort(t *testing.T) {
	origVersion := Version
	defer func() { Version = origVersion }()

	Version = "2.0.0"
	assert.Equal(t, "2.0.0", Short())
}

func TestShort_DefaultDev(t *testing.T) {
	origVersion := Version
	defer func() { Version = origVersion }()

	Version = "dev"
	assert.Equal(t, "dev", Short())
}

func TestFull(t *testing.T) {
	s := Full()
	require.NotEmpty(t, s)
	assert.Contains(t, s, "Wormhole")
	assert.Contains(t, s, Version)
}

func TestFull_ContainsAllFields(t *testing.T) {
	origVersion := Version
	origCommit := Commit
	origBuildTime := BuildTime
	defer func() {
		Version = origVersion
		Commit = origCommit
		BuildTime = origBuildTime
	}()

	Version = "3.0.0"
	Commit = "deadbeef"
	BuildTime = "2025-06-15"

	s := Full()
	assert.Contains(t, s, "3.0.0")
	assert.Contains(t, s, "deadbeef")
	assert.Contains(t, s, "2025-06-15")
	assert.Contains(t, s, runtime.Version())
	assert.Contains(t, s, runtime.GOOS+"/"+runtime.GOARCH)
}

func TestGet_DefaultValues(t *testing.T) {
	// When not set via ldflags, defaults should be present.
	info := Get()
	assert.NotEmpty(t, info.Version)
	assert.NotEmpty(t, info.Commit)
	assert.NotEmpty(t, info.BuildTime)
	assert.NotEmpty(t, info.GoVersion)
	assert.NotEmpty(t, info.OS)
	assert.NotEmpty(t, info.Arch)
}
