// Package version provides build version information.
package version

import (
	"fmt"
	"runtime"
)

// Build-time variables, set via ldflags
var (
	// Version is the semantic version of the build
	Version = "dev"
	// Commit is the git commit hash of the build
	Commit = "unknown"
	// BuildTime is the time the binary was built
	BuildTime = "unknown"
)

// Info contains the version information
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"buildTime"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the version information
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a human-readable version string
func (i Info) String() string {
	return fmt.Sprintf("Wormhole %s (%s) built at %s with %s for %s/%s",
		i.Version, i.Commit, i.BuildTime, i.GoVersion, i.OS, i.Arch)
}

// Short returns a short version string
func Short() string {
	return Version
}

// Full returns the full version string
func Full() string {
	return Get().String()
}
