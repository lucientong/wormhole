// Package version provides build version information.
package version

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Build-time variables, set via ldflags.
var (
	// Version is the semantic version of the build.
	Version = "dev"
	// Commit is the git commit hash of the build.
	Commit = "unknown"
	// BuildTime is the time the binary was built.
	BuildTime = "unknown"
)

// Info contains the version information.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"buildTime"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the version information.
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

// String returns a human-readable version string.
func (i Info) String() string {
	return fmt.Sprintf("Wormhole %s (%s) built at %s with %s for %s/%s",
		i.Version, i.Commit, i.BuildTime, i.GoVersion, i.OS, i.Arch)
}

// Short returns a short version string.
func Short() string {
	return Version
}

// Full returns the full version string.
func Full() string {
	return Get().String()
}

// ErrNotSemver is returned by ParseSemver and Compare when a version
// string doesn't follow the "[v]MAJOR.MINOR.PATCH[-pre][+build]" shape —
// notably including non-release builds like "dev" or an empty string.
// Callers performing compatibility checks should treat this as "unknown,
// don't enforce" rather than a hard failure, since local/dev builds
// intentionally have no meaningful version to compare.
var ErrNotSemver = errors.New("version: not a valid semantic version")

// ParseSemver parses a version string of the form "[v]MAJOR.MINOR.PATCH"
// into its three numeric components. Any pre-release/build metadata
// suffix (starting with "-" or "+") is ignored for comparison purposes.
// It returns ErrNotSemver for anything else, including "dev" or "".
func ParseSemver(v string) (major, minor, patch int, err error) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}

	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("%w: %q", ErrNotSemver, v)
	}

	nums := make([]int, 3)
	for i, p := range parts {
		n, convErr := strconv.Atoi(p)
		if convErr != nil || n < 0 {
			return 0, 0, 0, fmt.Errorf("%w: %q", ErrNotSemver, v)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

// Compare returns -1, 0, or 1 depending on whether a is older than,
// equal to, or newer than b, comparing only the major.minor.patch triple
// (pre-release/build metadata is ignored). It returns ErrNotSemver if
// either input can't be parsed by ParseSemver.
func Compare(a, b string) (int, error) {
	aMajor, aMinor, aPatch, err := ParseSemver(a)
	if err != nil {
		return 0, err
	}
	bMajor, bMinor, bPatch, err := ParseSemver(b)
	if err != nil {
		return 0, err
	}

	if d := aMajor - bMajor; d != 0 {
		return sign(d), nil
	}
	if d := aMinor - bMinor; d != 0 {
		return sign(d), nil
	}
	return sign(aPatch - bPatch), nil
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
