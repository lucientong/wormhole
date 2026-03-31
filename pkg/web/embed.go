// Package web provides embedded static resources for the Inspector Web UI.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the embedded filesystem containing the web UI assets.
func FS() fs.FS {
	subFS, err := fs.Sub(distFS, "dist")
	if err != nil {
		// This should never happen with a valid embed directive.
		panic("failed to create sub filesystem: " + err.Error())
	}
	return subFS
}

// Handler returns an http.Handler that serves the embedded web UI.
func Handler() http.Handler {
	return http.FileServer(http.FS(FS()))
}

// HandlerWithPrefix returns an http.Handler that serves the embedded web UI
// with the given URL prefix stripped.
func HandlerWithPrefix(prefix string) http.Handler {
	return http.StripPrefix(prefix, Handler())
}
