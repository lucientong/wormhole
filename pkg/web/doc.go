// Package web provides embedded static resources for the Inspector Web UI.
//
// The web package uses Go's embed directive to bundle the compiled frontend
// assets directly into the binary, enabling zero-dependency deployment.
//
// # Usage
//
//	// Serve embedded static files
//	http.Handle("/", web.Handler())
//
//	// Or get the filesystem directly
//	fs := web.FS()
package web
