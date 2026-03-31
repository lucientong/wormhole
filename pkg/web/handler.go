package web

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// ServerConfig holds configuration for the web server.
type ServerConfig struct {
	// APIHandler handles /api/* routes.
	APIHandler http.Handler
	// FallbackToIndex enables SPA routing (returns index.html for unknown routes).
	FallbackToIndex bool
}

// NewServer creates a new HTTP handler that serves both the web UI and API.
func NewServer(config ServerConfig) http.Handler {
	webFS := FS()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Route API requests to the API handler.
		if strings.HasPrefix(path, "/api/") {
			if config.APIHandler != nil {
				config.APIHandler.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}

		// Try to serve static file.
		if serveFile(w, r, webFS, path) {
			return
		}

		// SPA fallback: serve index.html for unknown routes.
		if config.FallbackToIndex {
			if serveFile(w, r, webFS, "/index.html") {
				return
			}
		}

		http.NotFound(w, r)
	})
}

// serveFile attempts to serve a file from the filesystem.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, path string) bool {
	// Clean the path.
	if path == "/" {
		path = "index.html"
	} else {
		path = strings.TrimPrefix(path, "/")
	}

	// Try to open the file.
	f, err := fsys.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Get file info.
	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		// If it's a directory, try index.html.
		indexPath := path + "/index.html"
		f2, err := fsys.Open(indexPath)
		if err != nil {
			return false
		}
		defer f2.Close()
		stat, err = f2.Stat()
		if err != nil {
			return false
		}
		path = indexPath
		f = f2
	}

	// Set content type based on extension.
	contentType := getContentType(path)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	// Serve the file.
	rs, ok := f.(readSeeker)
	if !ok {
		// Fallback: read all and write directly.
		data, readErr := io.ReadAll(f)
		if readErr != nil {
			return false
		}
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), bytes.NewReader(data))
		return true
	}
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), rs)
	return true
}

type readSeeker interface {
	Read(p []byte) (n int, err error)
	Seek(offset int64, whence int) (int64, error)
}

// getContentType returns the content type for a file based on its extension.
func getContentType(path string) string {
	ext := strings.ToLower(path[strings.LastIndex(path, ".")+1:])
	types := map[string]string{
		"html":  "text/html; charset=utf-8",
		"css":   "text/css; charset=utf-8",
		"js":    "application/javascript; charset=utf-8",
		"json":  "application/json; charset=utf-8",
		"png":   "image/png",
		"jpg":   "image/jpeg",
		"jpeg":  "image/jpeg",
		"gif":   "image/gif",
		"svg":   "image/svg+xml",
		"ico":   "image/x-icon",
		"woff":  "font/woff",
		"woff2": "font/woff2",
		"ttf":   "font/ttf",
	}
	return types[ext]
}
