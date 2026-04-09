package web

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFS(t *testing.T) {
	fsys := FS()
	require.NotNil(t, fsys)

	// Should be able to open index.html.
	f, err := fsys.Open("index.html")
	require.NoError(t, err)
	defer f.Close()

	stat, err := f.Stat()
	require.NoError(t, err)
	assert.False(t, stat.IsDir())
	assert.Greater(t, stat.Size(), int64(0))
}

func TestFS_OpenAssets(t *testing.T) {
	fsys := FS()

	// Should be able to open assets directory.
	f, err := fsys.Open("assets")
	if err != nil {
		t.Skip("assets directory may not exist in dist")
	}
	defer f.Close()

	stat, err := f.Stat()
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
}

func TestHandler(t *testing.T) {
	h := Handler()
	require.NotNil(t, h)

	// Should serve a valid response at root.
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// http.FileServer may redirect "/" -> "/index.html" (301) or serve directly.
	assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusMovedPermanently)
}

func TestHandlerWithPrefix(t *testing.T) {
	h := HandlerWithPrefix("/ui")
	require.NotNil(t, h)

	// Should serve index.html when prefix is stripped.
	req := httptest.NewRequest("GET", "/ui/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusMovedPermanently)
}

func TestGetContentType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"index.html", "text/html; charset=utf-8"},
		{"style.css", "text/css; charset=utf-8"},
		{"app.js", "application/javascript; charset=utf-8"},
		{"data.json", "application/json; charset=utf-8"},
		{"logo.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"photo.jpeg", "image/jpeg"},
		{"anim.gif", "image/gif"},
		{"icon.svg", "image/svg+xml"},
		{"favicon.ico", "image/x-icon"},
		{"font.woff", "font/woff"},
		{"font.woff2", "font/woff2"},
		{"font.ttf", "font/ttf"},
		{"unknown.xyz", ""},
		{"no-extension", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := getContentType(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewServer_APIRouting(t *testing.T) {
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"api":"ok"}`))
	})

	server := NewServer(ServerConfig{
		APIHandler:      apiHandler,
		FallbackToIndex: true,
	})
	require.NotNil(t, server)

	// API route should go to API handler.
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `{"api":"ok"}`, rr.Body.String())
}

func TestNewServer_APIRouting_NoHandler(t *testing.T) {
	server := NewServer(ServerConfig{
		APIHandler:      nil,
		FallbackToIndex: false,
	})

	// API route with no handler should 404.
	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestNewServer_StaticFiles(t *testing.T) {
	server := NewServer(ServerConfig{
		FallbackToIndex: false,
	})

	// Root should serve index.html.
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "html")
}

func TestNewServer_SPAFallback(t *testing.T) {
	server := NewServer(ServerConfig{
		FallbackToIndex: true,
	})

	// Unknown route should fallback to index.html.
	req := httptest.NewRequest("GET", "/some/unknown/route", nil)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "html")
}

func TestNewServer_SPAFallbackDisabled(t *testing.T) {
	server := NewServer(ServerConfig{
		FallbackToIndex: false,
	})

	// Unknown route should 404.
	req := httptest.NewRequest("GET", "/definitely/not/a/real/path", nil)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestServeFile_IndexHTML(t *testing.T) {
	fsys := FS()

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/")
	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestServeFile_NonExistent(t *testing.T) {
	fsys := FS()

	req := httptest.NewRequest("GET", "/nonexistent.file", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/nonexistent.file")
	assert.False(t, ok)
}

// --- Custom FS implementations for testing serveFile edge cases ---

// dirWithIndexFS is a filesystem that has a directory containing index.html.
// Opening the directory returns a DirEntry; opening dir/index.html returns a file.
type dirWithIndexFS struct{}

type fakeFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (fi fakeFileInfo) Name() string      { return fi.name }
func (fi fakeFileInfo) Size() int64       { return fi.size }
func (fi fakeFileInfo) Mode() fs.FileMode { return 0o644 }
func (fi fakeFileInfo) ModTime() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}
func (fi fakeFileInfo) IsDir() bool      { return fi.isDir }
func (fi fakeFileInfo) Sys() interface{} { return nil }

// fakeDir implements fs.File for a directory.
type fakeDir struct {
	info fakeFileInfo
}

func (d *fakeDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *fakeDir) Read([]byte) (int, error)   { return 0, io.EOF }
func (d *fakeDir) Close() error               { return nil }

// fakeFile implements fs.File but NOT io.ReadSeeker (non-seekable).
type fakeFile struct {
	info   fakeFileInfo
	reader *bytes.Reader
}

func (f *fakeFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *fakeFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *fakeFile) Close() error               { return nil }

// seekableFile implements fs.File AND io.ReadSeeker (seekable).
type seekableFile struct {
	info   fakeFileInfo
	reader *bytes.Reader
}

func (f *seekableFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *seekableFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *seekableFile) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}
func (f *seekableFile) Close() error { return nil }

func (d dirWithIndexFS) Open(name string) (fs.File, error) {
	switch name {
	case "subdir":
		return &fakeDir{info: fakeFileInfo{name: "subdir", isDir: true}}, nil
	case "subdir/index.html":
		content := []byte("<html><body>subdir index</body></html>")
		return &seekableFile{
			info:   fakeFileInfo{name: "index.html", size: int64(len(content))},
			reader: bytes.NewReader(content),
		}, nil
	default:
		return nil, fs.ErrNotExist
	}
}

// TestServeFile_DirectoryWithIndexHTML verifies that when the path is a
// directory, serveFile falls back to serving dir/index.html.
func TestServeFile_DirectoryWithIndexHTML(t *testing.T) {
	fsys := dirWithIndexFS{}

	req := httptest.NewRequest("GET", "/subdir", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/subdir")
	assert.True(t, ok, "should serve subdir/index.html when path is a directory")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "subdir index")
	assert.Equal(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))
}

// dirWithoutIndexFS is a filesystem with a directory that has NO index.html.
type dirWithoutIndexFS struct{}

func (d dirWithoutIndexFS) Open(name string) (fs.File, error) {
	if name == "emptydir" {
		return &fakeDir{info: fakeFileInfo{name: "emptydir", isDir: true}}, nil
	}
	return nil, fs.ErrNotExist
}

// TestServeFile_DirectoryWithoutIndexHTML verifies that when the path is a
// directory without index.html, serveFile returns false.
func TestServeFile_DirectoryWithoutIndexHTML(t *testing.T) {
	fsys := dirWithoutIndexFS{}

	req := httptest.NewRequest("GET", "/emptydir", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/emptydir")
	assert.False(t, ok, "should return false when directory has no index.html")
}

// nonSeekableFS returns files that do NOT implement io.ReadSeeker,
// exercising the io.ReadAll fallback path in serveFile.
type nonSeekableFS struct{}

func (n nonSeekableFS) Open(name string) (fs.File, error) {
	if name == "data.json" {
		content := []byte(`{"status":"ok","data":[1,2,3]}`)
		return &fakeFile{
			info:   fakeFileInfo{name: "data.json", size: int64(len(content))},
			reader: bytes.NewReader(content),
		}, nil
	}
	return nil, fs.ErrNotExist
}

// TestServeFile_NonSeekableFile verifies that when the file does not implement
// io.ReadSeeker, serveFile falls back to reading all data then serving via
// http.ServeContent with a bytes.NewReader.
func TestServeFile_NonSeekableFile(t *testing.T) {
	fsys := nonSeekableFS{}

	req := httptest.NewRequest("GET", "/data.json", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/data.json")
	assert.True(t, ok, "should serve non-seekable file via ReadAll fallback")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"ok"`)
	assert.Equal(t, "application/json; charset=utf-8", rr.Header().Get("Content-Type"))
}

// statErrorFS returns a file whose Stat() fails (not a dir, just error).
type statErrorFS struct{}

type statErrorFile struct{}

func (f *statErrorFile) Stat() (fs.FileInfo, error) {
	return nil, fs.ErrPermission
}
func (f *statErrorFile) Read([]byte) (int, error) { return 0, io.EOF }
func (f *statErrorFile) Close() error             { return nil }

func (s statErrorFS) Open(name string) (fs.File, error) {
	if name == "broken.txt" {
		return &statErrorFile{}, nil
	}
	return nil, fs.ErrNotExist
}

// TestServeFile_StatError verifies that when Stat() returns an error
// (not IsDir), serveFile tries the index.html fallback and returns false
// if that also doesn't exist.
func TestServeFile_StatError(t *testing.T) {
	fsys := statErrorFS{}

	req := httptest.NewRequest("GET", "/broken.txt", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/broken.txt")
	assert.False(t, ok, "should return false when Stat() errors and no index.html fallback")
}

// TestServeFile_RootPath verifies that "/" is mapped to "index.html".
func TestServeFile_RootPath(t *testing.T) {
	// Use the real embedded FS.
	fsys := FS()

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/")
	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")
}

// TestServeFile_ExplicitFile verifies serving an explicit file path.
func TestServeFile_ExplicitFile(t *testing.T) {
	fsys := FS()

	req := httptest.NewRequest("GET", "/index.html", nil)
	rr := httptest.NewRecorder()

	ok := serveFile(rr, req, fsys, "/index.html")
	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, rr.Code)
}
