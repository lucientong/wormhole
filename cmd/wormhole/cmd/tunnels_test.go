package cmd

// NT-04: `wormhole tunnels create/delete/list` had zero coverage — these
// exercise the success path of each against a real httptest control
// server (the same one *client.Client.StartControlServer exposes), the
// way a real running client would answer them. The log.Fatal error
// paths (control server unreachable, non-2xx status) are deliberately
// left untested here: they call os.Exit via zerolog, which would abort
// the test binary — not something worth restructuring runtime code to
// avoid just for coverage.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/lucientong/wormhole/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLoopbackHost is the local-host fixture value used throughout this
// file's TunnelInfo/flag fixtures — pulled into a constant instead of
// repeating the literal so goconst doesn't flag it across cases.
const testLoopbackHost = "127.0.0.1"

// withCtrlServer starts an httptest server and points the "tunnels"
// subcommands' --ctrl-port at it for the duration of the test.
func withCtrlServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	origPort := tunnelsCtrlPort
	tunnelsCtrlPort = port
	t.Cleanup(func() { tunnelsCtrlPort = origPort })
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. The read side is drained concurrently (not
// after fn returns) so this doesn't deadlock once fn writes more than the
// pipe's OS buffer can hold.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	outCh := make(chan string, 1)
	go func() {
		buf, _ := io.ReadAll(r)
		outCh <- string(buf)
	}()

	fn()

	require.NoError(t, w.Close())
	os.Stdout = orig
	return <-outCh
}

func TestRunTunnelsList_PrintsActiveTunnels(t *testing.T) {
	withCtrlServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/tunnels", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]client.TunnelInfo{
			{Name: "web", Protocol: "http", PublicURL: "https://web.example.com", LocalHost: testLoopbackHost, LocalPort: 8080},
		})
	})

	out := captureStdout(t, func() { runTunnelsList(nil, nil) })
	assert.Contains(t, out, "web")
	assert.Contains(t, out, "https://web.example.com")
	assert.Contains(t, out, testLoopbackHost+":8080")
}

func TestRunTunnelsList_NoActiveTunnels(t *testing.T) {
	withCtrlServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]client.TunnelInfo{})
	})

	out := captureStdout(t, func() { runTunnelsList(nil, nil) })
	assert.Contains(t, out, "No active tunnels")
}

func TestRunTunnelsCreate_Success(t *testing.T) {
	withCtrlServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/tunnels", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "db", body["name"])
		assert.Equal(t, float64(5432), body["local_port"])
		assert.Equal(t, "tcp", body["protocol"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(client.TunnelInfo{
			Name: "db", Protocol: "tcp", PublicURL: "tcp://db.example.com:12345", LocalHost: testLoopbackHost, LocalPort: 5432,
		})
	})

	origPort, origHost, origProto := tunnelsCreateLocalPort, tunnelsCreateLocalHost, tunnelsCreateProtocol
	t.Cleanup(func() {
		tunnelsCreateLocalPort, tunnelsCreateLocalHost, tunnelsCreateProtocol = origPort, origHost, origProto
	})
	tunnelsCreateLocalPort = 5432
	tunnelsCreateLocalHost = testLoopbackHost
	tunnelsCreateProtocol = "tcp"

	out := captureStdout(t, func() { runTunnelsCreate(nil, []string{"db"}) })
	assert.Contains(t, out, `"db" created`)
	assert.Contains(t, out, "tcp://db.example.com:12345")
}

func TestRunTunnelsDelete_Success(t *testing.T) {
	withCtrlServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/tunnels/db", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)
		w.WriteHeader(http.StatusNoContent)
	})

	out := captureStdout(t, func() { runTunnelsDelete(nil, []string{"db"}) })
	assert.Contains(t, out, `"db" deleted`)
}
