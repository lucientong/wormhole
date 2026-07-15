package server

// A full-stack end-to-end test with a real Server, a real Client, and a
// real local HTTP service — all three communicating over actual
// `:0`-assigned TCP sockets, no mux-pair fakes. Every other test in this
// package (and pkg/client's) drives one side of the protocol against a
// scripted/fake peer; this is the one test that exercises the entire
// chain a real `wormhole client`/`wormhole server` deployment would, and
// is deliberately kept minimal (a single request/response round trip)
// since its purpose is to catch wiring bugs the component-level tests
// can't see, not to re-verify protocol edge cases already covered
// elsewhere.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/client"
	"github.com/stretchr/testify/require"
)

// TestE2E_ClientToServerToLocalService_HTTPRoundTrip starts a real Server
// and a real Client (relay mode, P2P disabled) against real listeners,
// waits for the client to actually register its tunnel (not just connect
// its mux), then sends a real HTTP request into the server's public HTTP
// listener with the tunnel's assigned Host header and verifies it reaches
// the local echo service and the response comes back unmodified.
func TestE2E_ClientToServerToLocalService_HTTPRoundTrip(t *testing.T) {
	const wantBody = "hello from the local service"

	// The "local service" a real user would be exposing via the tunnel.
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/hello", r.URL.Path)
		w.Header().Set("X-Local-Echo", "1")
		_, _ = w.Write([]byte(wantBody))
	}))
	defer local.Close()
	localHost, localPort := mustSplitHostPort(t, local.Listener.Addr().String())

	srvCfg := DefaultConfig()
	srvCfg.ListenAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AdminAddr = "127.0.0.1:0"
	srvCfg.MuxConfig.KeepAliveInterval = 0
	srv := NewServer(srvCfg)

	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	srvErrCh := make(chan error, 1)
	go func() { srvErrCh <- srv.Start(srvCtx) }()
	<-srv.listenersReady

	tunnelAddr := srv.tunnelListener.Addr().String()
	httpAddr := srv.httpListener.Addr().String()

	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = tunnelAddr
	clientCfg.LocalHost = localHost
	clientCfg.LocalPort = localPort
	clientCfg.Subdomain = "e2e"
	clientCfg.P2PEnabled = false // exercise the relay data plane, not NAT traversal
	clientCfg.MuxConfig.KeepAliveInterval = 0
	clientCfg.ReconnectInterval = 50 * time.Millisecond
	c := client.NewClient(clientCfg)

	// Client.Run's reconnect loop is stopped via Close() (which closes its
	// own closeCh and returns nil), not context cancellation (which would
	// make Start return ctx.Err() instead) — see Client.Close's doc comment.
	defer func() { _ = c.Close() }()
	clientErrCh := make(chan error, 1)
	go func() { clientErrCh <- c.Start(context.Background()) }()

	// Wait for the tunnel to actually be registered cluster-side (not just
	// the client's mux connecting) before sending traffic at it.
	require.Eventually(t, func() bool {
		return srv.registry.router.LookupSubdomain("e2e") != nil
	}, 5*time.Second, 10*time.Millisecond, "client's tunnel never registered with the server")

	req, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/hello", nil)
	require.NoError(t, err)
	req.Host = "e2e." + srvCfg.Domain

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, wantBody, string(body))
	require.Equal(t, "1", resp.Header.Get("X-Local-Echo"))

	require.NoError(t, c.Close())
	require.NoError(t, <-clientErrCh)
	srvCancel()
	require.NoError(t, <-srvErrCh)
}

// mustSplitHostPort splits a "host:port" address into (host, port),
// failing the test on a malformed address.
func mustSplitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}
