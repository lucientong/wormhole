package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRefreshTokenServer starts a minimal OAuth2 token endpoint that only
// serves the refresh_token grant, for exercising refreshSavedCredentials
// end-to-end without hitting a real IdP.
func newRefreshTokenServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveClientCredentials_ExplicitTokenTakesPrecedence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// A previously-saved OIDC credential for the same server must never
	// override an explicitly-provided --token.
	require.NoError(t, auth.SaveCredentials("", "tunnel.example.com:7000", "saved-token", time.Now().Add(time.Hour)))

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000", Token: "explicit-token"}
	resolveClientCredentials(cfg, true)

	assert.Equal(t, "explicit-token", cfg.Token, "explicit --token must not be overwritten by saved credentials")
	// An explicit token bypasses the OIDC credential store entirely, so
	// there's no saved refresh material to wire an auto-refresh callback to.
	assert.Nil(t, cfg.OnAuthFailure)
}

func TestResolveClientCredentials_LoadsValidSavedCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	require.NoError(t, auth.SaveCredentials("", "tunnel.example.com:7000", "saved-token", time.Now().Add(time.Hour)))

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000"}
	resolveClientCredentials(cfg, false)

	assert.Equal(t, "saved-token", cfg.Token)
}

func TestResolveClientCredentials_NoSavedCredentials_LeavesTokenEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000"}
	resolveClientCredentials(cfg, false)

	assert.Empty(t, cfg.Token)
	assert.NotNil(t, cfg.OnAuthFailure)
}

func TestResolveClientCredentials_ExpiredWithRefresh_AutoRefreshes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := newRefreshTokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "old-refresh-token", r.FormValue("refresh_token"))
		assert.Equal(t, "my-client", r.FormValue("client_id"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "renewed-token",
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		})
	})

	creds := auth.Credentials{
		Server:        "tunnel.example.com:7000",
		Token:         "expired-token",
		ExpiresAt:     time.Now().Add(-time.Hour),
		RefreshToken:  "old-refresh-token",
		ClientID:      "my-client",
		TokenEndpoint: srv.URL,
	}
	require.NoError(t, auth.SaveCredentialsFull("", creds))

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000"}
	resolveClientCredentials(cfg, false)

	assert.Equal(t, "renewed-token", cfg.Token, "expired credentials with a refresh token should be silently renewed")

	// The renewed credentials must also be persisted so future runs (and
	// OnAuthFailure) see the refreshed token without hitting the IdP again.
	reloaded, err := auth.LoadCredentials("", "tunnel.example.com:7000")
	require.NoError(t, err)
	assert.Equal(t, "renewed-token", reloaded.Token)
	assert.Equal(t, "new-refresh-token", reloaded.RefreshToken)
}

func TestResolveClientCredentials_ExpiredWithoutRefreshCapability_LeavesTokenEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Expired and missing RefreshToken/ClientID/TokenEndpoint — CanRefresh() is false.
	require.NoError(t, auth.SaveCredentials("", "tunnel.example.com:7000", "expired-token", time.Now().Add(-time.Hour)))

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000"}
	resolveClientCredentials(cfg, false)

	assert.Empty(t, cfg.Token, "an expired token that can't be refreshed must not be used")
}

func TestResolveClientCredentials_OnAuthFailure_RefreshesLatestSavedCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := newRefreshTokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mid-session-renewed-token",
			"expires_in":   3600,
		})
	})

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000"}
	resolveClientCredentials(cfg, false)
	require.NotNil(t, cfg.OnAuthFailure)

	// Simulate `wormhole login` having refreshed credentials on disk after
	// the client started (OnAuthFailure re-reads from disk each time).
	creds := auth.Credentials{
		Server:        "tunnel.example.com:7000",
		Token:         "stale-token",
		RefreshToken:  "refresh-me",
		ClientID:      "my-client",
		TokenEndpoint: srv.URL,
	}
	require.NoError(t, auth.SaveCredentialsFull("", creds))

	newToken, ok := cfg.OnAuthFailure(context.Background())
	assert.True(t, ok)
	assert.Equal(t, "mid-session-renewed-token", newToken)
}

func TestResolveClientCredentials_OnAuthFailure_NoCredentials_ReturnsFalse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &client.Config{ServerAddr: "tunnel.example.com:7000"}
	resolveClientCredentials(cfg, false)

	_, ok := cfg.OnAuthFailure(context.Background())
	assert.False(t, ok)
}

// NT-04: reloadClientConfig is what runClientFromConfig's SIGHUP handler
// calls; testing it directly (rather than sending a real os.Signal to a
// live client process) covers the same reload logic without needing a
// running server connection — ReloadTunnels itself is a documented
// no-op when the client isn't currently connected.

func TestReloadClientConfig_ValidFile_ReloadsTunnels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wormhole.yml")
	require.NoError(t, os.WriteFile(path, []byte(`
server: tunnel.example.com:7000
tunnels:
  web:
    local_port: 8080
  api:
    local_port: 9090
`), 0o600))

	c := client.NewClient(client.DefaultConfig())
	err := reloadClientConfig(context.Background(), path, c)
	require.NoError(t, err)

	// Not connected, so ReloadTunnels is a safe no-op — the point of this
	// assertion is that reloadClientConfig didn't error out or panic
	// walking the newly-loaded tunnel set.
	assert.Empty(t, c.ListActiveTunnels())
}

func TestReloadClientConfig_MissingFile_ReturnsErrorWithoutTouchingClient(t *testing.T) {
	c := client.NewClient(client.DefaultConfig())
	err := reloadClientConfig(context.Background(), filepath.Join(t.TempDir(), "does-not-exist.yml"), c)
	assert.Error(t, err)
}

func TestReloadClientConfig_MalformedYAML_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wormhole.yml")
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml: at all:::"), 0o600))

	c := client.NewClient(client.DefaultConfig())
	err := reloadClientConfig(context.Background(), path, c)
	assert.Error(t, err)
}

func TestRefreshSavedCredentials_CannotRefresh(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	creds := &auth.Credentials{Server: "tunnel.example.com:7000", Token: "tok"}
	assert.Nil(t, refreshSavedCredentials(context.Background(), creds))
}

func TestRefreshSavedCredentials_HTTPError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := newRefreshTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
	})

	creds := &auth.Credentials{
		Server:        "tunnel.example.com:7000",
		RefreshToken:  "bad-refresh-token",
		ClientID:      "my-client",
		TokenEndpoint: srv.URL,
	}
	assert.Nil(t, refreshSavedCredentials(context.Background(), creds))
}

func TestRefreshSavedCredentials_PreservesRefreshTokenWhenOmitted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := newRefreshTokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		// Provider omits refresh_token on renewal — the original must be kept.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "renewed-token",
			"expires_in":   3600,
		})
	})

	creds := &auth.Credentials{
		Server:        "tunnel.example.com:7000",
		RefreshToken:  "original-refresh-token",
		ClientID:      "my-client",
		TokenEndpoint: srv.URL,
	}
	updated := refreshSavedCredentials(context.Background(), creds)
	require.NotNil(t, updated)
	assert.Equal(t, "renewed-token", updated.Token)
	assert.Equal(t, "original-refresh-token", updated.RefreshToken)
}
