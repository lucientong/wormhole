package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDiscoveryServer builds a test OIDC provider exposing well-known
// discovery, device authorization, and token endpoints. deviceHandler and
// tokenHandler let each test control the exact responses/assertions.
func newDiscoveryServer(t *testing.T, deviceHandler, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": srv.URL + "/device/auth",
			"token_endpoint":                srv.URL + "/token",
		})
	})
	mux.HandleFunc("/device/auth", deviceHandler)
	mux.HandleFunc("/token", tokenHandler)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestStartDeviceFlow_Success(t *testing.T) {
	srv := newDiscoveryServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "my-client", r.FormValue(paramClientID))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				paramDeviceCode:    "dc-123",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://idp/verify",
				"expires_in":       600,
				"interval":         1,
			})
		},
		func(_ http.ResponseWriter, _ *http.Request) {},
	)

	dc, err := StartDeviceFlow(context.Background(), DeviceFlowConfig{
		Issuer:   srv.URL,
		ClientID: "my-client",
	})
	require.NoError(t, err)
	assert.Equal(t, "dc-123", dc.DeviceCode)
	assert.Equal(t, "ABCD-1234", dc.UserCode)
	assert.Equal(t, "my-client", dc.ClientID, "ClientID must be carried through for RFC 8628 token-poll compliance")
	assert.Equal(t, srv.URL+"/token", dc.TokenEndpoint)
}

func TestStartDeviceFlow_MissingIssuerOrClientID(t *testing.T) {
	_, err := StartDeviceFlow(context.Background(), DeviceFlowConfig{ClientID: "c"})
	require.Error(t, err)

	_, err = StartDeviceFlow(context.Background(), DeviceFlowConfig{Issuer: "https://idp"})
	require.Error(t, err)
}

func TestStartDeviceFlow_NoDeviceAuthSupport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "https://idp/token"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := StartDeviceFlow(context.Background(), DeviceFlowConfig{Issuer: srv.URL, ClientID: "c"})
	require.Error(t, err)
}

// TestPollDeviceFlow_IncludesClientID verifies RFC 8628 §3.4 compliance
// (S15): the token-poll request must include client_id for public clients.
// Uses Interval: 1 (the smallest non-zero value — 0 means "use the 5s
// default" in PollDeviceFlow) so the test only waits ~1s in real time.
func TestPollDeviceFlow_IncludesClientID(t *testing.T) {
	var gotClientID string
	srv := newDiscoveryServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				paramDeviceCode: "dc-1", "user_code": "u", "verification_uri": "https://idp/v",
				"expires_in": 60, "interval": 1,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			gotClientID = r.FormValue(paramClientID)
			assert.Equal(t, grantTypeDeviceCode, r.FormValue(paramGrantType))
			assert.Equal(t, "dc-1", r.FormValue(paramDeviceCode))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at", "id_token": "idt", paramRefreshToken: "rt", "expires_in": 3600,
			})
		},
	)

	dc, err := StartDeviceFlow(context.Background(), DeviceFlowConfig{Issuer: srv.URL, ClientID: "public-client"})
	require.NoError(t, err)

	result, err := PollDeviceFlow(context.Background(), dc)
	require.NoError(t, err)
	assert.Equal(t, "public-client", gotClientID)
	assert.Equal(t, "idt", result.Token(), "Token() should prefer the ID token")
	assert.Equal(t, "rt", result.RefreshToken)
	assert.Equal(t, 3600, result.ExpiresIn)
}

// TestPollDeviceFlow_AuthorizationPendingThenSuccess exercises the retry
// loop end-to-end with a minimal 1s interval and a single retry to keep the
// test fast; requestToken-level behavior for each error code is covered
// directly by TestRequestToken_* below without incurring any real wait.
func TestPollDeviceFlow_AuthorizationPendingThenSuccess(t *testing.T) {
	attempts := 0
	srv := newDiscoveryServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				paramDeviceCode: "dc-1", "user_code": "u", "verification_uri": "https://idp/v",
				"expires_in": 60, "interval": 1,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.Header().Set("Content-Type", "application/json")
			if attempts < 2 {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": errCodeAuthorizationPending})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-final"})
		},
	)

	dc, err := StartDeviceFlow(context.Background(), DeviceFlowConfig{Issuer: srv.URL, ClientID: "c"})
	require.NoError(t, err)

	result, err := PollDeviceFlow(context.Background(), dc)
	require.NoError(t, err)
	assert.Equal(t, "at-final", result.Token())
	assert.Equal(t, 2, attempts)
}

func TestRequestToken_AuthorizationPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": errCodeAuthorizationPending})
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := requestToken(context.Background(), client, srv.URL, url.Values{paramGrantType: {"x"}})
	require.ErrorIs(t, err, ErrAuthorizationPending)
}

func TestRequestToken_SlowDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": errCodeSlowDown})
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := requestToken(context.Background(), client, srv.URL, url.Values{paramGrantType: {"x"}})
	require.ErrorIs(t, err, ErrSlowDown)
}

func TestPollDeviceFlow_ExpiredDeviceCode(t *testing.T) {
	dc := &DeviceCode{
		DeviceCode: "dc", TokenEndpoint: "http://unused", ExpiresIn: 0, Interval: 0,
	}
	_, err := PollDeviceFlow(context.Background(), dc)
	require.Error(t, err)
}

func TestPollDeviceFlow_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dc := &DeviceCode{DeviceCode: "dc", TokenEndpoint: "http://unused", ExpiresIn: 60, Interval: 1}
	_, err := PollDeviceFlow(ctx, dc)
	require.ErrorIs(t, err, context.Canceled)
}

func TestPollDeviceFlow_GenericTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "access_denied", "error_description": "user denied access"})
	}))
	defer srv.Close()

	dc := &DeviceCode{DeviceCode: "dc", TokenEndpoint: srv.URL, ExpiresIn: 60, Interval: 0}
	_, err := PollDeviceFlow(context.Background(), dc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_denied")
}

func TestRefreshAccessToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, grantTypeRefreshToken, r.FormValue(paramGrantType))
		assert.Equal(t, "old-refresh", r.FormValue(paramRefreshToken))
		assert.Equal(t, "my-client", r.FormValue(paramClientID))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-at", "id_token": "new-idt", paramRefreshToken: "new-refresh", "expires_in": 1800,
		})
	}))
	defer srv.Close()

	result, err := RefreshAccessToken(context.Background(), srv.URL, "my-client", "old-refresh")
	require.NoError(t, err)
	assert.Equal(t, "new-idt", result.Token())
	assert.Equal(t, "new-refresh", result.RefreshToken)
	assert.Equal(t, 1800, result.ExpiresIn)
}

// TestRefreshAccessToken_PreservesRefreshTokenWhenOmitted covers providers
// that don't rotate the refresh token on every renewal (RFC 6749 allows
// omitting it, meaning the original stays valid).
func TestRefreshAccessToken_PreservesRefreshTokenWhenOmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-at"})
	}))
	defer srv.Close()

	result, err := RefreshAccessToken(context.Background(), srv.URL, "my-client", "still-valid-refresh")
	require.NoError(t, err)
	assert.Equal(t, "still-valid-refresh", result.RefreshToken)
}

func TestRefreshAccessToken_MissingArgs(t *testing.T) {
	_, err := RefreshAccessToken(context.Background(), "", "client", "rt")
	require.Error(t, err)
	_, err = RefreshAccessToken(context.Background(), "https://idp/token", "", "rt")
	require.Error(t, err)
	_, err = RefreshAccessToken(context.Background(), "https://idp/token", "client", "")
	require.Error(t, err)
}

func TestRefreshAccessToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "refresh token expired"})
	}))
	defer srv.Close()

	_, err := RefreshAccessToken(context.Background(), srv.URL, "client", "expired-refresh")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestTokenResult_Token(t *testing.T) {
	withID := &TokenResult{AccessToken: "at", IDToken: "idt"}
	assert.Equal(t, "idt", withID.Token())

	accessOnly := &TokenResult{AccessToken: "at"}
	assert.Equal(t, "at", accessOnly.Token())
}

func TestDiscoverDeviceEndpoints_DiscoveryFailure(t *testing.T) {
	_, _, err := discoverDeviceEndpoints(context.Background(), "http://127.0.0.1:0")
	require.Error(t, err)
}

// Ensure url.Values usage in requestToken doesn't accidentally leak fields
// across grants (regression guard for the shared helper refactor).
func TestRequestToken_DoesNotLeakFieldsBetweenGrants(t *testing.T) {
	var gotBody url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotBody = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at"})
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := requestToken(context.Background(), client, srv.URL, url.Values{
		paramGrantType: {grantTypeRefreshToken},
		paramClientID:  {"c"},
	})
	require.NoError(t, err)
	assert.Empty(t, gotBody.Get(paramDeviceCode))
	assert.Equal(t, grantTypeRefreshToken, gotBody.Get(paramGrantType))
}
