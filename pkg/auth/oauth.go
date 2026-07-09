package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth2 token/device-authorization request form-field names (RFC 6749,
// RFC 8628 §3.1/§3.4).
const (
	paramGrantType    = "grant_type"
	paramDeviceCode   = "device_code"
	paramClientID     = "client_id"
	paramRefreshToken = "refresh_token"
	paramScope        = "scope"
)

// grantTypeDeviceCode is the "grant_type" value for the device authorization
// grant (RFC 8628 §3.4). grantTypeRefreshToken reuses paramRefreshToken since
// RFC 6749 §6 spells the refresh_token grant type identically to the
// refresh_token form field name.
const grantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

const grantTypeRefreshToken = paramRefreshToken

// OAuth2 token-endpoint error codes relevant to device-flow polling
// (RFC 8628 §3.5).
const (
	errCodeAuthorizationPending = "authorization_pending"
	errCodeSlowDown             = "slow_down"
)

// DeviceFlowConfig configures an OAuth2 Device Authorization Grant flow.
type DeviceFlowConfig struct {
	// Issuer is the OIDC provider URL used for endpoint discovery.
	Issuer string

	// ClientID is the OAuth2 public client registered with the provider.
	ClientID string

	// Scopes is the list of OAuth scopes to request.
	// Defaults to ["openid", "email", "profile"] when empty.
	Scopes []string
}

// DeviceCode holds the values returned by the device authorization endpoint.
type DeviceCode struct {
	// DeviceCode is the opaque code sent to the token endpoint.
	DeviceCode string

	// UserCode is the short code the user enters at VerificationURI.
	UserCode string

	// VerificationURI is the URL the user should visit to complete authorisation.
	VerificationURI string

	// VerificationURIComplete includes the user code for one-click auth (optional).
	VerificationURIComplete string

	// ExpiresIn is the number of seconds until the codes expire.
	ExpiresIn int

	// Interval is the polling interval in seconds (default 5).
	Interval int

	// TokenEndpoint is the endpoint to poll for a token.
	TokenEndpoint string

	// ClientID is carried through from DeviceFlowConfig so requestToken can
	// include it in the token-poll request body (RFC 8628 §3.4 requires
	// client_id for public clients that have no client secret).
	ClientID string
}

// TokenResult holds everything obtained from a successful token response,
// including refresh material needed for silent renewal.
type TokenResult struct {
	// AccessToken is the OAuth2 access token.
	AccessToken string
	// IDToken is the OIDC ID token, if the provider issued one.
	IDToken string
	// RefreshToken allows obtaining a new access/ID token without
	// re-running the interactive flow (empty if the provider didn't issue one).
	RefreshToken string
	// ExpiresIn is the access token lifetime in seconds, as reported by the
	// provider (0 if not reported).
	ExpiresIn int
}

// Token returns the ID token if present, otherwise the access token.
func (r *TokenResult) Token() string {
	if r.IDToken != "" {
		return r.IDToken
	}
	return r.AccessToken
}

// ErrAuthorizationPending is returned while the user has not yet completed auth.
var ErrAuthorizationPending = errors.New("authorization pending")

// ErrSlowDown is returned when polling too fast.
var ErrSlowDown = errors.New("slow down polling")

// StartDeviceFlow initiates the OAuth2 Device Authorization Grant.
// It discovers the device authorization and token endpoints from the OIDC
// well-known configuration, then starts the flow.
func StartDeviceFlow(ctx context.Context, cfg DeviceFlowConfig) (*DeviceCode, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("client_id is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", claimEmail, "profile"}
	}

	deviceEndpoint, tokenEndpoint, err := discoverDeviceEndpoints(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	return startDeviceAuthorization(ctx, deviceEndpoint, tokenEndpoint, cfg)
}

// PollDeviceFlow polls the token endpoint until the user completes authorisation
// or the device code expires. It handles the "slow_down" and
// "authorization_pending" error responses automatically.
func PollDeviceFlow(ctx context.Context, dc *DeviceCode) (*TokenResult, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		if time.Now().After(deadline) {
			return nil, errors.New("device code expired")
		}

		result, err := requestToken(ctx, client, dc.TokenEndpoint, url.Values{
			paramGrantType:  {grantTypeDeviceCode},
			paramDeviceCode: {dc.DeviceCode},
			paramClientID:   {dc.ClientID},
		})
		if err == nil {
			return result, nil
		}
		if errors.Is(err, ErrAuthorizationPending) {
			continue
		}
		if errors.Is(err, ErrSlowDown) {
			interval += 5 * time.Second
			continue
		}
		return nil, err
	}
}

// RefreshAccessToken exchanges a refresh token for a new access/ID token
// using the OAuth2 refresh_token grant (RFC 6749 §6). tokenEndpoint and
// clientID are normally the values cached in Credentials from the original
// device-flow login.
func RefreshAccessToken(ctx context.Context, tokenEndpoint, clientID, refreshToken string) (*TokenResult, error) {
	if tokenEndpoint == "" || clientID == "" || refreshToken == "" {
		return nil, errors.New("refresh access token: tokenEndpoint, clientID and refreshToken are required")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	result, err := requestToken(ctx, client, tokenEndpoint, url.Values{
		paramGrantType:    {grantTypeRefreshToken},
		paramRefreshToken: {refreshToken},
		paramClientID:     {clientID},
	})
	if err != nil {
		return nil, fmt.Errorf("refresh access token: %w", err)
	}
	// Some providers omit refresh_token on renewal, meaning the original
	// one remains valid for future refreshes — preserve it in that case.
	if result.RefreshToken == "" {
		result.RefreshToken = refreshToken
	}
	return result, nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func discoverDeviceEndpoints(ctx context.Context, issuer string) (deviceEP, tokenEP string, err error) {
	wellKnownURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return "", "", err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	var discovery struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", "", fmt.Errorf("decode discovery: %w", err)
	}
	if discovery.DeviceAuthorizationEndpoint == "" {
		return "", "", errors.New("provider does not support device authorization grant (device_authorization_endpoint missing)")
	}
	return discovery.DeviceAuthorizationEndpoint, discovery.TokenEndpoint, nil
}

func startDeviceAuthorization(ctx context.Context, deviceEP, tokenEP string, cfg DeviceFlowConfig) (*DeviceCode, error) {
	body := url.Values{
		paramClientID: {cfg.ClientID},
		paramScope:    {strings.Join(cfg.Scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceEP, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device authorization request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization request failed (HTTP %d): %s", resp.StatusCode, respBody)
	}

	var dc struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(respBody, &dc); err != nil {
		return nil, fmt.Errorf("decode device authorization response: %w", err)
	}

	if dc.ExpiresIn == 0 {
		dc.ExpiresIn = 300
	}
	if dc.Interval == 0 {
		dc.Interval = 5
	}

	return &DeviceCode{
		DeviceCode:              dc.DeviceCode,
		UserCode:                dc.UserCode,
		VerificationURI:         dc.VerificationURI,
		VerificationURIComplete: dc.VerificationURIComplete,
		ExpiresIn:               dc.ExpiresIn,
		Interval:                dc.Interval,
		TokenEndpoint:           tokenEP,
		ClientID:                cfg.ClientID,
	}, nil
}

// requestToken performs a single POST to tokenEndpoint with the given form
// body (grant-specific fields already set by the caller) and parses the
// response into a TokenResult.
func requestToken(ctx context.Context, client *http.Client, tokenEndpoint string, body url.Values) (*TokenResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	if result.Error != "" {
		switch result.Error {
		case errCodeAuthorizationPending:
			return nil, ErrAuthorizationPending
		case errCodeSlowDown:
			return nil, ErrSlowDown
		default:
			return nil, fmt.Errorf("token error %q: %s", result.Error, result.Description)
		}
	}

	if result.AccessToken == "" && result.IDToken == "" {
		return nil, errors.New("no token in response")
	}

	return &TokenResult{
		AccessToken:  result.AccessToken,
		IDToken:      result.IDToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}
