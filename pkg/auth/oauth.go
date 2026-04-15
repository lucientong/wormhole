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
		cfg.Scopes = []string{"openid", "email", "profile"}
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
func PollDeviceFlow(ctx context.Context, dc *DeviceCode) (string, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}

		if time.Now().After(deadline) {
			return "", errors.New("device code expired")
		}

		token, err := requestToken(ctx, client, dc)
		if err == nil {
			return token, nil
		}
		if errors.Is(err, ErrAuthorizationPending) {
			continue
		}
		if errors.Is(err, ErrSlowDown) {
			interval += 5 * time.Second
			continue
		}
		return "", err
	}
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
		"client_id": {cfg.ClientID},
		"scope":     {strings.Join(cfg.Scopes, " ")},
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
	}, nil
}

func requestToken(ctx context.Context, client *http.Client, dc *DeviceCode) (string, error) {
	body := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {dc.DeviceCode},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dc.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if result.Error != "" {
		switch result.Error {
		case "authorization_pending":
			return "", ErrAuthorizationPending
		case "slow_down":
			return "", ErrSlowDown
		default:
			return "", fmt.Errorf("token error %q: %s", result.Error, result.Description)
		}
	}

	// Prefer ID token (contains OIDC claims) over access token.
	token := result.IDToken
	if token == "" {
		token = result.AccessToken
	}
	if token == "" {
		return "", errors.New("no token in response")
	}
	return token, nil
}
