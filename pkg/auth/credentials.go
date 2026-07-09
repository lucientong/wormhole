package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoCredentials is returned when no saved credentials are found.
var ErrNoCredentials = errors.New("no credentials found")

// Credentials stores an OAuth/OIDC access token alongside its metadata.
type Credentials struct {
	// Server is the wormhole server address these credentials are for.
	Server string `json:"server"`

	// Token is the saved OAuth/OIDC access or ID token.
	Token string `json:"token"`

	// ExpiresAt is when the token expires (zero means no expiry).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// SavedAt records when the credentials were persisted.
	SavedAt time.Time `json:"saved_at"`

	// RefreshToken, when non-empty, allows silently renewing Token once it
	// expires without another interactive device-flow login.
	RefreshToken string `json:"refresh_token,omitempty"`

	// OIDCIssuer is the issuer URL used to obtain this token, needed to
	// rediscover the token endpoint for a refresh request.
	OIDCIssuer string `json:"oidc_issuer,omitempty"`

	// ClientID is the OAuth2 client ID used to obtain this token, required
	// on the refresh_token grant request for public clients (RFC 6749 §6).
	ClientID string `json:"client_id,omitempty"`

	// TokenEndpoint caches the discovered OAuth2 token endpoint so a
	// refresh doesn't need to re-run OIDC discovery.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
}

// CanRefresh reports whether these credentials have enough information to
// attempt a refresh_token grant when the access token expires.
func (c *Credentials) CanRefresh() bool {
	return c.RefreshToken != "" && c.TokenEndpoint != "" && c.ClientID != ""
}

// IsExpired returns true if the token has expired.
func (c *Credentials) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// DefaultCredentialsPath returns the default path for the credentials file.
func DefaultCredentialsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./credentials.json"
	}
	return filepath.Join(home, ".wormhole", "credentials.json")
}

// credentialsFile is the on-disk structure mapping server → credentials.
type credentialsFile map[string]Credentials

// SaveCredentials persists credentials for the given server to a JSON file.
// If path is empty, DefaultCredentialsPath() is used.
func SaveCredentials(path, server, token string, expiresAt time.Time) error {
	if path == "" {
		path = DefaultCredentialsPath()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}

	// Load existing file (if any) so we don't overwrite other servers.
	existing := make(credentialsFile)
	if data, err := os.ReadFile(path); err == nil { // #nosec G304
		_ = json.Unmarshal(data, &existing)
	}

	existing[server] = Credentials{
		Server:    server,
		Token:     token,
		ExpiresAt: expiresAt,
		SavedAt:   time.Now(),
	}

	// #nosec G117 -- this *is* the credentials store: writing Token/RefreshToken
	// to a 0600 file under the user's home directory is the intended purpose of
	// SaveCredentials, not an accidental secret leak.
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
}

// SaveCredentialsFull persists a fully-populated Credentials record (including
// refresh token / issuer / client ID needed for silent token renewal). Unlike
// SaveCredentials, the caller supplies the complete record; Server determines
// which entry is written and SavedAt is stamped automatically.
func SaveCredentialsFull(path string, creds Credentials) error {
	if path == "" {
		path = DefaultCredentialsPath()
	}
	if creds.Server == "" {
		return errors.New("credentials: server is required")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}

	existing := make(credentialsFile)
	if data, err := os.ReadFile(path); err == nil { // #nosec G304
		_ = json.Unmarshal(data, &existing)
	}

	creds.SavedAt = time.Now()
	existing[creds.Server] = creds

	// #nosec G117 -- see SaveCredentials above: this file is the credentials
	// store, so persisting Token/RefreshToken here is intentional.
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
}

// ParseJWTExpiry best-effort decodes the `exp` claim from a JWT's payload
// segment without verifying its signature. It is used purely for local
// bookkeeping (deciding when to attempt a token refresh) — the token itself
// was already obtained directly from the issuer over TLS, so re-verifying
// it here would add no security value. Returns the zero Time if the token
// isn't JWT-shaped or carries no `exp` claim.
func ParseJWTExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// LoadCredentials reads the saved credentials for the given server.
// Returns ErrNoCredentials when no entry exists.
func LoadCredentials(path, server string) (*Credentials, error) {
	if path == "" {
		path = DefaultCredentialsPath()
	}

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoCredentials
		}
		return nil, fmt.Errorf("read credentials file: %w", err)
	}

	var cf credentialsFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse credentials file: %w", err)
	}

	creds, ok := cf[server]
	if !ok {
		return nil, ErrNoCredentials
	}
	return &creds, nil
}

// DeleteCredentials removes the saved credentials for the given server.
func DeleteCredentials(path, server string) error {
	if path == "" {
		path = DefaultCredentialsPath()
	}

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read credentials file: %w", err)
	}

	var cf credentialsFile
	if unmarshalErr := json.Unmarshal(data, &cf); unmarshalErr != nil {
		return fmt.Errorf("parse credentials file: %w", unmarshalErr)
	}

	delete(cf, server)

	// #nosec G117 -- rewriting the same on-disk credentials store minus the
	// deleted entry; see SaveCredentials above.
	newData, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, newData, 0o600)
}
