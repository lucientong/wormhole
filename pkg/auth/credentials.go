package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
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

	newData, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, newData, 0o600)
}
