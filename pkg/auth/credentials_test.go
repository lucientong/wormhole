package auth

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wormhole-creds-*.json")
	require.NoError(t, err)
	f.Close()

	exp := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	require.NoError(t, SaveCredentials(f.Name(), "localhost:7000", "my-token", exp))

	creds, err := LoadCredentials(f.Name(), "localhost:7000")
	require.NoError(t, err)
	assert.Equal(t, "localhost:7000", creds.Server)
	assert.Equal(t, "my-token", creds.Token)
	assert.Equal(t, exp.UTC(), creds.ExpiresAt.UTC())
	assert.False(t, creds.IsExpired())
}

func TestLoadCredentials_NotFound(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wormhole-creds-*.json")
	require.NoError(t, err)
	f.Close()

	require.NoError(t, SaveCredentials(f.Name(), "server-a:7000", "tok-a", time.Time{}))

	_, err = LoadCredentials(f.Name(), "server-b:7000")
	require.ErrorIs(t, err, ErrNoCredentials)
}

func TestLoadCredentials_MissingFile(t *testing.T) {
	_, err := LoadCredentials("/nonexistent/creds.json", "server:7000")
	require.ErrorIs(t, err, ErrNoCredentials)
}

func TestSaveCredentials_MultipleServers(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wormhole-creds-*.json")
	require.NoError(t, err)
	f.Close()

	require.NoError(t, SaveCredentials(f.Name(), "server-a:7000", "tok-a", time.Time{}))
	require.NoError(t, SaveCredentials(f.Name(), "server-b:7000", "tok-b", time.Time{}))

	a, err := LoadCredentials(f.Name(), "server-a:7000")
	require.NoError(t, err)
	assert.Equal(t, "tok-a", a.Token)

	b, err := LoadCredentials(f.Name(), "server-b:7000")
	require.NoError(t, err)
	assert.Equal(t, "tok-b", b.Token)
}

func TestDeleteCredentials(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wormhole-creds-*.json")
	require.NoError(t, err)
	f.Close()

	require.NoError(t, SaveCredentials(f.Name(), "server-a:7000", "tok-a", time.Time{}))
	require.NoError(t, SaveCredentials(f.Name(), "server-b:7000", "tok-b", time.Time{}))
	require.NoError(t, DeleteCredentials(f.Name(), "server-a:7000"))

	_, err = LoadCredentials(f.Name(), "server-a:7000")
	require.ErrorIs(t, err, ErrNoCredentials)

	b, err := LoadCredentials(f.Name(), "server-b:7000")
	require.NoError(t, err)
	assert.Equal(t, "tok-b", b.Token)
}

func TestCredentials_IsExpired(t *testing.T) {
	past := Credentials{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	assert.True(t, past.IsExpired())

	future := Credentials{ExpiresAt: time.Now().Add(1 * time.Hour)}
	assert.False(t, future.IsExpired())

	noExpiry := Credentials{}
	assert.False(t, noExpiry.IsExpired())
}

func TestCredentials_CanRefresh(t *testing.T) {
	full := Credentials{RefreshToken: "rt", TokenEndpoint: "https://idp/token", ClientID: "cid"}
	assert.True(t, full.CanRefresh())

	missingRefresh := Credentials{TokenEndpoint: "https://idp/token", ClientID: "cid"}
	assert.False(t, missingRefresh.CanRefresh())

	missingEndpoint := Credentials{RefreshToken: "rt", ClientID: "cid"}
	assert.False(t, missingEndpoint.CanRefresh())

	missingClientID := Credentials{RefreshToken: "rt", TokenEndpoint: "https://idp/token"}
	assert.False(t, missingClientID.CanRefresh())
}

func TestSaveCredentialsFull_RoundTrip(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wormhole-creds-*.json")
	require.NoError(t, err)
	f.Close()

	exp := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	require.NoError(t, SaveCredentialsFull(f.Name(), Credentials{
		Server:        "tunnel.example.com:7000",
		Token:         "id-token",
		ExpiresAt:     exp,
		RefreshToken:  "refresh-token",
		OIDCIssuer:    "https://issuer.example.com",
		ClientID:      "my-client",
		TokenEndpoint: "https://issuer.example.com/token",
	}))

	creds, err := LoadCredentials(f.Name(), "tunnel.example.com:7000")
	require.NoError(t, err)
	assert.Equal(t, "id-token", creds.Token)
	assert.Equal(t, "refresh-token", creds.RefreshToken)
	assert.Equal(t, "https://issuer.example.com", creds.OIDCIssuer)
	assert.Equal(t, "my-client", creds.ClientID)
	assert.Equal(t, "https://issuer.example.com/token", creds.TokenEndpoint)
	assert.True(t, creds.CanRefresh())
	assert.False(t, creds.SavedAt.IsZero())
}

func TestSaveCredentialsFull_RequiresServer(t *testing.T) {
	err := SaveCredentialsFull(filepath.Join(t.TempDir(), "creds.json"), Credentials{Token: "tok"})
	require.Error(t, err)
}

func TestSaveCredentialsFull_PreservesOtherServers(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wormhole-creds-*.json")
	require.NoError(t, err)
	f.Close()

	require.NoError(t, SaveCredentials(f.Name(), "server-a:7000", "tok-a", time.Time{}))
	require.NoError(t, SaveCredentialsFull(f.Name(), Credentials{Server: "server-b:7000", Token: "tok-b", RefreshToken: "rt-b"}))

	a, err := LoadCredentials(f.Name(), "server-a:7000")
	require.NoError(t, err)
	assert.Equal(t, "tok-a", a.Token)

	b, err := LoadCredentials(f.Name(), "server-b:7000")
	require.NoError(t, err)
	assert.Equal(t, "tok-b", b.Token)
	assert.Equal(t, "rt-b", b.RefreshToken)
}

func TestParseJWTExpiry(t *testing.T) {
	future := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	token := makeTestJWT(t, future.Unix())

	got := ParseJWTExpiry(token)
	assert.Equal(t, future.Unix(), got.Unix())
}

func TestParseJWTExpiry_InvalidOrMissing(t *testing.T) {
	assert.True(t, ParseJWTExpiry("not-a-jwt").IsZero())
	assert.True(t, ParseJWTExpiry("a.b").IsZero())
	assert.True(t, ParseJWTExpiry("a.b.c").IsZero()) // invalid base64 payload
	// Valid JWT structure but no exp claim.
	noExp := makeTestJWTPayload(t, `{"sub":"user"}`)
	assert.True(t, ParseJWTExpiry(noExp).IsZero())
}

// makeTestJWT builds a syntactically-valid (unsigned) JWT with the given exp claim.
func makeTestJWT(t *testing.T, exp int64) string {
	t.Helper()
	return makeTestJWTPayload(t, fmt.Sprintf(`{"sub":"user","exp":%d}`, exp))
}

// makeTestJWTPayload builds an unsigned JWT with an arbitrary JSON payload.
func makeTestJWTPayload(t *testing.T, payloadJSON string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".sig"
}
