package auth

import (
	"os"
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
