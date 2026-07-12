package auth

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRedisStore spins up a miniredis instance and wraps it in a
// RedisStore, registering cleanup with t.
func newTestRedisStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return newRedisStoreWithClient(client), mr
}

func TestRedisStore_TeamOperations(t *testing.T) {
	store, _ := newTestRedisStore(t)
	defer store.Close()

	team := &TeamInfo{
		Name:      "test-team",
		CreatedAt: time.Now().Truncate(time.Second),
		Tokens:    5,
	}
	require.NoError(t, store.SaveTeam(team))

	retrieved, err := store.GetTeam("test-team")
	require.NoError(t, err)
	assert.Equal(t, team.Name, retrieved.Name)
	assert.Equal(t, team.Tokens, retrieved.Tokens)
	assert.Equal(t, team.CreatedAt.Unix(), retrieved.CreatedAt.Unix())

	_, err = store.GetTeam("nonexistent")
	assert.ErrorIs(t, err, ErrTeamNotFound)

	team2 := &TeamInfo{Name: "another-team", CreatedAt: time.Now().Truncate(time.Second), Tokens: 3}
	require.NoError(t, store.SaveTeam(team2))

	teams, err := store.ListTeams()
	require.NoError(t, err)
	assert.Len(t, teams, 2)

	require.NoError(t, store.DeleteTeam("test-team"))

	teams, err = store.ListTeams()
	require.NoError(t, err)
	assert.Len(t, teams, 1)

	_, err = store.GetTeam("test-team")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestRedisStore_UpdateTeam(t *testing.T) {
	store, _ := newTestRedisStore(t)
	defer store.Close()

	team := &TeamInfo{Name: "test-team", CreatedAt: time.Now().Truncate(time.Second), Tokens: 1}
	require.NoError(t, store.SaveTeam(team))

	team.Tokens = 10
	require.NoError(t, store.SaveTeam(team))

	retrieved, err := store.GetTeam("test-team")
	require.NoError(t, err)
	assert.Equal(t, 10, retrieved.Tokens)
}

func TestRedisStore_RevokedTokenOperations(t *testing.T) {
	store, _ := newTestRedisStore(t)
	defer store.Close()

	tokenID := "test-token-id"
	expiresAt := time.Now().Add(1 * time.Hour)

	require.NoError(t, store.SaveRevokedToken(tokenID, expiresAt))

	revoked, err := store.IsTokenRevoked(tokenID)
	require.NoError(t, err)
	assert.True(t, revoked)

	revoked, err = store.IsTokenRevoked("other-token")
	require.NoError(t, err)
	assert.False(t, revoked)

	require.NoError(t, store.RemoveRevokedToken(tokenID))

	revoked, err = store.IsTokenRevoked(tokenID)
	require.NoError(t, err)
	assert.False(t, revoked)

	require.NoError(t, store.SaveRevokedToken("token1", time.Now().Add(1*time.Hour)))
	require.NoError(t, store.SaveRevokedToken("token2", time.Now().Add(1*time.Hour)))
	require.NoError(t, store.SaveRevokedToken("token3", time.Now().Add(1*time.Hour)))

	count, err := store.CountRevokedTokens()
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

// TestRedisStore_PermanentRevocation verifies that a zero expiresAt (a
// "permanent" revocation) is stored with no TTL and never expires on its
// own — unlike a time-bound revocation, which Redis expires automatically
// (see TestRedisStore_TTLBasedExpiry).
func TestRedisStore_PermanentRevocation(t *testing.T) {
	store, mr := newTestRedisStore(t)
	defer store.Close()

	require.NoError(t, store.SaveRevokedToken("permanent", time.Time{}))

	revoked, err := store.IsTokenRevoked("permanent")
	require.NoError(t, err)
	assert.True(t, revoked)

	// Fast-forward far into the future; a permanent revocation must still
	// be there since it was stored with no TTL.
	mr.FastForward(24 * time.Hour)

	revoked, err = store.IsTokenRevoked("permanent")
	require.NoError(t, err)
	assert.True(t, revoked)
}

// TestRedisStore_TTLBasedExpiry verifies the "no explicit sweep needed"
// design: a revocation with a real expiry disappears on its own once
// Redis's TTL elapses, without ever calling CleanupExpiredRevocations.
func TestRedisStore_TTLBasedExpiry(t *testing.T) {
	store, mr := newTestRedisStore(t)
	defer store.Close()

	require.NoError(t, store.SaveRevokedToken("short-lived", time.Now().Add(2*time.Second)))

	revoked, err := store.IsTokenRevoked("short-lived")
	require.NoError(t, err)
	assert.True(t, revoked)

	mr.FastForward(3 * time.Second)

	revoked, err = store.IsTokenRevoked("short-lived")
	require.NoError(t, err)
	assert.False(t, revoked, "revocation should have expired via Redis TTL without any cleanup call")
}

// TestRedisStore_CleanupExpiredRevocationsIsNoop documents that
// CleanupExpiredRevocations always reports nothing to clean — Redis's own
// TTLs already do the work (see TestRedisStore_TTLBasedExpiry) — so
// callers like the periodic sweep goroutines in pkg/server can
// call it uniformly across every Store implementation without needing to
// special-case Redis.
func TestRedisStore_CleanupExpiredRevocationsIsNoop(t *testing.T) {
	store, _ := newTestRedisStore(t)
	defer store.Close()

	require.NoError(t, store.SaveRevokedToken("token", time.Now().Add(-1*time.Hour)))

	cleaned, err := store.CleanupExpiredRevocations()
	require.NoError(t, err)
	assert.Equal(t, 0, cleaned)
}

func TestNewRedisStore_PingFailure(t *testing.T) {
	_, err := NewRedisStore(RedisStoreConfig{Addr: "127.0.0.1:1"})
	assert.Error(t, err)
}

func TestRedisStore_Close(t *testing.T) {
	store, _ := newTestRedisStore(t)
	assert.NoError(t, store.Close())
}
