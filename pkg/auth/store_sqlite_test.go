package auth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteStore_TeamOperations(t *testing.T) {
	// Create temp directory.
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSQLiteStore(SQLiteStoreConfig{
		Path:      dbPath,
		CreateDir: true,
	})
	require.NoError(t, err)
	defer store.Close()

	// Test SaveTeam and GetTeam.
	team := &TeamInfo{
		Name:      "test-team",
		CreatedAt: time.Now().Truncate(time.Second), // SQLite stores as Unix timestamp.
		Tokens:    5,
	}
	err = store.SaveTeam(team)
	require.NoError(t, err)

	retrieved, err := store.GetTeam("test-team")
	require.NoError(t, err)
	assert.Equal(t, team.Name, retrieved.Name)
	assert.Equal(t, team.Tokens, retrieved.Tokens)
	assert.Equal(t, team.CreatedAt.Unix(), retrieved.CreatedAt.Unix())

	// Test GetTeam not found.
	_, err = store.GetTeam("nonexistent")
	assert.ErrorIs(t, err, ErrTeamNotFound)

	// Test ListTeams.
	team2 := &TeamInfo{
		Name:      "another-team",
		CreatedAt: time.Now().Truncate(time.Second),
		Tokens:    3,
	}
	err = store.SaveTeam(team2)
	require.NoError(t, err)

	teams, err := store.ListTeams()
	require.NoError(t, err)
	assert.Len(t, teams, 2)

	// Test DeleteTeam.
	err = store.DeleteTeam("test-team")
	require.NoError(t, err)

	teams, err = store.ListTeams()
	require.NoError(t, err)
	assert.Len(t, teams, 1)

	_, err = store.GetTeam("test-team")
	assert.ErrorIs(t, err, ErrTeamNotFound)
}

func TestSQLiteStore_RevokedTokenOperations(t *testing.T) {
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSQLiteStore(SQLiteStoreConfig{
		Path:      dbPath,
		CreateDir: true,
	})
	require.NoError(t, err)
	defer store.Close()

	tokenID := "test-token-id"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Test SaveRevokedToken and IsTokenRevoked.
	err = store.SaveRevokedToken(tokenID, expiresAt)
	require.NoError(t, err)

	revoked, err := store.IsTokenRevoked(tokenID)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Test not revoked.
	revoked, err = store.IsTokenRevoked("other-token")
	require.NoError(t, err)
	assert.False(t, revoked)

	// Test RemoveRevokedToken.
	err = store.RemoveRevokedToken(tokenID)
	require.NoError(t, err)

	revoked, err = store.IsTokenRevoked(tokenID)
	require.NoError(t, err)
	assert.False(t, revoked)

	// Test CountRevokedTokens.
	_ = store.SaveRevokedToken("token1", time.Now().Add(1*time.Hour))
	_ = store.SaveRevokedToken("token2", time.Now().Add(1*time.Hour))
	_ = store.SaveRevokedToken("token3", time.Now().Add(1*time.Hour))

	count, err := store.CountRevokedTokens()
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestSQLiteStore_CleanupExpiredRevocations(t *testing.T) {
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSQLiteStore(SQLiteStoreConfig{
		Path:      dbPath,
		CreateDir: true,
	})
	require.NoError(t, err)
	defer store.Close()

	// Add some tokens with different expiry times.
	_ = store.SaveRevokedToken("expired1", time.Now().Add(-1*time.Hour))
	_ = store.SaveRevokedToken("expired2", time.Now().Add(-30*time.Minute))
	_ = store.SaveRevokedToken("valid", time.Now().Add(1*time.Hour))
	_ = store.SaveRevokedToken("permanent", time.Time{}) // Zero time = permanent.

	count, _ := store.CountRevokedTokens()
	assert.Equal(t, 4, count)

	// Cleanup expired.
	cleaned, err := store.CleanupExpiredRevocations()
	require.NoError(t, err)
	assert.Equal(t, 2, cleaned)

	// Check remaining.
	count, _ = store.CountRevokedTokens()
	assert.Equal(t, 2, count)

	// Valid and permanent should still be revoked.
	revoked, _ := store.IsTokenRevoked("valid")
	assert.True(t, revoked)

	revoked, _ = store.IsTokenRevoked("permanent")
	assert.True(t, revoked)

	// Expired should be cleaned.
	revoked, _ = store.IsTokenRevoked("expired1")
	assert.False(t, revoked)
}

func TestSQLiteStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "test.db")

	// Open store and write data.
	store1, err := NewSQLiteStore(SQLiteStoreConfig{
		Path:      dbPath,
		CreateDir: true,
	})
	require.NoError(t, err)

	team := &TeamInfo{
		Name:      "persistent-team",
		CreatedAt: time.Now().Truncate(time.Second),
		Tokens:    42,
	}
	_ = store1.SaveTeam(team)
	_ = store1.SaveRevokedToken("revoked-token", time.Now().Add(1*time.Hour))

	// Close store.
	store1.Close()

	// Re-open store and verify data persisted.
	store2, err := NewSQLiteStore(SQLiteStoreConfig{
		Path:      dbPath,
		CreateDir: false,
	})
	require.NoError(t, err)
	defer store2.Close()

	// Verify team persisted.
	retrieved, err := store2.GetTeam("persistent-team")
	require.NoError(t, err)
	assert.Equal(t, "persistent-team", retrieved.Name)
	assert.Equal(t, 42, retrieved.Tokens)

	// Verify revoked token persisted.
	revoked, err := store2.IsTokenRevoked("revoked-token")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestSQLiteStore_UpdateTeam(t *testing.T) {
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSQLiteStore(SQLiteStoreConfig{
		Path:      dbPath,
		CreateDir: true,
	})
	require.NoError(t, err)
	defer store.Close()

	// Save initial team.
	team := &TeamInfo{
		Name:      "test-team",
		CreatedAt: time.Now().Truncate(time.Second),
		Tokens:    1,
	}
	_ = store.SaveTeam(team)

	// Update team (upsert).
	team.Tokens = 10
	_ = store.SaveTeam(team)

	// Verify update.
	retrieved, _ := store.GetTeam("test-team")
	assert.Equal(t, 10, retrieved.Tokens)
}

func TestSQLiteStore_DefaultPath(t *testing.T) {
	path := DefaultSQLiteStorePath()
	assert.Contains(t, path, "wormhole.db")
}
