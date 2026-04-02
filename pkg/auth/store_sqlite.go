package auth

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	// SQLite driver.
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements Store using SQLite for persistence.
type SQLiteStore struct {
	db *sql.DB
}

// SQLiteStoreConfig configures the SQLite store.
type SQLiteStoreConfig struct {
	// Path is the path to the SQLite database file.
	// If empty, defaults to ~/.wormhole/wormhole.db
	Path string

	// CreateDir creates the parent directory if it doesn't exist.
	CreateDir bool
}

// DefaultSQLiteStorePath returns the default path for the SQLite database.
func DefaultSQLiteStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./wormhole.db"
	}
	return filepath.Join(home, ".wormhole", "wormhole.db")
}

// NewSQLiteStore creates a new SQLite-backed store.
func NewSQLiteStore(config SQLiteStoreConfig) (*SQLiteStore, error) {
	if config.Path == "" {
		config.Path = DefaultSQLiteStorePath()
	}

	// Create parent directory if needed.
	if config.CreateDir {
		dir := filepath.Dir(config.Path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite3", config.Path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}

	// Initialize schema.
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

// initSchema creates the necessary tables if they don't exist.
func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS teams (
		name       TEXT PRIMARY KEY,
		created_at INTEGER NOT NULL,
		tokens     INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS revoked_tokens (
		token_id   TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires 
		ON revoked_tokens(expires_at);
	`

	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// SaveTeam saves a team to SQLite.
func (s *SQLiteStore) SaveTeam(team *TeamInfo) error {
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO teams (name, created_at, tokens) 
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET tokens = excluded.tokens
	`, team.Name, team.CreatedAt.Unix(), team.Tokens)
	return err
}

// GetTeam retrieves a team from SQLite.
func (s *SQLiteStore) GetTeam(name string) (*TeamInfo, error) {
	var team TeamInfo
	var createdAt int64

	ctx := context.Background()
	err := s.db.QueryRowContext(ctx, `
		SELECT name, created_at, tokens FROM teams WHERE name = ?
	`, name).Scan(&team.Name, &createdAt, &team.Tokens)

	if err == sql.ErrNoRows {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, err
	}

	team.CreatedAt = time.Unix(createdAt, 0)
	return &team, nil
}

// ListTeams returns all teams from SQLite.
func (s *SQLiteStore) ListTeams() ([]TeamInfo, error) {
	ctx := context.Background()
	rows, err := s.db.QueryContext(ctx, `SELECT name, created_at, tokens FROM teams`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []TeamInfo
	for rows.Next() {
		var team TeamInfo
		var createdAt int64
		if err := rows.Scan(&team.Name, &createdAt, &team.Tokens); err != nil {
			return nil, err
		}
		team.CreatedAt = time.Unix(createdAt, 0)
		teams = append(teams, team)
	}

	return teams, rows.Err()
}

// DeleteTeam removes a team from SQLite.
func (s *SQLiteStore) DeleteTeam(name string) error {
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `DELETE FROM teams WHERE name = ?`, name)
	return err
}

// SaveRevokedToken saves a revoked token to SQLite.
func (s *SQLiteStore) SaveRevokedToken(tokenID string, expiresAt time.Time) error {
	var expiresAtUnix int64
	if !expiresAt.IsZero() {
		expiresAtUnix = expiresAt.Unix()
	}

	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO revoked_tokens (token_id, expires_at)
		VALUES (?, ?)
		ON CONFLICT(token_id) DO UPDATE SET expires_at = excluded.expires_at
	`, tokenID, expiresAtUnix)
	return err
}

// IsTokenRevoked checks if a token is revoked.
func (s *SQLiteStore) IsTokenRevoked(tokenID string) (bool, error) {
	var count int
	ctx := context.Background()
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM revoked_tokens WHERE token_id = ?
	`, tokenID).Scan(&count)

	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// RemoveRevokedToken removes a token from the revocation list.
func (s *SQLiteStore) RemoveRevokedToken(tokenID string) error {
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE token_id = ?`, tokenID)
	return err
}

// CleanupExpiredRevocations removes expired revocation entries.
func (s *SQLiteStore) CleanupExpiredRevocations() (int, error) {
	now := time.Now().Unix()

	ctx := context.Background()
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM revoked_tokens 
		WHERE expires_at > 0 AND expires_at < ?
	`, now)

	if err != nil {
		return 0, err
	}

	affected, err := result.RowsAffected()
	return int(affected), err
}

// CountRevokedTokens returns the number of revoked tokens.
func (s *SQLiteStore) CountRevokedTokens() (int, error) {
	var count int
	ctx := context.Background()
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM revoked_tokens`).Scan(&count)
	return count, err
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
