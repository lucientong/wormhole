package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// SQLite driver (already required by store_sqlite.go).
	_ "github.com/mattn/go-sqlite3"
)

// AuditQuery carries all filtering parameters for audit log retrieval.
type AuditQuery struct {
	// Type filters by event type (empty = all types).
	Type AuditEventType
	// From is the inclusive start time (zero = no lower bound).
	From time.Time
	// To is the inclusive end time (zero = no upper bound).
	To time.Time
	// TeamName filters by team (empty = all teams).
	TeamName string
	// SessionID filters by session (empty = all sessions).
	SessionID string
	// IP filters by client IP (empty = all IPs).
	IP string
	// Limit is the maximum number of events to return (0 = use store default).
	Limit int
	// Offset is the number of events to skip (for pagination).
	Offset int
}

// AuditStore is the persistence interface for audit events.
// Implementations must be safe for concurrent use.
type AuditStore interface {
	// Store persists a single audit event.
	Store(event AuditEvent) error
	// Query retrieves events matching the given filter.
	Query(q AuditQuery) ([]AuditEvent, error)
	// Close releases any held resources.
	Close() error
}

// defaultQueryLimit caps unbounded queries in both store implementations.
const defaultQueryLimit = 1000

// ─── In-memory ring-buffer store ────────────────────────────────────────────

// MemoryAuditStore holds the most recent N audit events in memory.
// Older events are silently dropped when the buffer is full.
type MemoryAuditStore struct {
	mu    sync.RWMutex
	buf   []AuditEvent
	head  int // next write position (ring)
	count int // number of valid entries (≤ capacity)
	cap   int
}

// NewMemoryAuditStore creates a ring-buffer audit store with the given capacity.
// A capacity of 0 uses a default of 10 000.
func NewMemoryAuditStore(capacity int) *MemoryAuditStore {
	if capacity <= 0 {
		capacity = 10_000
	}
	return &MemoryAuditStore{
		buf: make([]AuditEvent, capacity),
		cap: capacity,
	}
}

// Store appends an event to the ring buffer.
func (m *MemoryAuditStore) Store(event AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buf[m.head] = event
	m.head = (m.head + 1) % m.cap
	if m.count < m.cap {
		m.count++
	}
	return nil
}

// Query returns events matching the filter in reverse-chronological order
// (newest first), applying Offset and Limit.
func (m *MemoryAuditStore) Query(q AuditQuery) ([]AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	limit := q.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}

	matched := make([]AuditEvent, 0, min(limit, m.count))
	// Iterate from newest to oldest.
	for i := 0; i < m.count; i++ {
		idx := (m.head - 1 - i + m.cap) % m.cap
		ev := m.buf[idx]
		if !matchesFilter(ev, q) {
			continue
		}
		if q.Offset > 0 {
			q.Offset--
			continue
		}
		matched = append(matched, ev)
		if len(matched) >= limit {
			break
		}
	}
	return matched, nil
}

// Close is a no-op for the in-memory store.
func (m *MemoryAuditStore) Close() error { return nil }

// ─── SQLite-backed store ─────────────────────────────────────────────────────

// SQLiteAuditStore persists audit events to a SQLite database.
type SQLiteAuditStore struct {
	db *sql.DB
}

// SQLiteAuditStoreConfig configures the SQLite audit store.
type SQLiteAuditStoreConfig struct {
	// Path is the file path for the SQLite database.
	// Defaults to ~/.wormhole/audit.db when empty.
	Path string

	// CreateDir creates the parent directory if it doesn't exist.
	CreateDir bool
}

// DefaultSQLiteAuditStorePath returns the default audit database path.
func DefaultSQLiteAuditStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./audit.db"
	}
	return filepath.Join(home, ".wormhole", "audit.db")
}

// NewSQLiteAuditStore opens (or creates) a SQLite audit store.
func NewSQLiteAuditStore(cfg SQLiteAuditStoreConfig) (*SQLiteAuditStore, error) {
	if cfg.Path == "" {
		cfg.Path = DefaultSQLiteAuditStorePath()
	}

	if cfg.CreateDir {
		if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
			return nil, fmt.Errorf("create audit store directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite3", cfg.Path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	s := &SQLiteAuditStore{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteAuditStore) initSchema() error {
	_, err := s.db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS audit_events (
			id         INTEGER  PRIMARY KEY AUTOINCREMENT,
			timestamp  DATETIME NOT NULL,
			type       TEXT     NOT NULL,
			ip         TEXT,
			team_name  TEXT,
			role       TEXT,
			session_id TEXT,
			subdomain  TEXT,
			tunnel_id  TEXT,
			protocol   TEXT,
			error      TEXT,
			details    TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_type       ON audit_events(type);
		CREATE INDEX IF NOT EXISTS idx_audit_team       ON audit_events(team_name);
		CREATE INDEX IF NOT EXISTS idx_audit_session    ON audit_events(session_id);
	`)
	return err
}

// Store inserts one audit event into the database.
func (s *SQLiteAuditStore) Store(event AuditEvent) error {
	var detailsJSON string
	if len(event.Details) > 0 {
		b, err := json.Marshal(event.Details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
		detailsJSON = string(b)
	}

	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO audit_events
			(timestamp, type, ip, team_name, role, session_id, subdomain, tunnel_id, protocol, error, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		string(event.Type),
		event.IP,
		event.TeamName,
		event.Role,
		event.SessionID,
		event.Subdomain,
		event.TunnelID,
		event.Protocol,
		event.Error,
		detailsJSON,
	)
	return err
}

// Query retrieves audit events matching the given filter (newest first).
func (s *SQLiteAuditStore) Query(q AuditQuery) ([]AuditEvent, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}

	where, args := buildWhereClause(q)
	//nolint:gosec // where clause is built by buildWhereClause using only safe placeholder values
	query := fmt.Sprintf(
		`SELECT timestamp, type, ip, team_name, role, session_id, subdomain, tunnel_id, protocol, error, details
		 FROM audit_events %s
		 ORDER BY timestamp DESC, id DESC
		 LIMIT ? OFFSET ?`,
		where,
	)
	args = append(args, limit, q.Offset)

	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var (
			ev          AuditEvent
			tsStr       string
			detailsJSON sql.NullString
		)
		if err := rows.Scan(
			&tsStr,
			&ev.Type,
			&ev.IP,
			&ev.TeamName,
			&ev.Role,
			&ev.SessionID,
			&ev.Subdomain,
			&ev.TunnelID,
			&ev.Protocol,
			&ev.Error,
			&detailsJSON,
		); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		if detailsJSON.Valid && detailsJSON.String != "" {
			_ = json.Unmarshal([]byte(detailsJSON.String), &ev.Details)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// Close closes the underlying database.
func (s *SQLiteAuditStore) Close() error {
	return s.db.Close()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// matchesFilter returns true if ev satisfies all non-zero fields of q.
func matchesFilter(ev AuditEvent, q AuditQuery) bool {
	if q.Type != "" && ev.Type != q.Type {
		return false
	}
	if !q.From.IsZero() && ev.Timestamp.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && ev.Timestamp.After(q.To) {
		return false
	}
	if q.TeamName != "" && ev.TeamName != q.TeamName {
		return false
	}
	if q.SessionID != "" && ev.SessionID != q.SessionID {
		return false
	}
	if q.IP != "" && ev.IP != q.IP {
		return false
	}
	return true
}

// buildWhereClause constructs a SQL WHERE clause from a query filter.
func buildWhereClause(q AuditQuery) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if q.Type != "" {
		clauses = append(clauses, "type = ?")
		args = append(args, string(q.Type))
	}
	if !q.From.IsZero() {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, q.From.UTC().Format(time.RFC3339Nano))
	}
	if !q.To.IsZero() {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, q.To.UTC().Format(time.RFC3339Nano))
	}
	if q.TeamName != "" {
		clauses = append(clauses, "team_name = ?")
		args = append(args, q.TeamName)
	}
	if q.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, q.SessionID)
	}
	if q.IP != "" {
		clauses = append(clauses, "ip = ?")
		args = append(args, q.IP)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}
