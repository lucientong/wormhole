package auth

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEvent creates an AuditEvent with the given type and timestamp offset in seconds.
func testEvent(t AuditEventType, sessionID string, offsetSec int) AuditEvent {
	return AuditEvent{
		Timestamp: time.Now().Add(time.Duration(offsetSec) * time.Second),
		Type:      t,
		SessionID: sessionID,
		TeamName:  "test-team",
		IP:        "127.0.0.1",
	}
}

// ─── MemoryAuditStore ────────────────────────────────────────────────────────

func TestMemoryAuditStore_StoreAndQuery(t *testing.T) {
	store := NewMemoryAuditStore(100)
	defer store.Close()

	events := []AuditEvent{
		testEvent(EventTunnelCreated, "sess-1", -30),
		testEvent(EventAuthSuccess, "sess-2", -20),
		testEvent(EventTunnelClosed, "sess-1", -10),
	}
	for _, ev := range events {
		require.NoError(t, store.Store(ev))
	}

	all, err := store.Query(AuditQuery{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestMemoryAuditStore_FilterByType(t *testing.T) {
	store := NewMemoryAuditStore(100)
	defer store.Close()

	require.NoError(t, store.Store(testEvent(EventTunnelCreated, "s1", -5)))
	require.NoError(t, store.Store(testEvent(EventAuthSuccess, "s2", -4)))
	require.NoError(t, store.Store(testEvent(EventTunnelCreated, "s3", -3)))

	results, err := store.Query(AuditQuery{Type: EventTunnelCreated, Limit: 10})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, ev := range results {
		assert.Equal(t, EventTunnelCreated, ev.Type)
	}
}

func TestMemoryAuditStore_FilterBySession(t *testing.T) {
	store := NewMemoryAuditStore(100)
	defer store.Close()

	require.NoError(t, store.Store(testEvent(EventTunnelCreated, "sess-A", -5)))
	require.NoError(t, store.Store(testEvent(EventTunnelCreated, "sess-B", -4)))

	results, err := store.Query(AuditQuery{SessionID: "sess-A", Limit: 10})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sess-A", results[0].SessionID)
}

func TestMemoryAuditStore_Pagination(t *testing.T) {
	store := NewMemoryAuditStore(100)
	defer store.Close()

	for i := 0; i < 10; i++ {
		require.NoError(t, store.Store(testEvent(EventAuthSuccess, "s", -i)))
	}

	page1, err := store.Query(AuditQuery{Limit: 3, Offset: 0})
	require.NoError(t, err)
	assert.Len(t, page1, 3)

	page2, err := store.Query(AuditQuery{Limit: 3, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, page2, 3)

	// Pages should not overlap.
	for _, ev1 := range page1 {
		for _, ev2 := range page2 {
			assert.NotEqual(t, ev1.Timestamp, ev2.Timestamp)
		}
	}
}

func TestMemoryAuditStore_RingBufferEviction(t *testing.T) {
	const ringCap = 5
	store := NewMemoryAuditStore(ringCap)
	defer store.Close()

	// Store ringCap+2 events; the oldest 2 should be evicted.
	for i := 0; i < ringCap+2; i++ {
		require.NoError(t, store.Store(testEvent(EventAuthSuccess, "s", i)))
	}

	all, err := store.Query(AuditQuery{Limit: 100})
	require.NoError(t, err)
	assert.Len(t, all, ringCap)
}

func TestMemoryAuditStore_TimeFilter(t *testing.T) {
	store := NewMemoryAuditStore(100)
	defer store.Close()

	now := time.Now()
	old := AuditEvent{Timestamp: now.Add(-2 * time.Hour), Type: EventAuthSuccess, SessionID: "old"}
	recent := AuditEvent{Timestamp: now.Add(-1 * time.Minute), Type: EventAuthSuccess, SessionID: "recent"}
	require.NoError(t, store.Store(old))
	require.NoError(t, store.Store(recent))

	results, err := store.Query(AuditQuery{From: now.Add(-30 * time.Minute), Limit: 10})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "recent", results[0].SessionID)
}

// ─── SQLiteAuditStore ────────────────────────────────────────────────────────

func TestSQLiteAuditStore_StoreAndQuery(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-test-*.db")
	require.NoError(t, err)
	f.Close()

	store, err := NewSQLiteAuditStore(SQLiteAuditStoreConfig{Path: f.Name()})
	require.NoError(t, err)
	defer store.Close()

	events := []AuditEvent{
		testEvent(EventTunnelCreated, "sess-1", -30),
		testEvent(EventAuthFailure, "sess-2", -20),
		testEvent(EventTunnelClosed, "sess-1", -10),
	}
	for _, ev := range events {
		require.NoError(t, store.Store(ev))
	}

	all, err := store.Query(AuditQuery{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestSQLiteAuditStore_FilterByType(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-test-*.db")
	require.NoError(t, err)
	f.Close()

	store, err := NewSQLiteAuditStore(SQLiteAuditStoreConfig{Path: f.Name()})
	require.NoError(t, err)
	defer store.Close()

	require.NoError(t, store.Store(testEvent(EventTunnelCreated, "s1", -5)))
	require.NoError(t, store.Store(testEvent(EventAuthSuccess, "s2", -4)))
	require.NoError(t, store.Store(testEvent(EventTunnelCreated, "s3", -3)))

	results, err := store.Query(AuditQuery{Type: EventTunnelCreated, Limit: 10})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, ev := range results {
		assert.Equal(t, EventTunnelCreated, ev.Type)
	}
}

func TestSQLiteAuditStore_FilterBySession(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-test-*.db")
	require.NoError(t, err)
	f.Close()

	store, err := NewSQLiteAuditStore(SQLiteAuditStoreConfig{Path: f.Name()})
	require.NoError(t, err)
	defer store.Close()

	require.NoError(t, store.Store(testEvent(EventP2PEstablished, "sess-A", -5)))
	require.NoError(t, store.Store(testEvent(EventP2PFallback, "sess-B", -4)))

	results, err := store.Query(AuditQuery{SessionID: "sess-A", Limit: 10})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sess-A", results[0].SessionID)
}

func TestSQLiteAuditStore_DetailsRoundtrip(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-test-*.db")
	require.NoError(t, err)
	f.Close()

	store, err := NewSQLiteAuditStore(SQLiteAuditStoreConfig{Path: f.Name()})
	require.NoError(t, err)
	defer store.Close()

	ev := AuditEvent{
		Timestamp: time.Now(),
		Type:      EventTunnelCreated,
		SessionID: "sess-1",
		TunnelID:  "tun-abc",
		Protocol:  "http",
		Details:   map[string]interface{}{"public_url": "https://example.com"},
	}
	require.NoError(t, store.Store(ev))

	results, err := store.Query(AuditQuery{Limit: 1})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "tun-abc", results[0].TunnelID)
	assert.Equal(t, "http", results[0].Protocol)
	assert.Equal(t, "https://example.com", results[0].Details["public_url"])
}
