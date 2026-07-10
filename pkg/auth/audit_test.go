package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingAuditStore is a minimal AuditStore whose Store method always
// fails, used to exercise AuditLogger's A4 error-counting path.
type failingAuditStore struct{}

func (failingAuditStore) Store(AuditEvent) error { return errors.New("store unavailable") }
func (failingAuditStore) Query(AuditQuery) ([]AuditEvent, error) {
	return nil, errors.New("store unavailable")
}
func (failingAuditStore) DeleteOlderThan(time.Time) (int64, error) { return 0, nil }
func (failingAuditStore) Close() error                             { return nil }

func TestAuditLogger_Disabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: false,
		Writer:  &buf,
	})

	logger.LogAuthSuccess("192.168.1.1", "team1", RoleMember, "sess1", "app1")

	// Nothing should be written when disabled.
	assert.Empty(t, buf.String())
}

func TestAuditLogger_AuthSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogAuthSuccess("192.168.1.1", "team1", RoleMember, "sess1", "app1")

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventAuthSuccess, event.Type)
	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Equal(t, "team1", event.TeamName)
	assert.Equal(t, "member", event.Role)
	assert.Equal(t, "sess1", event.SessionID)
	assert.Equal(t, "app1", event.Subdomain)
	assert.False(t, event.Timestamp.IsZero())
}

// TestAuditLogger_StoreErrors_CountsFailures verifies A4: a persistently
// failing AuditStore is counted rather than silently and invisibly
// swallowed, and logging still succeeds to the JSON-line writer.
func TestAuditLogger_StoreErrors_CountsFailures(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
		Store:   failingAuditStore{},
	})

	assert.Equal(t, uint64(0), logger.StoreErrors())

	logger.LogAuthSuccess("192.168.1.1", "team1", RoleMember, "sess1", "app1")
	logger.LogAuthFailure("192.168.1.1", "bad token")

	assert.Equal(t, uint64(2), logger.StoreErrors())
	// The writer path is independent of the store and must still work.
	assert.NotEmpty(t, buf.String())
}

// TestAuditLogger_StoreErrors_NoStoreConfigured verifies that without a
// Store configured, StoreErrors stays at zero (there's nothing to fail).
func TestAuditLogger_StoreErrors_NoStoreConfigured(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogAuthSuccess("192.168.1.1", "team1", RoleMember, "sess1", "app1")
	assert.Equal(t, uint64(0), logger.StoreErrors())
}

func TestAuditLogger_AuthFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogAuthFailure("192.168.1.1", "invalid token")

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventAuthFailure, event.Type)
	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Equal(t, "invalid token", event.Error)
}

func TestAuditLogger_IPBlocked(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogIPBlocked("192.168.1.1", 5)

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventIPBlocked, event.Type)
	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Equal(t, float64(5), event.Details["failure_count"])
}

func TestAuditLogger_IPUnblocked(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogIPUnblocked("192.168.1.1", true)

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventIPUnblocked, event.Type)
	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Equal(t, true, event.Details["manual"])
}

func TestAuditLogger_TokenGenerated(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogTokenGenerated("team1", RoleAdmin)

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventTokenGenerated, event.Type)
	assert.Equal(t, "team1", event.TeamName)
	assert.Equal(t, "admin", event.Role)
}

func TestAuditLogger_ClientConnected(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogClientConnected("192.168.1.1", "sess1", "app1", "team1", RoleMember)

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventClientConnected, event.Type)
	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Equal(t, "sess1", event.SessionID)
	assert.Equal(t, "app1", event.Subdomain)
	assert.Equal(t, "team1", event.TeamName)
	assert.Equal(t, "member", event.Role)
}

func TestAuditLogger_ClientDisconnected(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogClientDisconnected("sess1", "app1", 5*time.Minute)

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, EventClientDisconnected, event.Type)
	assert.Equal(t, "sess1", event.SessionID)
	assert.Equal(t, "app1", event.Subdomain)
	assert.Equal(t, float64(300), event.Details["duration_seconds"])
}

func TestAuditLogger_SetEnabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: false,
		Writer:  &buf,
	})

	assert.False(t, logger.IsEnabled())

	logger.SetEnabled(true)
	assert.True(t, logger.IsEnabled())

	logger.LogAuthSuccess("192.168.1.1", "team1", RoleMember, "sess1", "app1")
	assert.NotEmpty(t, buf.String())
}

func TestAuditLogger_LogWithTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	customTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	logger.Log(AuditEvent{
		Timestamp: customTime,
		Type:      EventAuthSuccess,
		IP:        "192.168.1.1",
	})

	var event AuditEvent
	err := json.Unmarshal(buf.Bytes(), &event)
	require.NoError(t, err)

	assert.Equal(t, customTime, event.Timestamp)
}

func TestAuditLogger_MultipleEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Writer:  &buf,
	})

	logger.LogAuthSuccess("192.168.1.1", "team1", RoleMember, "sess1", "app1")
	logger.LogAuthFailure("192.168.1.2", "invalid token")

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	assert.Len(t, lines, 2)

	var event1 AuditEvent
	err := json.Unmarshal(lines[0], &event1)
	require.NoError(t, err)
	assert.Equal(t, EventAuthSuccess, event1.Type)

	var event2 AuditEvent
	err = json.Unmarshal(lines[1], &event2)
	require.NoError(t, err)
	assert.Equal(t, EventAuthFailure, event2.Type)
}
