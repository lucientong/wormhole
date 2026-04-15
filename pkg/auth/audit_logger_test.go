package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditLogger_ConvenienceMethods verifies that every convenience Log* method
// stores an event of the correct type in the AuditStore.
func TestAuditLogger_ConvenienceMethods(t *testing.T) {
	store := NewMemoryAuditStore(100)
	logger := NewAuditLogger(AuditLoggerConfig{
		Enabled: true,
		Store:   store,
	})

	logger.LogTokenRevoked("tok-abc", "team-alpha")
	logger.LogTeamTokensRevoked("team-alpha")
	logger.LogTunnelCreated("sess-1", "tun-1", "http", "https://abc.example.com")
	logger.LogTunnelClosed("sess-1", "tun-1", "http", "graceful")
	logger.LogP2PEstablished("sess-2", "1.2.3.4:9000")
	logger.LogP2PFallback("sess-2", "symmetric NAT")

	events, err := store.Query(AuditQuery{Limit: 100})
	require.NoError(t, err)
	require.Len(t, events, 6)

	types := make([]AuditEventType, len(events))
	for i, e := range events {
		types[i] = e.Type
	}

	assert.Contains(t, types, EventTokenRevoked)
	assert.Contains(t, types, EventTeamTokensRevoked)
	assert.Contains(t, types, EventTunnelCreated)
	assert.Contains(t, types, EventTunnelClosed)
	assert.Contains(t, types, EventP2PEstablished)
	assert.Contains(t, types, EventP2PFallback)
}

func TestAuditLogger_StoreAccessor(t *testing.T) {
	store := NewMemoryAuditStore(10)
	logger := NewAuditLogger(AuditLoggerConfig{Enabled: true, Store: store})
	assert.Equal(t, store, logger.Store())
}

func TestAuditLogger_DisabledDoesNotStore(t *testing.T) {
	store := NewMemoryAuditStore(10)
	logger := NewAuditLogger(AuditLoggerConfig{Enabled: false, Store: store})

	logger.LogTunnelCreated("sess-1", "tun-1", "http", "https://x.example.com")

	events, err := store.Query(AuditQuery{Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, events, "disabled logger should not write events")
}

func TestAuditLogger_ClientEvents(t *testing.T) {
	store := NewMemoryAuditStore(10)
	logger := NewAuditLogger(AuditLoggerConfig{Enabled: true, Store: store})

	logger.LogClientConnected("10.0.0.1", "sess-x", "abc", "team-x", RoleMember)
	logger.LogClientDisconnected("sess-x", "abc", 30*time.Second)

	events, err := store.Query(AuditQuery{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, events, 2)
}
