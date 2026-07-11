package server

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempServerConfig writes content to a temp YAML file and returns its path.
func writeTempServerConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "wormhole-server-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

const validServerConfigYAML = `
listen_addr: :7000
http_addr: :80
admin_addr: 127.0.0.1:7001
domain: tunnel.example.com

tls:
  enabled: true
  tunnel_tls_enabled: true

tcp_port_range:
  start: 11000
  end: 12000

timeouts:
  read: 45s
  shutdown: 20s

max_clients: 500
max_concurrent_streams: 5000

require_auth: true
auth_tokens:
  - token-a
  - token-b
auth_secret: my-secret-key-at-least-16-chars
min_client_version: 0.6.4

rate_limit:
  enabled: true
  max_failures: 10
  window: 10m

persistence:
  type: sqlite
  path: /var/lib/wormhole/wormhole.db

audit:
  enabled: true
  retention_days: 30

cluster:
  node_id: node-1
  state_backend: redis
  redis_addr: redis.internal:6379
  secret: shared-secret
`

func TestLoadServerFileConfig_Valid(t *testing.T) {
	f := writeTempServerConfig(t, validServerConfigYAML)

	fc, err := LoadServerFileConfig(f)
	require.NoError(t, err)

	assert.Equal(t, ":7000", fc.ListenAddr)
	assert.Equal(t, "tunnel.example.com", fc.Domain)
	assert.True(t, fc.TLS.Enabled)
	require.NotNil(t, fc.TLS.TunnelTLSEnabled)
	assert.True(t, *fc.TLS.TunnelTLSEnabled)
	assert.Equal(t, 11000, fc.TCPPortRange.Start)
	assert.Equal(t, "sqlite", fc.Persistence.Type)
	assert.Equal(t, "redis", fc.Cluster.StateBackend)
}

func TestLoadServerFileConfig_MissingFile(t *testing.T) {
	_, err := LoadServerFileConfig("/nonexistent/path/server.yml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read config file")
}

func TestLoadServerFileConfig_InvalidYAML(t *testing.T) {
	f := writeTempServerConfig(t, "not: valid: yaml: [")
	_, err := LoadServerFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse config file")
}

func TestLoadServerFileConfig_InvalidDuration(t *testing.T) {
	f := writeTempServerConfig(t, "timeouts:\n  read: not-a-duration\n")
	_, err := LoadServerFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config")
	assert.Contains(t, err.Error(), "timeouts.read")
}

func TestLoadServerFileConfig_InvalidPersistenceType(t *testing.T) {
	f := writeTempServerConfig(t, "persistence:\n  type: mongodb\n")
	_, err := LoadServerFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persistence.type")
}

func TestLoadServerFileConfig_InvalidAuditPersistence(t *testing.T) {
	f := writeTempServerConfig(t, "audit:\n  persistence: mongodb\n")
	_, err := LoadServerFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit.persistence")
}

func TestLoadServerFileConfig_InvalidClusterBackend(t *testing.T) {
	f := writeTempServerConfig(t, "cluster:\n  state_backend: etcd\n")
	_, err := LoadServerFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cluster.state_backend")
}

func TestFileConfig_ToServerConfig_OverridesExplicitFields(t *testing.T) {
	f := writeTempServerConfig(t, validServerConfigYAML)
	fc, err := LoadServerFileConfig(f)
	require.NoError(t, err)

	cfg := fc.ToServerConfig(DefaultConfig())

	assert.Equal(t, ":7000", cfg.ListenAddr)
	assert.Equal(t, "tunnel.example.com", cfg.Domain)
	assert.True(t, cfg.TLSEnabled)
	assert.True(t, cfg.TunnelTLSEnabled)
	assert.Equal(t, 11000, cfg.TCPPortRangeStart)
	assert.Equal(t, 12000, cfg.TCPPortRangeEnd)
	assert.Equal(t, 45*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 20*time.Second, cfg.ShutdownTimeout)
	assert.Equal(t, 500, cfg.MaxClients)
	assert.Equal(t, 5000, cfg.MaxConcurrentStreams)
	assert.True(t, cfg.RequireAuth)
	assert.Equal(t, []string{"token-a", "token-b"}, cfg.AuthTokens)
	assert.Equal(t, "my-secret-key-at-least-16-chars", cfg.AuthSecret)
	assert.Equal(t, "0.6.4", cfg.MinClientVersion)
	assert.True(t, cfg.RateLimitEnabled)
	assert.Equal(t, 10, cfg.RateLimitMaxFailures)
	assert.Equal(t, 10*time.Minute, cfg.RateLimitWindow)
	assert.Equal(t, PersistenceSQLite, cfg.Persistence)
	assert.Equal(t, "/var/lib/wormhole/wormhole.db", cfg.PersistencePath)
	assert.True(t, cfg.AuditEnabled)
	assert.Equal(t, 30, cfg.AuditRetentionDays)
	assert.Equal(t, "node-1", cfg.ClusterNodeID)
	assert.Equal(t, "redis", cfg.ClusterStateBackend)
	assert.Equal(t, "redis.internal:6379", cfg.ClusterRedisAddr)
	assert.Equal(t, "shared-secret", cfg.ClusterSecret)
}

// TestFileConfig_ToServerConfig_LeavesUnsetFieldsAtBase verifies that
// fields not mentioned in the YAML file keep base's (DefaultConfig())
// value rather than being zeroed out.
func TestFileConfig_ToServerConfig_LeavesUnsetFieldsAtBase(t *testing.T) {
	f := writeTempServerConfig(t, "domain: tunnel.example.com\n")
	fc, err := LoadServerFileConfig(f)
	require.NoError(t, err)

	base := DefaultConfig()
	cfg := fc.ToServerConfig(base)

	assert.Equal(t, "tunnel.example.com", cfg.Domain)
	assert.Equal(t, base.ListenAddr, cfg.ListenAddr)
	assert.Equal(t, base.MaxClients, cfg.MaxClients)
	assert.Equal(t, base.MaxConcurrentStreams, cfg.MaxConcurrentStreams)
	assert.Equal(t, base.AuthTimeout, cfg.AuthTimeout)
	assert.Equal(t, base.Persistence, cfg.Persistence)
	assert.False(t, cfg.RequireAuth)
	assert.False(t, cfg.AuditEnabled)
}

// TestFileConfig_ToServerConfig_EnableMetricsTriState verifies
// EnableMetrics's *bool tri-state: DefaultConfig() sets it true, and an
// explicit "enable_metrics: false" in the file must actually disable it
// (a plain bool couldn't distinguish "unset" from "explicitly false").
func TestFileConfig_ToServerConfig_EnableMetricsTriState(t *testing.T) {
	base := DefaultConfig()
	require.True(t, base.EnableMetrics, "precondition: default has metrics enabled")

	f := writeTempServerConfig(t, "enable_metrics: false\n")
	fc, err := LoadServerFileConfig(f)
	require.NoError(t, err)

	cfg := fc.ToServerConfig(base)
	assert.False(t, cfg.EnableMetrics)

	// Omitting the field entirely must leave the default untouched.
	f2 := writeTempServerConfig(t, "domain: example.com\n")
	fc2, err := LoadServerFileConfig(f2)
	require.NoError(t, err)
	cfg2 := fc2.ToServerConfig(base)
	assert.True(t, cfg2.EnableMetrics)
}
