package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServerDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, ":7000", cfg.ListenAddr)
	assert.Equal(t, ":80", cfg.HTTPAddr)
	assert.Equal(t, ":7001", cfg.AdminAddr)
	assert.Equal(t, "localhost", cfg.Domain)
	assert.False(t, cfg.TLSEnabled)
	assert.Equal(t, 10000, cfg.TCPPortRangeStart)
	assert.Equal(t, 20000, cfg.TCPPortRangeEnd)
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 5*time.Minute, cfg.IdleTimeout)
	assert.Equal(t, 1000, cfg.MaxClients)
	assert.False(t, cfg.RequireAuth)
	assert.Equal(t, 10*time.Second, cfg.AuthTimeout)
	assert.True(t, cfg.RateLimitEnabled)
	assert.Equal(t, 5, cfg.RateLimitMaxFailures)
	assert.Equal(t, 5*time.Minute, cfg.RateLimitWindow)
	assert.Equal(t, 15*time.Minute, cfg.RateLimitBlockDuration)
	assert.Equal(t, PersistenceMemory, cfg.Persistence)
}

func TestServerDefaultConfig_EmptyOptionalFields(t *testing.T) {
	cfg := DefaultConfig()

	assert.Empty(t, cfg.TLSCertFile)
	assert.Empty(t, cfg.TLSKeyFile)
	assert.False(t, cfg.AutoTLS)
	assert.Empty(t, cfg.AutoTLSEmail)
	assert.Empty(t, cfg.AuthTokens)
	assert.Empty(t, cfg.AuthSecret)
	assert.Empty(t, cfg.AdminToken)
	assert.Empty(t, cfg.PersistencePath)
}

func TestServerDefaultConfig_MuxConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.NotZero(t, cfg.MuxConfig.MaxFrameSize)
}

func TestPersistenceType_Constants(t *testing.T) {
	assert.Equal(t, PersistenceType("memory"), PersistenceMemory)
	assert.Equal(t, PersistenceType("sqlite"), PersistenceSQLite)
	assert.NotEqual(t, PersistenceMemory, PersistenceSQLite)
}

func TestServerConfig_CustomValues(t *testing.T) {
	cfg := Config{
		ListenAddr:             ":9000",
		HTTPAddr:               ":443",
		AdminAddr:              ":9001",
		Domain:                 "example.com",
		TLSEnabled:             true,
		TLSCertFile:            "/path/to/cert.pem",
		TLSKeyFile:             "/path/to/key.pem",
		AutoTLS:                true,
		AutoTLSEmail:           "admin@example.com",
		TCPPortRangeStart:      20000,
		TCPPortRangeEnd:        30000,
		ReadTimeout:            60 * time.Second,
		WriteTimeout:           60 * time.Second,
		IdleTimeout:            10 * time.Minute,
		MaxClients:             5000,
		RequireAuth:            true,
		AuthTokens:             []string{"token1", "token2"},
		AuthSecret:             "supersecretkey123",
		AuthTimeout:            30 * time.Second,
		AdminToken:             "admin-secret",
		RateLimitEnabled:       true,
		RateLimitMaxFailures:   10,
		RateLimitWindow:        10 * time.Minute,
		RateLimitBlockDuration: 30 * time.Minute,
		Persistence:            PersistenceSQLite,
		PersistencePath:        "/tmp/wormhole.db",
	}

	assert.Equal(t, ":9000", cfg.ListenAddr)
	assert.Equal(t, ":443", cfg.HTTPAddr)
	assert.Equal(t, ":9001", cfg.AdminAddr)
	assert.Equal(t, "example.com", cfg.Domain)
	assert.True(t, cfg.TLSEnabled)
	assert.Equal(t, "/path/to/cert.pem", cfg.TLSCertFile)
	assert.Equal(t, "/path/to/key.pem", cfg.TLSKeyFile)
	assert.True(t, cfg.AutoTLS)
	assert.Equal(t, "admin@example.com", cfg.AutoTLSEmail)
	assert.Equal(t, 20000, cfg.TCPPortRangeStart)
	assert.Equal(t, 30000, cfg.TCPPortRangeEnd)
	assert.Equal(t, 60*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 60*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 10*time.Minute, cfg.IdleTimeout)
	assert.Equal(t, 5000, cfg.MaxClients)
	assert.True(t, cfg.RequireAuth)
	assert.Len(t, cfg.AuthTokens, 2)
	assert.Equal(t, "supersecretkey123", cfg.AuthSecret)
	assert.Equal(t, 30*time.Second, cfg.AuthTimeout)
	assert.Equal(t, "admin-secret", cfg.AdminToken)
	assert.True(t, cfg.RateLimitEnabled)
	assert.Equal(t, 10, cfg.RateLimitMaxFailures)
	assert.Equal(t, 10*time.Minute, cfg.RateLimitWindow)
	assert.Equal(t, 30*time.Minute, cfg.RateLimitBlockDuration)
	assert.Equal(t, PersistenceSQLite, cfg.Persistence)
	assert.Equal(t, "/tmp/wormhole.db", cfg.PersistencePath)
}
