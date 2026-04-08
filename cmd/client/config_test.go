package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "localhost:7000", cfg.ServerAddr)
	assert.Equal(t, 8080, cfg.LocalPort)
	assert.Equal(t, "127.0.0.1", cfg.LocalHost)
	assert.Equal(t, 1*time.Second, cfg.ReconnectInterval)
	assert.Equal(t, 60*time.Second, cfg.MaxReconnectInterval)
	assert.Equal(t, 2.0, cfg.ReconnectBackoff)
	assert.Equal(t, 0, cfg.MaxReconnectAttempts)
	assert.Equal(t, 30*time.Second, cfg.HeartbeatInterval)
	assert.Equal(t, 10*time.Second, cfg.HeartbeatTimeout)
	assert.True(t, cfg.P2PEnabled)
}

func TestDefaultConfig_EmptyOptionalFields(t *testing.T) {
	cfg := DefaultConfig()

	// These fields should be zero/empty by default.
	assert.Empty(t, cfg.Subdomain)
	assert.Empty(t, cfg.Token)
	assert.Equal(t, 0, cfg.InspectorPort)
	assert.False(t, cfg.TLSEnabled)
	assert.False(t, cfg.TLSInsecure)
}

func TestDefaultConfig_MuxConfig(t *testing.T) {
	cfg := DefaultConfig()

	// MuxConfig should have sensible defaults from tunnel.DefaultMuxConfig().
	assert.NotZero(t, cfg.MuxConfig.MaxFrameSize)
}

func TestDefaultConfig_P2PConfig(t *testing.T) {
	cfg := DefaultConfig()

	// P2PConfig should have defaults from p2p.DefaultManagerConfig().
	assert.NotNil(t, cfg.P2PConfig)
}

func TestConfig_CustomValues(t *testing.T) {
	cfg := Config{
		ServerAddr:           "example.com:9000",
		LocalPort:            3000,
		LocalHost:            "0.0.0.0",
		Subdomain:            "myapp",
		Token:                "secret",
		InspectorPort:        9090,
		TLSEnabled:           true,
		TLSInsecure:          true,
		ReconnectInterval:    5 * time.Second,
		MaxReconnectInterval: 120 * time.Second,
		ReconnectBackoff:     3.0,
		MaxReconnectAttempts: 10,
		HeartbeatInterval:    15 * time.Second,
		HeartbeatTimeout:     5 * time.Second,
		P2PEnabled:           false,
	}

	assert.Equal(t, "example.com:9000", cfg.ServerAddr)
	assert.Equal(t, 3000, cfg.LocalPort)
	assert.Equal(t, "0.0.0.0", cfg.LocalHost)
	assert.Equal(t, "myapp", cfg.Subdomain)
	assert.Equal(t, "secret", cfg.Token)
	assert.Equal(t, 9090, cfg.InspectorPort)
	assert.True(t, cfg.TLSEnabled)
	assert.True(t, cfg.TLSInsecure)
	assert.Equal(t, 5*time.Second, cfg.ReconnectInterval)
	assert.Equal(t, 120*time.Second, cfg.MaxReconnectInterval)
	assert.Equal(t, 3.0, cfg.ReconnectBackoff)
	assert.Equal(t, 10, cfg.MaxReconnectAttempts)
	assert.Equal(t, 15*time.Second, cfg.HeartbeatInterval)
	assert.Equal(t, 5*time.Second, cfg.HeartbeatTimeout)
	assert.False(t, cfg.P2PEnabled)
}
