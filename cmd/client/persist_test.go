package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersistentConfig_SaveAndLoad(t *testing.T) {
	// Create a temporary home directory.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Initially, config should be empty.
	cfg, err := LoadPersistentConfig()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.ServerAddr)
	assert.Equal(t, "", cfg.Token)

	// Save a config.
	cfg = &PersistentConfig{
		ServerAddr:    "example.com:7000",
		Token:         "secret-token",
		Subdomain:     "myapp",
		TLSEnabled:    true,
		InspectorPort: 9000,
	}
	p2pEnabled := true
	cfg.P2PEnabled = &p2pEnabled

	err = SavePersistentConfig(cfg)
	require.NoError(t, err)

	// Verify file exists with correct permissions.
	path := filepath.Join(tmpHome, ".wormhole", "config.yaml")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Load and verify.
	loaded, err := LoadPersistentConfig()
	require.NoError(t, err)
	assert.Equal(t, "example.com:7000", loaded.ServerAddr)
	assert.Equal(t, "secret-token", loaded.Token)
	assert.Equal(t, "myapp", loaded.Subdomain)
	assert.True(t, loaded.TLSEnabled)
	assert.Equal(t, 9000, loaded.InspectorPort)
	require.NotNil(t, loaded.P2PEnabled)
	assert.True(t, *loaded.P2PEnabled)
}

func TestApplyPersistentConfig(t *testing.T) {
	// Start with default config.
	cfg := DefaultConfig()

	// Persistent config has some values.
	p2pEnabled := false
	persistent := &PersistentConfig{
		ServerAddr:    "saved.example.com:7000",
		Token:         "saved-token",
		Subdomain:     "saved-subdomain",
		InspectorPort: 8888,
		P2PEnabled:    &p2pEnabled,
	}

	// No flags set — should apply all persistent values.
	flags := &FlagValues{}
	ApplyPersistentConfig(&cfg, persistent, flags)

	assert.Equal(t, "saved.example.com:7000", cfg.ServerAddr)
	assert.Equal(t, "saved-token", cfg.Token)
	assert.Equal(t, "saved-subdomain", cfg.Subdomain)
	assert.Equal(t, 8888, cfg.InspectorPort)
	assert.False(t, cfg.P2PEnabled)
}

func TestApplyPersistentConfig_FlagsOverride(t *testing.T) {
	// Start with config from command line.
	cfg := DefaultConfig()
	cfg.ServerAddr = "cli.example.com:7000"
	cfg.Token = "cli-token"

	// Persistent config has different values.
	persistent := &PersistentConfig{
		ServerAddr: "saved.example.com:7000",
		Token:      "saved-token",
	}

	// ServerAddr and Token were set via flags.
	flags := &FlagValues{
		ServerAddrSet: true,
		TokenSet:      true,
	}
	ApplyPersistentConfig(&cfg, persistent, flags)

	// Should keep CLI values, not persistent.
	assert.Equal(t, "cli.example.com:7000", cfg.ServerAddr)
	assert.Equal(t, "cli-token", cfg.Token)
}

func TestClearToken(t *testing.T) {
	// Create a temporary home directory.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Save a config with token.
	cfg := &PersistentConfig{
		ServerAddr: "example.com:7000",
		Token:      "secret-token",
	}
	err := SavePersistentConfig(cfg)
	require.NoError(t, err)

	// Clear token.
	err = ClearToken()
	require.NoError(t, err)

	// Verify token is cleared.
	loaded, err := LoadPersistentConfig()
	require.NoError(t, err)
	assert.Equal(t, "", loaded.Token)
	assert.Equal(t, "example.com:7000", loaded.ServerAddr) // Other fields preserved.
}

func TestLoadPersistentConfig_NonExistent(t *testing.T) {
	// Create a temporary home directory with no config.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Should return empty config, not error.
	cfg, err := LoadPersistentConfig()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.ServerAddr)
	assert.Equal(t, "", cfg.Token)
}

func TestUpdatePersistentConfig(t *testing.T) {
	// Create a temporary home directory.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Runtime config.
	cfg := &Config{
		ServerAddr:    "updated.example.com:7000",
		Token:         "new-token",
		Subdomain:     "newapp",
		TLSEnabled:    true,
		InspectorPort: 9999,
		P2PEnabled:    true,
	}

	// Update with token save.
	err := UpdatePersistentConfig(cfg, true)
	require.NoError(t, err)

	// Verify.
	loaded, err := LoadPersistentConfig()
	require.NoError(t, err)
	assert.Equal(t, "updated.example.com:7000", loaded.ServerAddr)
	assert.Equal(t, "new-token", loaded.Token)
	assert.Equal(t, "newapp", loaded.Subdomain)
	assert.True(t, loaded.TLSEnabled)
	assert.Equal(t, 9999, loaded.InspectorPort)
}

func TestUpdatePersistentConfig_NoTokenSave(t *testing.T) {
	// Create a temporary home directory.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Pre-existing config with token.
	existing := &PersistentConfig{
		ServerAddr: "old.example.com:7000",
		Token:      "old-token",
	}
	err := SavePersistentConfig(existing)
	require.NoError(t, err)

	// Runtime config with new token.
	cfg := &Config{
		ServerAddr: "new.example.com:7000",
		Token:      "new-token",
	}

	// Update WITHOUT saving token.
	err = UpdatePersistentConfig(cfg, false)
	require.NoError(t, err)

	// Token should be unchanged.
	loaded, err := LoadPersistentConfig()
	require.NoError(t, err)
	assert.Equal(t, "new.example.com:7000", loaded.ServerAddr)
	assert.Equal(t, "old-token", loaded.Token) // Token preserved!
}
