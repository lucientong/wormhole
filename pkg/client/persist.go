package client

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// PersistentConfig represents the configuration that is persisted to disk.
// Only a subset of Config fields are persisted (user-facing settings).
type PersistentConfig struct {
	// ServerAddr is the default server address.
	ServerAddr string `yaml:"server_addr,omitempty"`

	// Token is the authentication token.
	Token string `yaml:"token,omitempty"`

	// Subdomain is the preferred subdomain.
	Subdomain string `yaml:"subdomain,omitempty"`

	// TLSEnabled enables TLS for server connection.
	TLSEnabled bool `yaml:"tls_enabled,omitempty"`

	// TLSInsecure skips TLS certificate verification.
	TLSInsecure bool `yaml:"tls_insecure,omitempty"`

	// InspectorPort is the default inspector UI port.
	InspectorPort int `yaml:"inspector_port,omitempty"`

	// P2PEnabled enables P2P direct connection attempts.
	P2PEnabled *bool `yaml:"p2p_enabled,omitempty"`
}

const (
	// ConfigDirName is the name of the configuration directory.
	ConfigDirName = ".wormhole"
	// ConfigFileName is the name of the configuration file.
	ConfigFileName = "config.yaml"
)

// configDir returns the path to the configuration directory.
func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ConfigDirName), nil
}

// configPath returns the path to the configuration file.
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

// LoadPersistentConfig loads the persistent configuration from disk.
// Returns an empty config if the file doesn't exist.
func LoadPersistentConfig() (*PersistentConfig, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path) // #nosec G304 -- path is constructed from user home dir, not user input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist, return empty config.
			return &PersistentConfig{}, nil
		}
		return nil, err
	}

	var cfg PersistentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// SavePersistentConfig saves the persistent configuration to disk.
func SavePersistentConfig(cfg *PersistentConfig) error {
	dir, err := configDir()
	if err != nil {
		return err
	}

	// Create config directory if it doesn't exist.
	if mkdirErr := os.MkdirAll(dir, 0700); mkdirErr != nil {
		return mkdirErr
	}

	path, err := configPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Write with restrictive permissions (contains token).
	return os.WriteFile(path, data, 0600)
}

// ApplyPersistentConfig applies the persistent configuration to the runtime config.
// Command-line flags take precedence over persistent config.
func ApplyPersistentConfig(cfg *Config, persistent *PersistentConfig, flags *FlagValues) {
	// Apply persistent values only if not overridden by flags.
	if !flags.ServerAddrSet && persistent.ServerAddr != "" {
		cfg.ServerAddr = persistent.ServerAddr
	}

	if !flags.TokenSet && persistent.Token != "" {
		cfg.Token = persistent.Token
	}

	if !flags.SubdomainSet && persistent.Subdomain != "" {
		cfg.Subdomain = persistent.Subdomain
	}

	if !flags.TLSSet && persistent.TLSEnabled {
		cfg.TLSEnabled = persistent.TLSEnabled
	}

	if !flags.TLSInsecureSet && persistent.TLSInsecure {
		cfg.TLSInsecure = persistent.TLSInsecure
	}

	if !flags.InspectorPortSet && persistent.InspectorPort != 0 {
		cfg.InspectorPort = persistent.InspectorPort
	}

	if !flags.P2PEnabledSet && persistent.P2PEnabled != nil {
		cfg.P2PEnabled = *persistent.P2PEnabled
	}
}

// UpdatePersistentConfig updates the persistent config from the runtime config.
// This is typically called after successful authentication to save the token.
func UpdatePersistentConfig(cfg *Config, saveToken bool) error {
	persistent, err := LoadPersistentConfig()
	if err != nil {
		return err
	}

	// Update fields.
	persistent.ServerAddr = cfg.ServerAddr
	persistent.Subdomain = cfg.Subdomain
	persistent.TLSEnabled = cfg.TLSEnabled
	persistent.TLSInsecure = cfg.TLSInsecure
	persistent.InspectorPort = cfg.InspectorPort
	persistent.P2PEnabled = &cfg.P2PEnabled

	// Only save token if explicitly requested (security consideration).
	if saveToken && cfg.Token != "" {
		persistent.Token = cfg.Token
	}

	return SavePersistentConfig(persistent)
}

// FlagValues tracks which command-line flags were explicitly set.
type FlagValues struct {
	ServerAddrSet    bool
	TokenSet         bool
	SubdomainSet     bool
	TLSSet           bool
	TLSInsecureSet   bool
	TLSCACertSet     bool
	InspectorPortSet bool
	P2PEnabledSet    bool
}

// ClearToken removes the saved token from persistent config.
func ClearToken() error {
	persistent, err := LoadPersistentConfig()
	if err != nil {
		return err
	}

	persistent.Token = ""
	return SavePersistentConfig(persistent)
}
