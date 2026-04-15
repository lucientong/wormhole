package client

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// FileConfig is the YAML schema for a wormhole configuration file.
//
// Example:
//
//	server: tunnel.example.com:7000
//	tls: true
//	token: my-team-token
//
//	tunnels:
//	  web:
//	    local_port: 8080
//	    protocol: http
//	    subdomain: myapp
//	  api:
//	    local_port: 3000
//	    hostname: api.example.com
//	  db:
//	    local_port: 5432
//	    protocol: tcp
type FileConfig struct {
	// Server is the wormhole server address (host:port).
	Server string `yaml:"server"`

	// TLS enables TLS for the control connection.
	TLS bool `yaml:"tls"`

	// TLSInsecure skips certificate verification (dev only).
	TLSInsecure bool `yaml:"tls_insecure"`

	// TLSCACert is the path to a custom CA certificate.
	TLSCACert string `yaml:"tls_ca"`

	// Token is the authentication token.
	Token string `yaml:"token"`

	// P2P enables P2P connections (default true).
	P2P *bool `yaml:"p2p"`

	// CtrlPort is the local control server port (0 = disabled).
	CtrlPort int `yaml:"ctrl_port"`

	// CtrlHost is the local control server host (default: 127.0.0.1).
	CtrlHost string `yaml:"ctrl_host"`

	// Tunnels maps tunnel names to their definitions.
	Tunnels map[string]FileTunnelDef `yaml:"tunnels"`
}

// FileTunnelDef is the YAML schema for a single tunnel definition.
type FileTunnelDef struct {
	// LocalPort is the local port to expose.
	LocalPort int `yaml:"local_port"`

	// LocalHost is the local host to forward to (default: 127.0.0.1).
	LocalHost string `yaml:"local_host"`

	// Protocol is the tunnel protocol (default: http).
	Protocol string `yaml:"protocol"`

	// Subdomain requests a specific subdomain.
	Subdomain string `yaml:"subdomain"`

	// Hostname is a custom hostname for routing.
	Hostname string `yaml:"hostname"`

	// PathPrefix is a path-based routing prefix.
	PathPrefix string `yaml:"path_prefix"`
}

// LoadFileConfig reads and parses a YAML configuration file.
func LoadFileConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from CLI flag
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	if err := fc.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &fc, nil
}

// validate checks the config for required fields.
func (fc *FileConfig) validate() error {
	if len(fc.Tunnels) == 0 {
		return fmt.Errorf("config file must define at least one tunnel under 'tunnels'")
	}
	for name, t := range fc.Tunnels {
		if t.LocalPort <= 0 || t.LocalPort > 65535 {
			return fmt.Errorf("tunnel %q: local_port must be in 1–65535, got %d", name, t.LocalPort)
		}
	}
	return nil
}

// ToClientConfig converts a FileConfig into a client.Config.
// The first tunnel (alphabetically) becomes the primary tunnel; remaining
// tunnels are placed in Config.Tunnels.
func (fc *FileConfig) ToClientConfig(base Config) Config {
	cfg := base

	if fc.Server != "" {
		cfg.ServerAddr = fc.Server
	}
	if fc.TLS {
		cfg.TLSEnabled = true
	}
	if fc.TLSInsecure {
		cfg.TLSInsecure = true
	}
	if fc.TLSCACert != "" {
		cfg.TLSCACert = fc.TLSCACert
	}
	if fc.Token != "" {
		cfg.Token = fc.Token
	}
	if fc.P2P != nil {
		cfg.P2PEnabled = *fc.P2P
	}
	cfg.CtrlPort = fc.CtrlPort
	if fc.CtrlHost != "" {
		cfg.CtrlHost = fc.CtrlHost
	}

	// Convert each FileTunnelDef to a TunnelDef.
	defs := make([]TunnelDef, 0, len(fc.Tunnels))
	for name, t := range fc.Tunnels {
		localHost := t.LocalHost
		if localHost == "" {
			localHost = defaultLocalHost
		}
		protocol := t.Protocol
		if protocol == "" {
			protocol = protocolHTTP
		}
		defs = append(defs, TunnelDef{
			Name:       name,
			LocalPort:  t.LocalPort,
			LocalHost:  localHost,
			Protocol:   protocol,
			Subdomain:  t.Subdomain,
			Hostname:   t.Hostname,
			PathPrefix: t.PathPrefix,
		})
	}

	cfg.Tunnels = defs
	// Clear the single-tunnel fields to avoid double registration.
	cfg.LocalPort = 0

	return cfg
}
