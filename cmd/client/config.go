package main

import (
	"time"

	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/tunnel"
)

// Config holds the client configuration.
type Config struct {
	// ServerAddr is the server address to connect to.
	ServerAddr string

	// LocalPort is the local port to expose.
	LocalPort int

	// LocalHost is the local host to forward to.
	LocalHost string

	// Subdomain is the requested subdomain (optional).
	Subdomain string

	// Token is the authentication token (optional).
	Token string

	// InspectorPort is the port for the inspector UI (0 to disable).
	InspectorPort int

	// TLSEnabled enables TLS for server connection.
	TLSEnabled bool

	// TLSInsecure skips TLS certificate verification.
	TLSInsecure bool

	// MuxConfig is the multiplexer configuration.
	MuxConfig tunnel.MuxConfig

	// ReconnectInterval is the initial reconnect interval.
	ReconnectInterval time.Duration

	// MaxReconnectInterval is the maximum reconnect interval.
	MaxReconnectInterval time.Duration

	// ReconnectBackoff is the backoff multiplier for reconnection.
	ReconnectBackoff float64

	// MaxReconnectAttempts is the maximum number of reconnection attempts (0 for unlimited).
	MaxReconnectAttempts int

	// HeartbeatInterval is the interval between heartbeats.
	HeartbeatInterval time.Duration

	// HeartbeatTimeout is the timeout for heartbeat responses.
	HeartbeatTimeout time.Duration

	// P2PEnabled enables P2P direct connection attempts.
	P2PEnabled bool

	// P2PConfig is the P2P manager configuration.
	P2PConfig p2p.ManagerConfig
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() Config {
	return Config{
		ServerAddr:           "localhost:7000",
		LocalPort:            8080,
		LocalHost:            "127.0.0.1",
		MuxConfig:            tunnel.DefaultMuxConfig(),
		ReconnectInterval:    1 * time.Second,
		MaxReconnectInterval: 60 * time.Second,
		ReconnectBackoff:     2.0,
		MaxReconnectAttempts: 0, // Unlimited
		HeartbeatInterval:    30 * time.Second,
		HeartbeatTimeout:     10 * time.Second,
		P2PEnabled:           true,
		P2PConfig:            p2p.DefaultManagerConfig(),
	}
}
