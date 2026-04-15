package client

import (
	"time"

	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/tunnel"
)

// TunnelDef describes a single tunnel in multi-tunnel mode (config file).
type TunnelDef struct {
	// Name is the unique identifier for this tunnel definition.
	Name string

	// LocalPort is the local port to expose.
	LocalPort int

	// LocalHost is the local host to forward to (defaults to 127.0.0.1).
	LocalHost string

	// Protocol is the tunnel protocol: http, tcp, udp, ws, grpc (default: http).
	Protocol string

	// Subdomain is the requested subdomain (optional).
	Subdomain string

	// Hostname is a custom hostname for routing (optional).
	Hostname string

	// PathPrefix is a path-based routing prefix (optional).
	PathPrefix string
}

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

	// InspectorHost is the host the inspector UI binds to (default: 127.0.0.1).
	InspectorHost string

	// TLSEnabled enables TLS for server connection.
	TLSEnabled bool

	// TLSInsecure skips TLS certificate verification.
	TLSInsecure bool

	// TLSCACert is the path to a custom CA certificate for verifying the server.
	TLSCACert string

	// Protocol is the tunnel protocol type (e.g. "http", "tcp", "udp", "ws", "grpc").
	// Defaults to "http" if empty.
	Protocol string

	// Hostname is the custom hostname for routing (optional).
	Hostname string

	// PathPrefix is the path-based routing prefix (optional).
	PathPrefix string

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

	// Tunnels holds additional tunnel definitions for multi-tunnel mode.
	// When non-empty, all tunnels are registered during connect.
	// The primary tunnel (LocalPort/Protocol/etc.) is still registered first
	// if LocalPort > 0; additional ones come from this slice.
	Tunnels []TunnelDef

	// CtrlPort is the port for the local control HTTP server.
	// 0 disables the control server (default).
	// The control server exposes /tunnels for `wormhole tunnels list`.
	CtrlPort int

	// CtrlHost is the host the control server binds to (default: 127.0.0.1).
	CtrlHost string
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() Config {
	return Config{
		ServerAddr:           "localhost:7000",
		LocalPort:            8080,
		LocalHost:            defaultLocalHost,
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
