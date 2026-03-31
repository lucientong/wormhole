package main

import (
	"time"

	"github.com/wormhole-tunnel/wormhole/pkg/tunnel"
)

// Config holds the server configuration.
type Config struct {
	// ListenAddr is the address to listen on for client connections.
	ListenAddr string

	// HTTPAddr is the address to listen on for HTTP traffic.
	HTTPAddr string

	// AdminAddr is the address to listen on for the admin API.
	AdminAddr string

	// Domain is the base domain for tunnel URLs.
	Domain string

	// TLSEnabled enables TLS for client connections.
	TLSEnabled bool

	// TLSCertFile is the path to the TLS certificate.
	TLSCertFile string

	// TLSKeyFile is the path to the TLS private key.
	TLSKeyFile string

	// AutoTLS enables automatic TLS certificate via Let's Encrypt.
	AutoTLS bool

	// AutoTLSEmail is the email for Let's Encrypt registration.
	AutoTLSEmail string

	// TCPPortRange is the range of ports for TCP tunnels.
	TCPPortRangeStart int
	TCPPortRangeEnd   int

	// MuxConfig is the multiplexer configuration.
	MuxConfig tunnel.MuxConfig

	// ReadTimeout is the read timeout for connections.
	ReadTimeout time.Duration

	// WriteTimeout is the write timeout for connections.
	WriteTimeout time.Duration

	// IdleTimeout is the idle timeout for connections.
	IdleTimeout time.Duration

	// MaxClients is the maximum number of concurrent clients.
	MaxClients int

	// RequireAuth requires authentication for connections.
	RequireAuth bool

	// AuthTokens is a list of valid authentication tokens (simple mode).
	AuthTokens []string

	// AuthSecret is the HMAC secret for signed token mode.
	// Must be at least 16 bytes. If empty, only simple token mode is available.
	AuthSecret string

	// AuthTimeout is the timeout for the authentication handshake.
	AuthTimeout time.Duration

	// AdminToken is the token required to access the admin API.
	// If empty, the admin API requires no authentication.
	AdminToken string
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:        ":7000",
		HTTPAddr:          ":80",
		AdminAddr:         ":7001",
		Domain:            "localhost",
		TLSEnabled:        false,
		TCPPortRangeStart: 10000,
		TCPPortRangeEnd:   20000,
		MuxConfig:         tunnel.DefaultMuxConfig(),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxClients:        1000,
		RequireAuth:       false,
		AuthTimeout:       10 * time.Second,
	}
}
