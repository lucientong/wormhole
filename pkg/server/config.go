package server

import (
	"time"

	"github.com/lucientong/wormhole/pkg/tunnel"
)

// PersistenceType represents the storage backend type.
type PersistenceType string

const (
	// PersistenceMemory uses in-memory storage (no persistence).
	PersistenceMemory PersistenceType = "memory"
	// PersistenceSQLite uses SQLite for persistent storage.
	PersistenceSQLite PersistenceType = "sqlite"
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

	// TunnelTLSEnabled enables TLS for the tunnel control listener.
	// When true, the tunnel listener is also wrapped with TLS.
	// Defaults to the value of TLSEnabled if not explicitly set.
	TunnelTLSEnabled bool

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
	// 0 means unlimited.
	MaxClients int

	// MaxTunnelsPerClient is the maximum number of tunnels a single client can register.
	// 0 means unlimited.
	MaxTunnelsPerClient int

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

	// RateLimitEnabled enables authentication failure rate limiting.
	RateLimitEnabled bool

	// RateLimitMaxFailures is the max failures before blocking an IP.
	RateLimitMaxFailures int

	// RateLimitWindow is the time window for counting failures.
	RateLimitWindow time.Duration

	// RateLimitBlockDuration is how long to block after exceeding failures.
	RateLimitBlockDuration time.Duration

	// Persistence configures the storage backend for auth data.
	// Options: "memory" (default), "sqlite"
	Persistence PersistenceType

	// PersistencePath is the path to the SQLite database file.
	// Only used when Persistence is "sqlite".
	// If empty, defaults to ~/.wormhole/wormhole.db
	PersistencePath string

	// EnableMetrics enables Prometheus metrics collection and the /metrics endpoint.
	EnableMetrics bool

	// OIDCIssuer enables OIDC JWT token validation.
	// When set, JWT tokens signed by the given issuer are accepted in addition to
	// the HMAC tokens.  Example: "https://accounts.google.com"
	OIDCIssuer string

	// OIDCClientID is the OAuth2 client ID to validate the audience claim.
	OIDCClientID string

	// OIDCTeamClaim is the JWT claim used as the Wormhole team name (default: "email").
	OIDCTeamClaim string

	// OIDCRoleClaim is an optional JWT claim for the Wormhole role.
	OIDCRoleClaim string

	// AuditEnabled enables structured audit logging.
	// When false, no audit events are recorded.
	AuditEnabled bool

	// AuditPersistence controls the storage backend for audit logs.
	// Options: "memory" (default ring buffer) or "sqlite".
	AuditPersistence PersistenceType

	// AuditPath is the path to the SQLite audit database file.
	// Only used when AuditPersistence is "sqlite".
	// If empty, defaults to ~/.wormhole/audit.db.
	AuditPath string

	// AuditBufferSize is the number of events to keep in memory.
	// Only used when AuditPersistence is "memory". Defaults to 10 000.
	AuditBufferSize int

	// ─── Cluster / HA settings ────────────────────────────────────────────────

	// ClusterNodeID is a unique identifier for this node in the cluster.
	// Defaults to the hostname when empty and clustering is enabled.
	ClusterNodeID string

	// ClusterNodeAddr is the address (host:port) other nodes use to reach this
	// node's HTTP listener for cross-node tunnel proxying.
	// Example: "10.0.0.1:7002"
	ClusterNodeAddr string

	// ClusterStateBackend selects the shared-state backend.
	// Options: "memory" (default, single-node) or "redis".
	ClusterStateBackend string

	// ClusterRedisAddr is the Redis server address for the Redis state backend.
	// Required when ClusterStateBackend is "redis".
	ClusterRedisAddr string

	// ClusterRedisPassword is the optional Redis AUTH password.
	ClusterRedisPassword string

	// ClusterRedisDB is the Redis database number (default 0).
	ClusterRedisDB int
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:             ":7000",
		HTTPAddr:               ":80",
		AdminAddr:              ":7001",
		Domain:                 "localhost",
		TLSEnabled:             false,
		TCPPortRangeStart:      10000,
		TCPPortRangeEnd:        20000,
		MuxConfig:              tunnel.DefaultMuxConfig(),
		ReadTimeout:            30 * time.Second,
		WriteTimeout:           30 * time.Second,
		IdleTimeout:            5 * time.Minute,
		MaxClients:             1000,
		MaxTunnelsPerClient:    0, // Unlimited by default.
		RequireAuth:            false,
		AuthTimeout:            10 * time.Second,
		RateLimitEnabled:       true,
		RateLimitMaxFailures:   5,
		RateLimitWindow:        5 * time.Minute,
		RateLimitBlockDuration: 15 * time.Minute,
		Persistence:            PersistenceMemory,
		EnableMetrics:          true,
		AuditEnabled:           false,
		AuditPersistence:       PersistenceMemory,
		AuditBufferSize:        10_000,
	}
}
