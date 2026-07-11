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
	// PersistenceRedis uses Redis for persistent, cluster-shared storage
	// (H5): unlike memory or SQLite, a token revoked or a team's version
	// bumped on one node is immediately visible to every other node,
	// since they all query the same Redis keys instead of a per-node
	// local store.
	PersistenceRedis PersistenceType = "redis"
)

// ClusterStateBackend values selecting the shared-state backend used for
// cross-node route/heartbeat coordination (see Config.ClusterStateBackend).
const (
	// ClusterBackendMemory keeps cluster state in a single process, i.e.
	// effectively single-node; useful for tests and local development.
	ClusterBackendMemory = "memory"
	// ClusterBackendRedis shares cluster state across nodes via Redis.
	ClusterBackendRedis = "redis"
)

// defaultDomain is the default Config.Domain value used for local
// development. It's also the sentinel checked by the ACME/TLS manager to
// skip certificate provisioning, since Let's Encrypt cannot issue certs for
// "localhost".
const defaultDomain = "localhost"

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

	// ShutdownTimeout bounds how long Shutdown waits for in-flight HTTP
	// and admin API requests to finish via http.Server.Shutdown(ctx)
	// (DP-26) before the process moves on to closing everything else.
	// 0 falls back to defaultShutdownTimeout.
	ShutdownTimeout time.Duration

	// MaxClients is the maximum number of concurrent clients.
	// 0 means unlimited.
	MaxClients int

	// MaxTunnelsPerClient is the maximum number of tunnels a single client can register.
	// 0 means unlimited.
	MaxTunnelsPerClient int

	// MaxConcurrentStreams bounds the total number of data-plane streams
	// (HTTP forward, WebSocket, TCP tunnel) proxying concurrently across
	// all clients (DP-03). MaxClients only bounds connection *count*, not
	// per-connection concurrency, so a handful of clients issuing many
	// simultaneous requests could otherwise spawn unbounded goroutines.
	// 0 means unlimited. Saturating this returns 503 (HTTP) or drops the
	// connection (TCP) rather than queuing, to keep worst-case resource
	// use bounded instead of trading it for unbounded added latency.
	MaxConcurrentStreams int

	// MaxStreamsPerClient bounds concurrent data-plane streams for a
	// single client (DP-27), independent of MaxConcurrentStreams, so one
	// noisy/malicious client can't exhaust the global budget by itself.
	// 0 means unlimited.
	MaxStreamsPerClient int

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

	// AuditRetentionDays is how many days of audit events to retain before
	// they're purged by a periodic background sweep (A5). 0 disables the
	// sweep entirely (unbounded retention — the previous, and still the
	// in-memory ring buffer's, default behavior).
	AuditRetentionDays int

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

	// AuthRedisAddr is the Redis address for the auth Store when
	// Persistence is "redis" (H5). Defaults to ClusterRedisAddr when
	// empty, so a single --cluster-redis-addr is enough for the common
	// case of sharing one Redis instance for both cluster routing state
	// and shared auth/revocation state; set explicitly to use a
	// different Redis instance for auth data.
	AuthRedisAddr string

	// AuthRedisPassword is the Redis AUTH password for the auth store.
	// Defaults to ClusterRedisPassword when AuthRedisAddr is empty.
	AuthRedisPassword string

	// AuthRedisDB is the Redis database number for the auth store.
	// Defaults to ClusterRedisDB when AuthRedisAddr is empty.
	AuthRedisDB int

	// ClusterSecret is a shared secret attached to requests forwarded
	// between nodes by proxyToNode (S1). When set, a receiving node
	// rejects any request carrying a mismatched cluster-secret header,
	// distinguishing genuine peer hops from an external caller that
	// reaches ClusterNodeAddr directly. Requests with no such header at
	// all (ordinary external traffic) are unaffected either way.
	ClusterSecret string

	// MinClientVersion, when set, rejects the auth handshake of any
	// client reporting an older semantic version (DP-30) — useful during
	// a rolling upgrade to require clients to update before a breaking
	// wire/behavior change goes live. Must be a "MAJOR.MINOR.PATCH"
	// string (an optional leading "v" is accepted). Left empty (the
	// default) disables the check entirely. Clients reporting a
	// non-semver version (e.g. "dev" builds) are never rejected by this
	// check, since they have no meaningful version to compare.
	MinClientVersion string
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:             ":7000",
		HTTPAddr:               ":80",
		AdminAddr:              ":7001",
		Domain:                 defaultDomain,
		TLSEnabled:             false,
		TCPPortRangeStart:      10000,
		TCPPortRangeEnd:        20000,
		MuxConfig:              tunnel.DefaultMuxConfig(),
		ReadTimeout:            30 * time.Second,
		WriteTimeout:           30 * time.Second,
		IdleTimeout:            5 * time.Minute,
		ShutdownTimeout:        15 * time.Second,
		MaxClients:             1000,
		MaxTunnelsPerClient:    0,     // Unlimited by default.
		MaxConcurrentStreams:   10000, // Global data-plane stream cap (DP-03).
		MaxStreamsPerClient:    500,   // Per-client data-plane stream cap (DP-27).
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
