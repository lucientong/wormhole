package server

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// FileConfig is the YAML schema for a wormhole server configuration file
// (loaded via `wormhole server -c server.yml`), covering the same settings
// exposed via CLI flags so operators can check a config into version
// control instead of maintaining a long flag invocation. Durations are
// plain strings parsed with time.ParseDuration (e.g. "30s", "5m").
//
// Example:
//
//	listen_addr: :7000
//	http_addr: :80
//	admin_addr: 127.0.0.1:7001
//	domain: tunnel.example.com
//	tls:
//	  enabled: true
//	require_auth: true
//	auth_secret: my-secret-key-at-least-16-chars
//	persistence:
//	  type: sqlite
//	audit:
//	  enabled: true
//	  retention_days: 90
type FileConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	HTTPAddr   string `yaml:"http_addr"`
	AdminAddr  string `yaml:"admin_addr"`
	Domain     string `yaml:"domain"`

	TLS struct {
		Enabled          bool   `yaml:"enabled"`
		CertFile         string `yaml:"cert_file"`
		KeyFile          string `yaml:"key_file"`
		AutoTLS          bool   `yaml:"auto_tls"`
		AutoTLSEmail     string `yaml:"auto_tls_email"`
		TunnelTLSEnabled *bool  `yaml:"tunnel_tls_enabled"`
	} `yaml:"tls"`

	TCPPortRange struct {
		Start int `yaml:"start"`
		End   int `yaml:"end"`
	} `yaml:"tcp_port_range"`

	Timeouts struct {
		Read     string `yaml:"read"`
		Write    string `yaml:"write"`
		Idle     string `yaml:"idle"`
		Shutdown string `yaml:"shutdown"`
		Auth     string `yaml:"auth"`
	} `yaml:"timeouts"`

	MaxClients                 int `yaml:"max_clients"`
	MaxTunnelsPerClient        int `yaml:"max_tunnels_per_client"`
	MaxConcurrentStreams       int `yaml:"max_concurrent_streams"`
	MaxStreamsPerClient        int `yaml:"max_streams_per_client"`
	MaxControlStreamsPerClient int `yaml:"max_control_streams_per_client"`

	RequireAuth bool     `yaml:"require_auth"`
	AuthTokens  []string `yaml:"auth_tokens"`
	AuthSecret  string   `yaml:"auth_secret"`
	AdminToken  string   `yaml:"admin_token"`

	MinClientVersion string `yaml:"min_client_version"`

	// ReservedSubdomains overrides Config.ReservedSubdomains. A present
	// but empty list (`reserved_subdomains: []`) disables the check;
	// omitting the key entirely keeps DefaultConfig's built-in list.
	ReservedSubdomains *[]string `yaml:"reserved_subdomains"`

	RateLimit struct {
		Enabled       bool   `yaml:"enabled"`
		MaxFailures   int    `yaml:"max_failures"`
		Window        string `yaml:"window"`
		BlockDuration string `yaml:"block_duration"`
	} `yaml:"rate_limit"`

	Persistence struct {
		Type string `yaml:"type"` // "memory" (default), "sqlite", or "redis"
		Path string `yaml:"path"`
	} `yaml:"persistence"`

	EnableMetrics *bool `yaml:"enable_metrics"`

	OIDC struct {
		Issuer         string `yaml:"issuer"`
		ClientID       string `yaml:"client_id"`
		TeamClaim      string `yaml:"team_claim"`
		RoleClaim      string `yaml:"role_claim"`
		AllowAdminRole bool   `yaml:"allow_admin_role"`
	} `yaml:"oidc"`

	Audit struct {
		Enabled       bool   `yaml:"enabled"`
		Persistence   string `yaml:"persistence"` // "memory" (default) or "sqlite"
		Path          string `yaml:"path"`
		BufferSize    int    `yaml:"buffer_size"`
		RetentionDays *int   `yaml:"retention_days"`
	} `yaml:"audit"`

	Cluster struct {
		NodeID        string `yaml:"node_id"`
		NodeAddr      string `yaml:"node_addr"`
		StateBackend  string `yaml:"state_backend"` // "memory" (default) or "redis"
		RedisAddr     string `yaml:"redis_addr"`
		RedisPassword string `yaml:"redis_password"`
		RedisDB       int    `yaml:"redis_db"`
		Secret        string `yaml:"secret"`
	} `yaml:"cluster"`

	AuthRedis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"auth_redis"`
}

// LoadServerFileConfig reads and parses a YAML server configuration file.
func LoadServerFileConfig(path string) (*FileConfig, error) {
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

// validate checks the config for internally-inconsistent or malformed
// values that would otherwise fail confusingly deep inside Config
// consumers (e.g. an unparseable duration surfacing as a silent zero
// timeout rather than a config-file error at load time).
func (fc *FileConfig) validate() error {
	durations := map[string]string{
		"timeouts.read":             fc.Timeouts.Read,
		"timeouts.write":            fc.Timeouts.Write,
		"timeouts.idle":             fc.Timeouts.Idle,
		"timeouts.shutdown":         fc.Timeouts.Shutdown,
		"timeouts.auth":             fc.Timeouts.Auth,
		"rate_limit.window":         fc.RateLimit.Window,
		"rate_limit.block_duration": fc.RateLimit.BlockDuration,
	}
	for field, v := range durations {
		if v == "" {
			continue
		}
		if _, err := time.ParseDuration(v); err != nil {
			return fmt.Errorf("%s: invalid duration %q: %w", field, v, err)
		}
	}

	switch fc.Persistence.Type {
	case "", string(PersistenceMemory), string(PersistenceSQLite), string(PersistenceRedis):
	default:
		return fmt.Errorf("persistence.type: must be one of memory, sqlite, redis, got %q", fc.Persistence.Type)
	}
	switch fc.Audit.Persistence {
	case "", string(PersistenceMemory), string(PersistenceSQLite):
	default:
		return fmt.Errorf("audit.persistence: must be one of memory, sqlite, got %q", fc.Audit.Persistence)
	}
	switch fc.Cluster.StateBackend {
	case "", ClusterBackendMemory, ClusterBackendRedis:
	default:
		return fmt.Errorf("cluster.state_backend: must be one of memory, redis, got %q", fc.Cluster.StateBackend)
	}
	return nil
}

// ToServerConfig converts a FileConfig into a server.Config, starting
// from base (typically DefaultConfig()) and overriding only the fields
// explicitly set in the file. Zero-value string/int fields are treated
// as "not set" and left at base's value, mirroring the client's
// FileConfig.ToClientConfig; bools that need a real tri-state
// (unset/false/true) use a *bool.
func (fc *FileConfig) ToServerConfig(base Config) Config {
	cfg := base

	fc.applyCore(&cfg)
	fc.applyTLS(&cfg)
	fc.applyLimitsAndAuth(&cfg)
	fc.applyRateLimitAndPersistence(&cfg)
	fc.applyOIDCAndAudit(&cfg)
	fc.applyCluster(&cfg)

	return cfg
}

func (fc *FileConfig) applyCore(cfg *Config) {
	overrideString(&cfg.ListenAddr, fc.ListenAddr)
	overrideString(&cfg.HTTPAddr, fc.HTTPAddr)
	overrideString(&cfg.AdminAddr, fc.AdminAddr)
	overrideString(&cfg.Domain, fc.Domain)

	if fc.TCPPortRange.Start > 0 {
		cfg.TCPPortRangeStart = fc.TCPPortRange.Start
	}
	if fc.TCPPortRange.End > 0 {
		cfg.TCPPortRangeEnd = fc.TCPPortRange.End
	}

	overrideDuration(&cfg.ReadTimeout, fc.Timeouts.Read)
	overrideDuration(&cfg.WriteTimeout, fc.Timeouts.Write)
	overrideDuration(&cfg.IdleTimeout, fc.Timeouts.Idle)
	overrideDuration(&cfg.ShutdownTimeout, fc.Timeouts.Shutdown)
	overrideDuration(&cfg.AuthTimeout, fc.Timeouts.Auth)

	if fc.EnableMetrics != nil {
		cfg.EnableMetrics = *fc.EnableMetrics
	}
}

func (fc *FileConfig) applyTLS(cfg *Config) {
	if fc.TLS.Enabled {
		cfg.TLSEnabled = true
	}
	overrideString(&cfg.TLSCertFile, fc.TLS.CertFile)
	overrideString(&cfg.TLSKeyFile, fc.TLS.KeyFile)
	if fc.TLS.AutoTLS {
		cfg.AutoTLS = true
	}
	overrideString(&cfg.AutoTLSEmail, fc.TLS.AutoTLSEmail)
	if fc.TLS.TunnelTLSEnabled != nil {
		cfg.TunnelTLSEnabled = *fc.TLS.TunnelTLSEnabled
	}
}

func (fc *FileConfig) applyLimitsAndAuth(cfg *Config) {
	overrideInt(&cfg.MaxClients, fc.MaxClients)
	overrideInt(&cfg.MaxTunnelsPerClient, fc.MaxTunnelsPerClient)
	overrideInt(&cfg.MaxConcurrentStreams, fc.MaxConcurrentStreams)
	overrideInt(&cfg.MaxStreamsPerClient, fc.MaxStreamsPerClient)
	overrideInt(&cfg.MaxControlStreamsPerClient, fc.MaxControlStreamsPerClient)

	if fc.RequireAuth {
		cfg.RequireAuth = true
	}
	if len(fc.AuthTokens) > 0 {
		cfg.AuthTokens = fc.AuthTokens
	}
	overrideString(&cfg.AuthSecret, fc.AuthSecret)
	overrideString(&cfg.AdminToken, fc.AdminToken)
	overrideString(&cfg.MinClientVersion, fc.MinClientVersion)
	if fc.ReservedSubdomains != nil {
		cfg.ReservedSubdomains = *fc.ReservedSubdomains
	}
}

func (fc *FileConfig) applyRateLimitAndPersistence(cfg *Config) {
	if fc.RateLimit.Enabled {
		cfg.RateLimitEnabled = true
	}
	overrideInt(&cfg.RateLimitMaxFailures, fc.RateLimit.MaxFailures)
	overrideDuration(&cfg.RateLimitWindow, fc.RateLimit.Window)
	overrideDuration(&cfg.RateLimitBlockDuration, fc.RateLimit.BlockDuration)

	switch fc.Persistence.Type {
	case string(PersistenceSQLite):
		cfg.Persistence = PersistenceSQLite
	case string(PersistenceRedis):
		cfg.Persistence = PersistenceRedis
	}
	overrideString(&cfg.PersistencePath, fc.Persistence.Path)
}

func (fc *FileConfig) applyOIDCAndAudit(cfg *Config) {
	overrideString(&cfg.OIDCIssuer, fc.OIDC.Issuer)
	overrideString(&cfg.OIDCClientID, fc.OIDC.ClientID)
	overrideString(&cfg.OIDCTeamClaim, fc.OIDC.TeamClaim)
	overrideString(&cfg.OIDCRoleClaim, fc.OIDC.RoleClaim)
	if fc.OIDC.AllowAdminRole {
		cfg.OIDCAllowAdminRole = true
	}

	if fc.Audit.Enabled {
		cfg.AuditEnabled = true
	}
	if fc.Audit.Persistence == string(PersistenceSQLite) {
		cfg.AuditPersistence = PersistenceSQLite
	}
	overrideString(&cfg.AuditPath, fc.Audit.Path)
	overrideInt(&cfg.AuditBufferSize, fc.Audit.BufferSize)
	if fc.Audit.RetentionDays != nil {
		cfg.AuditRetentionDays = *fc.Audit.RetentionDays
	}
}

func (fc *FileConfig) applyCluster(cfg *Config) {
	overrideString(&cfg.ClusterNodeID, fc.Cluster.NodeID)
	overrideString(&cfg.ClusterNodeAddr, fc.Cluster.NodeAddr)
	if fc.Cluster.StateBackend != "" {
		cfg.ClusterStateBackend = fc.Cluster.StateBackend
	}
	overrideString(&cfg.ClusterRedisAddr, fc.Cluster.RedisAddr)
	overrideString(&cfg.ClusterRedisPassword, fc.Cluster.RedisPassword)
	overrideInt(&cfg.ClusterRedisDB, fc.Cluster.RedisDB)
	overrideString(&cfg.ClusterSecret, fc.Cluster.Secret)

	overrideString(&cfg.AuthRedisAddr, fc.AuthRedis.Addr)
	overrideString(&cfg.AuthRedisPassword, fc.AuthRedis.Password)
	overrideInt(&cfg.AuthRedisDB, fc.AuthRedis.DB)
}

func overrideString(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func overrideInt(dst *int, v int) {
	if v != 0 {
		*dst = v
	}
}

// overrideDuration parses v (if non-empty) and assigns it to dst.
// validate() already rejected unparseable durations at load time, so a
// parse error here can only mean validate() was skipped (e.g. a
// hand-built FileConfig in a test) — silently keep dst's current value
// rather than panicking on config wiring.
func overrideDuration(dst *time.Duration, v string) {
	if v == "" {
		return
	}
	if d, err := time.ParseDuration(v); err == nil {
		*dst = d
	}
}
