package cmd

import (
	"os"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/server"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTLSTestCmd returns a bare *cobra.Command carrying only the "tunnel-tls"
// bool flag that buildServerConfig() inspects via Flags().Changed(). This
// lets tests control whether the flag was "explicitly set" by the operator
// without going through full CLI argument parsing.
func newTLSTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	var throwaway bool
	cmd.Flags().BoolVar(&throwaway, "tunnel-tls", false, "")
	return cmd
}

// withServerGlobals sets the package-level CLI flag variables consulted by
// buildServerConfig for the duration of the test, restoring their previous
// values on cleanup. These variables are normally populated by cobra flag
// parsing, but buildServerConfig reads them directly as package globals.
// serverTunnelTLS itself is set separately by each test via the returned
// setter, since its effective value depends on whether "tunnel-tls" was
// marked Changed on the *cobra.Command passed to buildServerConfig.
func withServerGlobals(t *testing.T, tlsEnabled, requireAuth bool, domain, certFile, keyFile string) {
	t.Helper()

	origTLS, origAuth, origTunnelTLS := serverTLSEnabled, serverRequireAuth, serverTunnelTLS
	origDomain, origCert, origKey := serverDomain, serverTLSCert, serverTLSKey
	t.Cleanup(func() {
		serverTLSEnabled, serverRequireAuth, serverTunnelTLS = origTLS, origAuth, origTunnelTLS
		serverDomain, serverTLSCert, serverTLSKey = origDomain, origCert, origKey
	})

	serverTLSEnabled = tlsEnabled
	serverRequireAuth = requireAuth
	serverTunnelTLS = false
	serverDomain = domain
	serverTLSCert = certFile
	serverTLSKey = keyFile
}

// TestBuildServerConfig_TunnelTLSDefault_RequireAuthWithDomain verifies S4:
// when --require-auth is set and a real domain is configured, the tunnel
// control channel defaults to TLS even if --tls itself was never passed,
// since auth tokens travel over that channel.
func TestBuildServerConfig_TunnelTLSDefault_RequireAuthWithDomain(t *testing.T) {
	withServerGlobals(t, false, true, "tunnel.example.com", "", "")
	cmd := newTLSTestCmd() // "tunnel-tls" not marked Changed.

	config := buildServerConfig(cmd)

	assert.True(t, config.TunnelTLSEnabled, "tunnel TLS should default on when require-auth + real domain")
	assert.True(t, config.AutoTLS, "auto-TLS should be enabled to serve the tunnel TLS default")
	assert.False(t, config.TLSEnabled, "the HTTP listener's TLS setting must be untouched")
}

// TestBuildServerConfig_TunnelTLSDefault_RequireAuthNoDomain verifies that
// without a usable domain, S4 cannot silently turn on tunnel TLS (there's no
// certificate source), and instead the plaintext-control-channel warning
// path is taken (verified indirectly: TunnelTLSEnabled stays false).
func TestBuildServerConfig_TunnelTLSDefault_RequireAuthNoDomain(t *testing.T) {
	withServerGlobals(t, false, true, "", "", "")
	cmd := newTLSTestCmd()

	config := buildServerConfig(cmd)

	assert.False(t, config.TunnelTLSEnabled)
	assert.False(t, config.AutoTLS)
}

// TestBuildServerConfig_TunnelTLSDefault_FollowsTLSEnabled verifies the
// pre-existing default (S4 must not regress it): with no --require-auth,
// --tunnel-tls still mirrors --tls.
func TestBuildServerConfig_TunnelTLSDefault_FollowsTLSEnabled(t *testing.T) {
	withServerGlobals(t, true, false, "tunnel.example.com", "", "")
	cmd := newTLSTestCmd()

	config := buildServerConfig(cmd)

	assert.True(t, config.TunnelTLSEnabled)
}

// TestBuildServerConfig_TunnelTLSExplicitOverride verifies that an operator
// explicitly passing --tunnel-tls=false is respected even when
// --require-auth + a real domain would otherwise default it to true.
func TestBuildServerConfig_TunnelTLSExplicitOverride(t *testing.T) {
	withServerGlobals(t, false, true, "tunnel.example.com", "", "")
	cmd := newTLSTestCmd()
	require := assert.New(t)
	require.NoError(cmd.Flags().Set("tunnel-tls", "false"))

	config := buildServerConfig(cmd)

	assert.False(t, config.TunnelTLSEnabled)
}

// TestBuildServerConfig_TunnelTLSDefault_ManualCertsNoDomainNeeded verifies
// that when manual cert/key files are supplied, AutoTLS is not forced on
// even though TunnelTLSEnabled defaults to true under require-auth.
func TestBuildServerConfig_TunnelTLSDefault_ManualCertsNoDomainNeeded(t *testing.T) {
	withServerGlobals(t, false, true, "tunnel.example.com", "/path/to/cert.pem", "/path/to/key.pem")
	cmd := newTLSTestCmd()

	config := buildServerConfig(cmd)

	assert.True(t, config.TunnelTLSEnabled)
	assert.False(t, config.AutoTLS, "manual certs provided, no need for auto-TLS")
}

// TestBuildServerConfig_ClusterFlags verifies P3-5's new cluster/auth-Redis
// CLI flags (--cluster-secret, --auth-redis-*, --persistence redis) are
// correctly wired into server.Config.
func TestBuildServerConfig_ClusterFlags(t *testing.T) {
	withServerGlobals(t, false, false, "", "", "")
	cmd := newTLSTestCmd()

	origSecret := serverClusterSecret
	origAddr, origPass, origDB := serverAuthRedisAddr, serverAuthRedisPassword, serverAuthRedisDB
	origPersistence := serverPersistence
	t.Cleanup(func() {
		serverClusterSecret = origSecret
		serverAuthRedisAddr, serverAuthRedisPassword, serverAuthRedisDB = origAddr, origPass, origDB
		serverPersistence = origPersistence
	})

	serverClusterSecret = "shared-secret"
	serverAuthRedisAddr = "redis.internal:6379"
	serverAuthRedisPassword = "hunter2"
	serverAuthRedisDB = 3
	serverPersistence = "redis"

	config := buildServerConfig(cmd)

	assert.Equal(t, "shared-secret", config.ClusterSecret)
	assert.Equal(t, "redis.internal:6379", config.AuthRedisAddr)
	assert.Equal(t, "hunter2", config.AuthRedisPassword)
	assert.Equal(t, 3, config.AuthRedisDB)
	assert.Equal(t, server.PersistenceRedis, config.Persistence)
}

// TestBuildServerConfig_ResourceLimitFlags verifies the P3-6 batch A
// resource-limit flags (DP-03/DP-27) and the graceful-shutdown timeout
// (DP-26) are wired from their CLI globals into server.Config.
func TestBuildServerConfig_ResourceLimitFlags(t *testing.T) {
	withServerGlobals(t, false, false, "", "", "")
	cmd := newTLSTestCmd()

	origStreams, origPerClient, origShutdown := serverMaxConcurrentStrms, serverMaxStreamsPerCli, serverShutdownTimeout
	t.Cleanup(func() {
		serverMaxConcurrentStrms, serverMaxStreamsPerCli, serverShutdownTimeout = origStreams, origPerClient, origShutdown
	})

	serverMaxConcurrentStrms = 42
	serverMaxStreamsPerCli = 7
	serverShutdownTimeout = 30 * time.Second

	config := buildServerConfig(cmd)

	assert.Equal(t, 42, config.MaxConcurrentStreams)
	assert.Equal(t, 7, config.MaxStreamsPerClient)
	assert.Equal(t, 30*time.Second, config.ShutdownTimeout)
}

// TestApplyTunnelTLSDefaultsExplicit_MatchesFlagBehavior verifies the U4
// refactor (extracting applyTunnelTLSDefaultsExplicit out of
// applyTunnelTLSDefaults) preserves the exact same S4 defaulting rule so
// the YAML config-file path (which has no cobra flags to check
// Changed() on) gets identical behavior to the --tunnel-tls flag path.
func TestApplyTunnelTLSDefaultsExplicit_MatchesFlagBehavior(t *testing.T) {
	// Not explicit + require-auth + real domain → defaults on.
	cfg := server.DefaultConfig()
	cfg.RequireAuth = true
	cfg.Domain = "tunnel.example.com"
	applyTunnelTLSDefaultsExplicit(&cfg, false, false)
	assert.True(t, cfg.TunnelTLSEnabled)
	assert.True(t, cfg.AutoTLS)

	// Explicit false overrides the would-be default.
	cfg2 := server.DefaultConfig()
	cfg2.RequireAuth = true
	cfg2.Domain = "tunnel.example.com"
	applyTunnelTLSDefaultsExplicit(&cfg2, true, false)
	assert.False(t, cfg2.TunnelTLSEnabled)

	// Explicit true is honored even without require-auth/domain.
	cfg3 := server.DefaultConfig()
	applyTunnelTLSDefaultsExplicit(&cfg3, true, true)
	assert.True(t, cfg3.TunnelTLSEnabled)
}

// TestRunServer_ConfigFileTunnelTLSDefault_EndToEnd exercises the U4
// config-file loading path (LoadServerFileConfig → ToServerConfig →
// applyTunnelTLSDefaultsExplicit) the same way runServer wires them
// together, verifying a config file that enables --require-auth with a
// real domain but never mentions tls.tunnel_tls_enabled still gets the
// same S4 auto-default as the equivalent CLI flags would.
func TestRunServer_ConfigFileTunnelTLSDefault_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/server.yml"
	require.NoError(t, os.WriteFile(path, []byte("domain: tunnel.example.com\nrequire_auth: true\nauth_secret: my-secret-key-at-least-16-chars\n"), 0o600))

	fc, err := server.LoadServerFileConfig(path)
	require.NoError(t, err)

	config := fc.ToServerConfig(server.DefaultConfig())
	applyTunnelTLSDefaultsExplicit(&config, fc.TLS.TunnelTLSEnabled != nil, config.TunnelTLSEnabled)

	assert.True(t, config.RequireAuth)
	assert.True(t, config.TunnelTLSEnabled, "should auto-default on, matching CLI --require-auth + --domain behavior")
	assert.True(t, config.AutoTLS)
}

// TestBuildServerConfig_MinClientVersion verifies the P3-6 batch A
// --min-client-version flag (DP-30) is wired into server.Config.
func TestBuildServerConfig_MinClientVersion(t *testing.T) {
	withServerGlobals(t, false, false, "", "", "")
	cmd := newTLSTestCmd()

	origVersion := serverMinClientVersion
	t.Cleanup(func() { serverMinClientVersion = origVersion })

	serverMinClientVersion = "0.6.4"

	config := buildServerConfig(cmd)

	assert.Equal(t, "0.6.4", config.MinClientVersion)
}
