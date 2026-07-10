package cmd

import (
	"testing"

	"github.com/lucientong/wormhole/pkg/server"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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
