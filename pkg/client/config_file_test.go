package client

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validConfigYAML = `
server: tunnel.example.com:7000
tls: true
token: my-token
ctrl_port: 7010

tunnels:
  web:
    local_port: 8080
    protocol: http
    subdomain: myapp
  api:
    local_port: 3000
    hostname: api.example.com
  db:
    local_port: 5432
    protocol: tcp
`

func TestLoadFileConfig_Valid(t *testing.T) {
	f := writeTempConfig(t, validConfigYAML)
	defer os.Remove(f)

	fc, err := LoadFileConfig(f)
	require.NoError(t, err)

	assert.Equal(t, "tunnel.example.com:7000", fc.Server)
	assert.True(t, fc.TLS)
	assert.Equal(t, "my-token", fc.Token)
	assert.Equal(t, 7010, fc.CtrlPort)
	assert.Len(t, fc.Tunnels, 3)

	web := fc.Tunnels["web"]
	assert.Equal(t, 8080, web.LocalPort)
	assert.Equal(t, "http", web.Protocol)
	assert.Equal(t, "myapp", web.Subdomain)

	api := fc.Tunnels["api"]
	assert.Equal(t, 3000, api.LocalPort)
	assert.Equal(t, "api.example.com", api.Hostname)

	db := fc.Tunnels["db"]
	assert.Equal(t, 5432, db.LocalPort)
	assert.Equal(t, "tcp", db.Protocol)
}

func TestLoadFileConfig_MissingFile(t *testing.T) {
	_, err := LoadFileConfig("/nonexistent/path/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read config file")
}

func TestLoadFileConfig_InvalidYAML(t *testing.T) {
	f := writeTempConfig(t, "this: is: not: valid: yaml:")
	defer os.Remove(f)
	_, err := LoadFileConfig(f)
	require.Error(t, err)
}

func TestLoadFileConfig_NoTunnels(t *testing.T) {
	f := writeTempConfig(t, "server: localhost:7000\n")
	defer os.Remove(f)
	_, err := LoadFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one tunnel")
}

func TestLoadFileConfig_InvalidPort(t *testing.T) {
	yaml := `
tunnels:
  bad:
    local_port: 99999
`
	f := writeTempConfig(t, yaml)
	defer os.Remove(f)
	_, err := LoadFileConfig(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "local_port")
}

func TestFileConfig_ToClientConfig(t *testing.T) {
	f := writeTempConfig(t, validConfigYAML)
	defer os.Remove(f)

	fc, err := LoadFileConfig(f)
	require.NoError(t, err)

	cfg := fc.ToClientConfig(DefaultConfig())

	assert.Equal(t, "tunnel.example.com:7000", cfg.ServerAddr)
	assert.True(t, cfg.TLSEnabled)
	assert.Equal(t, "my-token", cfg.Token)
	assert.Equal(t, 7010, cfg.CtrlPort)
	// LocalPort should be 0 in multi-tunnel mode (tunnels come from Tunnels slice).
	assert.Equal(t, 0, cfg.LocalPort)
	assert.Len(t, cfg.Tunnels, 3)

	for _, def := range cfg.Tunnels {
		assert.NotEmpty(t, def.Name)
		assert.Greater(t, def.LocalPort, 0)
		assert.NotEmpty(t, def.Protocol)
		assert.Equal(t, defaultLocalHost, def.LocalHost)
	}
}

func TestFileConfig_DefaultLocalHostAndProtocol(t *testing.T) {
	yaml := `
tunnels:
  minimal:
    local_port: 8080
`
	f := writeTempConfig(t, yaml)
	defer os.Remove(f)

	fc, err := LoadFileConfig(f)
	require.NoError(t, err)
	cfg := fc.ToClientConfig(DefaultConfig())

	require.Len(t, cfg.Tunnels, 1)
	def := cfg.Tunnels[0]
	assert.Equal(t, defaultLocalHost, def.LocalHost)
	assert.Equal(t, "http", def.Protocol)
}

// writeTempConfig writes content to a temp file and returns the path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "wormhole-config-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}
