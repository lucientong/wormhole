package p2p

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultManagerConfig(t *testing.T) {
	cfg := DefaultManagerConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 15*time.Second, cfg.FallbackTimeout)
	assert.NotEmpty(t, cfg.STUNConfig.Servers)
	assert.Greater(t, cfg.HolePunchConfig.MaxAttempts, 0)
}

func TestNewManager(t *testing.T) {
	cfg := DefaultManagerConfig()
	m := NewManager(cfg)

	assert.NotNil(t, m)
	assert.Equal(t, ModeRelay, m.Mode())
	assert.Nil(t, m.NATInfo())
	assert.False(t, m.IsEnabled()) // natInfo is nil → false.
}

func TestManager_NATInfo(t *testing.T) {
	m := &Manager{
		config: ManagerConfig{Enabled: true},
		natInfo: &NATInfo{
			Type:       NATPortRestricted,
			PublicAddr: Endpoint{IP: "1.2.3.4", Port: 5678},
			LocalAddr:  Endpoint{IP: "192.168.1.1", Port: 12345},
		},
	}

	info := m.NATInfo()
	require.NotNil(t, info)
	assert.Equal(t, NATPortRestricted, info.Type)
	assert.Equal(t, "1.2.3.4", info.PublicAddr.IP)
	assert.Equal(t, 5678, info.PublicAddr.Port)
}

func TestManager_Mode_And_FallbackToRelay(t *testing.T) {
	m := &Manager{
		config: ManagerConfig{Enabled: true},
		mode:   ModeP2P,
	}

	assert.Equal(t, ModeP2P, m.Mode())

	m.FallbackToRelay("test reason")
	assert.Equal(t, ModeRelay, m.Mode())
}

func TestManager_IsEnabled_Comprehensive(t *testing.T) {
	tests := []struct {
		name    string
		config  ManagerConfig
		natInfo *NATInfo
		want    bool
	}{
		{
			name:    "disabled in config",
			config:  ManagerConfig{Enabled: false},
			natInfo: &NATInfo{Type: NATFullCone},
			want:    false,
		},
		{
			name:    "natInfo is nil",
			config:  ManagerConfig{Enabled: true},
			natInfo: nil,
			want:    false,
		},
		{
			name:    "symmetric NAT (not traversable)",
			config:  ManagerConfig{Enabled: true},
			natInfo: &NATInfo{Type: NATSymmetric},
			want:    false,
		},
		{
			name:    "unknown NAT (not traversable)",
			config:  ManagerConfig{Enabled: true},
			natInfo: &NATInfo{Type: NATUnknown},
			want:    false,
		},
		{
			name:    "full cone (traversable)",
			config:  ManagerConfig{Enabled: true},
			natInfo: &NATInfo{Type: NATFullCone},
			want:    true,
		},
		{
			name:    "port restricted cone (traversable)",
			config:  ManagerConfig{Enabled: true},
			natInfo: &NATInfo{Type: NATPortRestricted},
			want:    true,
		},
		{
			name:    "no NAT (traversable)",
			config:  ManagerConfig{Enabled: true},
			natInfo: &NATInfo{Type: NATNone},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				config:  tt.config,
				natInfo: tt.natInfo,
			}
			assert.Equal(t, tt.want, m.IsEnabled())
		})
	}
}

func TestManager_Init_Disabled(t *testing.T) {
	cfg := DefaultManagerConfig()
	cfg.Enabled = false

	m := NewManager(cfg)
	err := m.Init(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, m.NATInfo()) // Should not perform discovery.
}

func TestManager_AttemptP2P_NotAvailable_NilNATInfo(t *testing.T) {
	m := &Manager{
		config:  ManagerConfig{Enabled: true},
		natInfo: nil, // NAT discovery not completed.
	}

	_, _, err := m.AttemptP2P(context.Background(), Endpoint{IP: "1.2.3.4", Port: 5678}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "NAT discovery not completed")
}

func TestManager_AttemptP2P_NotAvailable_SymmetricNAT(t *testing.T) {
	m := &Manager{
		config:  ManagerConfig{Enabled: true},
		natInfo: &NATInfo{Type: NATSymmetric},
	}

	_, _, err := m.AttemptP2P(context.Background(), Endpoint{IP: "1.2.3.4", Port: 5678}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Symmetric")
}
