package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ConnectionMode represents how the connection is established.
type ConnectionMode int

const (
	// ModeRelay means traffic goes through the server (default).
	ModeRelay ConnectionMode = iota
	// ModeP2P means a direct UDP connection was established.
	ModeP2P
)

// String returns the connection mode name.
func (m ConnectionMode) String() string {
	switch m {
	case ModeP2P:
		return "P2P"
	default:
		return "Relay"
	}
}

// ManagerConfig holds configuration for the P2P manager.
type ManagerConfig struct {
	// Enabled controls whether P2P is attempted.
	Enabled bool
	// STUNConfig is the STUN client configuration.
	STUNConfig STUNConfig
	// HolePunchConfig is the hole punch configuration.
	HolePunchConfig HolePunchConfig
	// FallbackTimeout is how long to wait before falling back to relay.
	FallbackTimeout time.Duration
}

// DefaultManagerConfig returns sensible defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		Enabled:         true,
		STUNConfig:      DefaultSTUNConfig(),
		HolePunchConfig: DefaultHolePunchConfig(),
		FallbackTimeout: 15 * time.Second,
	}
}

// Manager coordinates P2P connection establishment and fallback.
type Manager struct {
	config ManagerConfig

	stunClient  *STUNClient
	holePuncher *HolePuncher

	// NAT info discovered at startup.
	natInfo *NATInfo
	natOnce sync.Once
	natErr  error

	// Current connection mode.
	mode ConnectionMode
	mu   sync.RWMutex
}

// NewManager creates a new P2P manager.
func NewManager(config ManagerConfig) *Manager {
	return &Manager{
		config:      config,
		stunClient:  NewSTUNClient(config.STUNConfig),
		holePuncher: NewHolePuncher(config.HolePunchConfig),
		mode:        ModeRelay,
	}
}

// Init performs initial NAT discovery. Should be called once at startup.
func (m *Manager) Init(ctx context.Context) error {
	if !m.config.Enabled {
		log.Info().Msg("P2P disabled")
		return nil
	}

	m.natOnce.Do(func() {
		log.Info().Msg("Performing NAT discovery...")

		discoverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		m.natInfo, m.natErr = m.stunClient.Discover(discoverCtx)
		if m.natErr != nil {
			log.Warn().Err(m.natErr).Msg("NAT discovery failed, P2P will not be available")
			return
		}

		log.Info().
			Str("nat_type", m.natInfo.Type.String()).
			Str("public_addr", m.natInfo.PublicAddr.String()).
			Bool("traversable", m.natInfo.Type.IsTraversable()).
			Msg("NAT discovery complete")
	})

	return m.natErr
}

// NATInfo returns the discovered NAT info, or nil if not yet discovered.
func (m *Manager) NATInfo() *NATInfo {
	return m.natInfo
}

// Mode returns the current connection mode.
func (m *Manager) Mode() ConnectionMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode
}

// IsEnabled returns whether P2P is enabled and NAT is traversable.
func (m *Manager) IsEnabled() bool {
	if !m.config.Enabled || m.natInfo == nil {
		return false
	}
	return m.natInfo.Type.IsTraversable()
}

// AttemptP2P tries to establish a P2P connection with a peer.
// It returns the established UDP connection or an error (caller should fallback to relay).
// If a SessionCipher is provided, hole-punch probes will be HMAC-authenticated.
func (m *Manager) AttemptP2P(ctx context.Context, peerEndpoint Endpoint, cipher *SessionCipher) (net.PacketConn, *net.UDPAddr, error) {
	if !m.IsEnabled() {
		if m.natInfo == nil {
			return nil, nil, fmt.Errorf("P2P not available (NAT discovery not completed)")
		}
		return nil, nil, fmt.Errorf("P2P not available (NAT type: %s)", m.natInfo.Type)
	}

	log.Info().
		Str("peer", peerEndpoint.String()).
		Str("nat_type", m.natInfo.Type.String()).
		Msg("Attempting P2P connection")

	ctx, cancel := context.WithTimeout(ctx, m.config.FallbackTimeout)
	defer cancel()

	// Create local UDP socket.
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen udp: %w", err)
	}

	// Set cipher on hole puncher for authenticated probes.
	m.holePuncher.SetCipher(cipher)

	// Attempt hole punch.
	peerAddr, punchErr := m.holePuncher.Punch(ctx, conn, peerEndpoint)
	if punchErr != nil {
		_ = conn.Close()
		log.Warn().Err(punchErr).Msg("Hole punch failed, falling back to relay")
		return nil, nil, punchErr
	}

	// P2P established!
	m.mu.Lock()
	m.mode = ModeP2P
	m.mu.Unlock()

	log.Info().
		Str("peer", peerAddr.String()).
		Str("local", conn.LocalAddr().String()).
		Msg("P2P connection established")

	return conn, peerAddr, nil
}

// FallbackToRelay switches back to relay mode.
func (m *Manager) FallbackToRelay(reason string) {
	m.mu.Lock()
	m.mode = ModeRelay
	m.mu.Unlock()

	log.Info().Str("reason", reason).Msg("Falling back to relay mode")
}
