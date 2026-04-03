package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// HolePunchConfig holds configuration for UDP hole punching.
type HolePunchConfig struct {
	// MaxAttempts is the maximum number of punch attempts.
	MaxAttempts int
	// Interval is the delay between punch attempts.
	Interval time.Duration
	// Timeout is the overall timeout for the hole punch operation.
	Timeout time.Duration
}

// DefaultHolePunchConfig returns sensible defaults.
func DefaultHolePunchConfig() HolePunchConfig {
	return HolePunchConfig{
		MaxAttempts: 30,
		Interval:    100 * time.Millisecond,
		Timeout:     10 * time.Second,
	}
}

// HolePuncher performs UDP hole punching between two peers.
type HolePuncher struct {
	config HolePunchConfig
	// cipher is the optional session cipher for authenticated probes.
	// When set, probes include an HMAC tag for peer authentication.
	cipher *SessionCipher
}

// NewHolePuncher creates a new hole puncher.
func NewHolePuncher(config HolePunchConfig) *HolePuncher {
	return &HolePuncher{config: config}
}

// SetCipher sets the session cipher for authenticated hole punching.
func (h *HolePuncher) SetCipher(c *SessionCipher) {
	h.cipher = c
}

// punchMagic is the 4-byte magic prefix for hole punch packets.
var punchMagic = []byte{0x57, 0x48, 0x50, 0x50} // "WHPP" = WormHole Punch Protocol.

// Punch attempts to establish a UDP connection to the peer via hole punching.
// It sends probe packets to the peer's public endpoint while simultaneously
// listening for incoming probes. Returns the established connection if successful.
func (h *HolePuncher) Punch(ctx context.Context, localConn net.PacketConn, peerEndpoint Endpoint) (*net.UDPAddr, error) {
	peerAddr, err := net.ResolveUDPAddr("udp4", peerEndpoint.String())
	if err != nil {
		return nil, fmt.Errorf("resolve peer address: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, h.config.Timeout)
	defer cancel()

	// Channel to receive the confirmed peer address.
	result := make(chan *net.UDPAddr, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	// Sender goroutine: send probe packets to peer.
	go func() {
		defer wg.Done()
		h.sendProbes(ctx, localConn, peerAddr)
	}()

	// Receiver goroutine: listen for probe packets from peer.
	go func() {
		defer wg.Done()
		if addr := h.receiveProbe(ctx, localConn); addr != nil {
			select {
			case result <- addr:
			default:
			}
			cancel() // Got a response — stop sending.
		}
	}()

	// Wait for result or timeout.
	select {
	case addr := <-result:
		// Cancel context to stop sender goroutine, then wait for both to exit.
		cancel()
		wg.Wait()
		log.Info().Str("peer", addr.String()).Msg("Hole punch successful")
		return addr, nil
	case <-ctx.Done():
		wg.Wait()
		return nil, fmt.Errorf("hole punch timed out after %v", h.config.Timeout)
	}
}

// sendProbes sends periodic UDP probe packets to the peer.
func (h *HolePuncher) sendProbes(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) {
	// Build probe packet: magic + "probe" [+ HMAC tag].
	probePayload := []byte("probe")
	baseProbe := make([]byte, 0, len(punchMagic)+len(probePayload))
	baseProbe = append(baseProbe, punchMagic...)
	baseProbe = append(baseProbe, probePayload...)

	// If cipher is set, append HMAC tag for authenticated probes.
	probe := baseProbe
	if h.cipher != nil {
		tag := h.cipher.SignProbe(baseProbe)
		probe = make([]byte, 0, len(baseProbe)+len(tag))
		probe = append(probe, baseProbe...)
		probe = append(probe, tag...)
	}

	// Send the first probe immediately (avoid ticker startup delay).
	if _, err := conn.WriteTo(probe, peer); err != nil {
		log.Debug().Err(err).Str("peer", peer.String()).Msg("Probe send failed")
	}

	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()

	for i := 1; i < h.config.MaxAttempts; i++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := conn.WriteTo(probe, peer); err != nil {
				log.Debug().Err(err).Str("peer", peer.String()).Msg("Probe send failed")
			}
		}
	}
}

// receiveProbe listens for probe packets from the peer.
func (h *HolePuncher) receiveProbe(ctx context.Context, conn net.PacketConn) *net.UDPAddr {
	buf := make([]byte, 256)
	// hmacTagLen is the HMAC-SHA256 tag length (32 bytes).
	const hmacTagLen = 32

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Short read deadline to allow checking context.
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return nil
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		// Verify magic prefix.
		if n < len(punchMagic) || string(buf[:len(punchMagic)]) != string(punchMagic) {
			continue
		}

		// If cipher is set, verify HMAC authentication on the probe.
		if h.cipher != nil {
			// Authenticated probe format: [magic + payload][HMAC-SHA256 tag].
			// Minimum length: magic (4) + "probe" (5) + tag (32) = 41.
			baseLen := n - hmacTagLen
			if baseLen < len(punchMagic) {
				log.Debug().Msg("Probe too short for HMAC verification, ignoring")
				continue
			}
			payload := buf[:baseLen]
			tag := buf[baseLen:n]
			if !h.cipher.VerifyProbe(payload, tag) {
				log.Debug().Msg("Probe HMAC verification failed, ignoring")
				continue
			}
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		// Build authenticated ack.
		ackPayload := []byte("ack")
		baseAck := make([]byte, 0, len(punchMagic)+len(ackPayload))
		baseAck = append(baseAck, punchMagic...)
		baseAck = append(baseAck, ackPayload...)

		ack := baseAck
		if h.cipher != nil {
			tag := h.cipher.SignProbe(baseAck)
			ack = make([]byte, 0, len(baseAck)+len(tag))
			ack = append(ack, baseAck...)
			ack = append(ack, tag...)
		}

		_, _ = conn.WriteTo(ack, addr)
		return udpAddr
	}
}
