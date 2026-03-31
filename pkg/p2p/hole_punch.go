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
}

// NewHolePuncher creates a new hole puncher.
func NewHolePuncher(config HolePunchConfig) *HolePuncher {
	return &HolePuncher{config: config}
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
	// Probe packet: magic + "probe".
	probePayload := []byte("probe")
	probe := make([]byte, 0, len(punchMagic)+len(probePayload))
	probe = append(probe, punchMagic...)
	probe = append(probe, probePayload...)

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
		if n >= len(punchMagic) && string(buf[:len(punchMagic)]) == string(punchMagic) {
			udpAddr, ok := addr.(*net.UDPAddr)
			if ok {
				// Send ack back.
				ackPayload := []byte("ack")
				ack := make([]byte, 0, len(punchMagic)+len(ackPayload))
				ack = append(ack, punchMagic...)
				ack = append(ack, ackPayload...)
				_, _ = conn.WriteTo(ack, addr)
				return udpAddr
			}
		}
	}
}
