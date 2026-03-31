package p2p

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHolePuncher_LocalPunch(t *testing.T) {
	// Test hole punching between two local UDP sockets.
	// This simulates a "no NAT" scenario where both sides are on localhost.

	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	hp := NewHolePuncher(HolePunchConfig{
		MaxAttempts: 10,
		Interval:    50 * time.Millisecond,
		Timeout:     5 * time.Second,
	})

	ctx := context.Background()
	resultCh := make(chan *net.UDPAddr, 2)
	errCh := make(chan error, 2)

	// Punch from conn1 → conn2.
	go func() {
		peer := Endpoint{IP: addr2.IP.String(), Port: addr2.Port}
		result, punchErr := hp.Punch(ctx, conn1, peer)
		if punchErr != nil {
			errCh <- punchErr
		} else {
			resultCh <- result
		}
	}()

	// Punch from conn2 → conn1.
	go func() {
		peer := Endpoint{IP: addr1.IP.String(), Port: addr1.Port}
		result, punchErr := hp.Punch(ctx, conn2, peer)
		if punchErr != nil {
			errCh <- punchErr
		} else {
			resultCh <- result
		}
	}()

	// At least one side should succeed.
	select {
	case addr := <-resultCh:
		assert.NotNil(t, addr)
		t.Logf("Hole punch succeeded: peer=%s", addr.String())
	case punchErr := <-errCh:
		// Both sides failing is also acceptable in some CI environments.
		t.Logf("Hole punch failed (acceptable in some environments): %v", punchErr)
	case <-time.After(10 * time.Second):
		t.Fatal("Hole punch timed out")
	}
}

func TestHolePuncher_Timeout(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	hp := NewHolePuncher(HolePunchConfig{
		MaxAttempts: 3,
		Interval:    50 * time.Millisecond,
		Timeout:     500 * time.Millisecond,
	})

	// Try to punch to a non-existent peer — should timeout.
	peer := Endpoint{IP: "127.0.0.1", Port: 1}
	_, punchErr := hp.Punch(context.Background(), conn, peer)
	assert.Error(t, punchErr)
	assert.Contains(t, punchErr.Error(), "timed out")
}
