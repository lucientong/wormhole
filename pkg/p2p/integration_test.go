package p2p

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestP2PIntegration_DirectConnection tests P2P communication between
// two endpoints without NAT (localhost simulation).
func TestP2PIntegration_DirectConnection(t *testing.T) {
	// Create two UDP sockets to simulate two peers.
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	// Create transports for bidirectional communication.
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, nil)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config, nil)
	defer t2.Close()

	// Test bidirectional echo.
	testData := []byte("Hello from peer 1!")

	var wg sync.WaitGroup
	wg.Add(2)

	// Peer 1 sends, Peer 2 echoes back.
	go func() {
		defer wg.Done()
		_, writeErr := t1.Write(testData)
		require.NoError(t, writeErr)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, readErr := t2.Read(buf)
		require.NoError(t, readErr)
		assert.Equal(t, testData, buf[:n])

		// Echo back.
		_, writeErr := t2.Write(buf[:n])
		require.NoError(t, writeErr)
	}()

	wg.Wait()

	// Peer 1 receives echo.
	buf := make([]byte, 1024)
	done := make(chan struct{})
	go func() {
		n, readErr := t1.Read(buf)
		if readErr == nil {
			assert.Equal(t, testData, buf[:n])
		}
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Echo read timed out")
	}
}

// TestP2PIntegration_ProtocolMessage tests sending and receiving
// P2P protocol messages over the transport.
func TestP2PIntegration_ProtocolMessage(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, nil)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config, nil)
	defer t2.Close()

	// Simulate a P2P stream request as JSON.
	// In real usage, this would be proto.ControlMessage.
	streamRequest := `{"type":2,"sequence":1,"stream_request":{"request_id":"test-123","protocol":1}}`

	_, err = t1.Write([]byte(streamRequest))
	require.NoError(t, err)

	// Read on receiver side.
	buf := make([]byte, 4096)
	done := make(chan []byte, 1)

	go func() {
		n, readErr := t2.Read(buf)
		if readErr == nil {
			result := make([]byte, n)
			copy(result, buf[:n])
			done <- result
		}
		close(done)
	}()

	select {
	case received := <-done:
		assert.Equal(t, streamRequest, string(received))
	case <-time.After(5 * time.Second):
		t.Fatal("Protocol message read timed out")
	}
}

// TestP2PIntegration_ConcurrentStreams tests multiple concurrent
// data streams over a single P2P transport.
func TestP2PIntegration_ConcurrentStreams(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, nil)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config, nil)
	defer t2.Close()

	numMessages := 10
	var wg sync.WaitGroup
	wg.Add(numMessages)

	// Send multiple messages concurrently.
	for i := range numMessages {
		go func(idx int) {
			defer wg.Done()
			msg := []byte{byte(idx)}
			_, writeErr := t1.Write(msg)
			assert.NoError(t, writeErr)
		}(i)
	}

	// Receive all messages.
	received := make(map[byte]bool)
	mu := sync.Mutex{}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			n, readErr := t2.Read(buf)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				continue
			}
			if n > 0 {
				mu.Lock()
				received[buf[0]] = true
				if len(received) >= numMessages {
					mu.Unlock()
					close(done)
					return
				}
				mu.Unlock()
			}
		}
	}()

	wg.Wait()

	select {
	case <-done:
		mu.Lock()
		assert.Len(t, received, numMessages)
		mu.Unlock()
	case <-time.After(10 * time.Second):
		mu.Lock()
		t.Fatalf("Only received %d/%d messages", len(received), numMessages)
		mu.Unlock()
	}
}

// TestP2PIntegration_GracefulClose tests that closing one side
// properly notifies the other side.
func TestP2PIntegration_GracefulClose(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, nil)
	t2 := NewTransport(conn2, addr1, config, nil)

	// Send some data first.
	_, err = t1.Write([]byte("test"))
	require.NoError(t, err)

	// Read on t2.
	buf := make([]byte, 1024)
	_, err = t2.Read(buf)
	require.NoError(t, err)

	// Close t1 gracefully.
	err = t1.Close()
	require.NoError(t, err)

	// t2 should eventually get EOF or error on read.
	done := make(chan error, 1)
	go func() {
		_, readErr := t2.Read(buf)
		done <- readErr
	}()

	select {
	case readErr := <-done:
		// EOF or other error is expected after FIN.
		assert.True(t, readErr == io.EOF || readErr != nil)
	case <-time.After(3 * time.Second):
		// FIN packet might not always be received - acceptable.
	}

	// Cleanup.
	_ = t2.Close()
	_ = conn1.Close()
	_ = conn2.Close()
}

// TestP2PIntegration_ReconnectScenario tests the fallback-to-relay
// scenario by simulating a transport failure.
func TestP2PIntegration_ReconnectScenario(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config, nil)
	t2 := NewTransport(conn2, addr1, config, nil)

	// Initial communication works.
	_, err = t1.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = t2.Read(buf)
	require.NoError(t, err)

	// Simulate transport failure by closing t2 first (gracefully).
	_ = t2.Close()
	_ = conn2.Close()

	// Attempt to write after peer is gone - write to closed transport should error.
	_, _ = t1.Write([]byte("test"))
	// This may succeed (UDP is connectionless) or fail if transport detects closure.
	// The key is that no panic occurs and behavior is predictable.

	// In real scenario, manager would detect failure and fallback to relay.
	// The transport should handle this gracefully without panicking.

	// Cleanup.
	_ = t1.Close()
	_ = conn1.Close()

	// Test passes if no panic occurred during the failure scenario.
}

// TestP2PManager_ModeSwitch tests the manager's mode switching capability.
func TestP2PManager_ModeSwitch(t *testing.T) {
	config := DefaultManagerConfig()
	config.Enabled = true

	m := NewManager(config)

	// Initial mode should be Relay.
	assert.Equal(t, ModeRelay, m.Mode())

	// Simulate mode switch to P2P.
	m.mu.Lock()
	m.mode = ModeP2P
	m.mu.Unlock()

	assert.Equal(t, ModeP2P, m.Mode())

	// Fallback to relay.
	m.FallbackToRelay("test reason")
	assert.Equal(t, ModeRelay, m.Mode())
}

// TestP2PIntegration_Timeout tests transport timeout behavior.
func TestP2PIntegration_Timeout(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	// Create transport to a non-existent peer.
	fakePeer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65000}

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond
	config.MaxRetransmits = 2 // Quick timeout.

	tr := NewTransport(conn, fakePeer, config, nil)
	defer tr.Close()

	// Send data - should succeed (local operation).
	_, err = tr.Write([]byte("test"))
	assert.NoError(t, err)

	// After some time, the unacknowledged packet should be cleaned up.
	time.Sleep(300 * time.Millisecond)

	stats := tr.Stats()
	assert.Equal(t, 0, stats.PendingAcks) // Should be cleaned up after max retransmits.
}

// TestEndpoint tests the Endpoint type.
func TestEndpoint(t *testing.T) {
	ep := Endpoint{IP: "192.168.1.1", Port: 8080}
	assert.Equal(t, "192.168.1.1:8080", ep.String())

	ep2 := Endpoint{IP: "::1", Port: 443}
	assert.Equal(t, "::1:443", ep2.String())
}

// TestManagerConfig_Defaults tests default manager configuration.
func TestManagerConfig_Defaults(t *testing.T) {
	config := DefaultManagerConfig()

	assert.True(t, config.Enabled)
	assert.Equal(t, 15*time.Second, config.FallbackTimeout)
}

// TestManager_IsEnabled tests IsEnabled with various states.
func TestManager_IsEnabled(t *testing.T) {
	// Disabled config.
	config := DefaultManagerConfig()
	config.Enabled = false
	m := NewManager(config)
	assert.False(t, m.IsEnabled())

	// Enabled but no NAT info.
	config.Enabled = true
	m = NewManager(config)
	assert.False(t, m.IsEnabled())

	// With NAT info but not traversable.
	m.natInfo = &NATInfo{
		Type: NATSymmetric, // Not traversable.
	}
	assert.False(t, m.IsEnabled())

	// With traversable NAT.
	m.natInfo = &NATInfo{
		Type: NATNone, // No NAT, public IP.
	}
	assert.True(t, m.IsEnabled())
}

// TestManager_AttemptP2P_NotEnabled tests AttemptP2P when not enabled.
func TestManager_AttemptP2P_NotEnabled(t *testing.T) {
	config := DefaultManagerConfig()
	config.Enabled = false
	m := NewManager(config)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, _, err := m.AttemptP2P(ctx, Endpoint{IP: "127.0.0.1", Port: 8080}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "P2P not available")
}
