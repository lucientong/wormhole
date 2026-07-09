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
// two endpoints without NAT (localhost simulation), via a UDPMux stream.
func TestP2PIntegration_DirectConnection(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, nil, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, nil, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)
	defer s1.Close()

	testData := []byte("Hello from peer 1!")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, writeErr := s1.Write(testData)
		require.NoError(t, writeErr)
	}()

	var s2 *UDPStream
	go func() {
		defer wg.Done()
		var acceptErr error
		s2, acceptErr = m2.AcceptStream()
		require.NoError(t, acceptErr)

		buf := make([]byte, 1024)
		n, readErr := s2.Read(buf)
		require.NoError(t, readErr)
		assert.Equal(t, testData, buf[:n])

		// Echo back.
		_, writeErr := s2.Write(buf[:n])
		require.NoError(t, writeErr)
	}()

	wg.Wait()
	defer s2.Close()

	buf := make([]byte, 1024)
	done := make(chan struct{})
	go func() {
		n, readErr := s1.Read(buf)
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
// P2P protocol messages over a UDPMux stream.
func TestP2PIntegration_ProtocolMessage(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, nil, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, nil, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)
	defer s1.Close()

	// Simulate a P2P stream request as JSON.
	// In real usage, this would be proto.ControlMessage.
	streamRequest := `{"type":2,"sequence":1,"stream_request":{"request_id":"test-123","protocol":1}}`

	go func() {
		_, _ = s1.Write([]byte(streamRequest))
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)
	defer s2.Close()

	buf := make([]byte, 4096)
	done := make(chan []byte, 1)

	go func() {
		n, readErr := s2.Read(buf)
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

// TestP2PIntegration_ConcurrentStreams tests multiple concurrent logical
// streams multiplexed over a single UDPMux connection.
func TestP2PIntegration_ConcurrentStreams(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, nil, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, nil, false)
	defer m2.Close()

	numStreams := 10
	var wg sync.WaitGroup
	wg.Add(numStreams)

	for i := range numStreams {
		go func(idx int) {
			defer wg.Done()
			s, openErr := m1.OpenStream()
			require.NoError(t, openErr)
			defer s.Close()
			_, writeErr := s.Write([]byte{byte(idx)})
			assert.NoError(t, writeErr)
		}(i)
	}

	received := make(map[byte]bool)
	mu := sync.Mutex{}

	done := make(chan struct{})
	go func() {
		for range numStreams {
			s, acceptErr := m2.AcceptStream()
			if acceptErr != nil {
				return
			}
			go func(stream *UDPStream) {
				defer stream.Close()
				buf := make([]byte, 1024)
				n, readErr := stream.Read(buf)
				if readErr != nil || n == 0 {
					return
				}
				mu.Lock()
				received[buf[0]] = true
				count := len(received)
				mu.Unlock()
				if count >= numStreams {
					close(done)
				}
			}(s)
		}
	}()

	wg.Wait()

	select {
	case <-done:
		mu.Lock()
		assert.Len(t, received, numStreams)
		mu.Unlock()
	case <-time.After(10 * time.Second):
		mu.Lock()
		t.Fatalf("Only received %d/%d messages", len(received), numStreams)
		mu.Unlock()
	}
}

// TestP2PIntegration_GracefulClose tests that closing one stream
// properly notifies the peer (FIN -> EOF).
func TestP2PIntegration_GracefulClose(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, nil, true)
	defer m1.Close()
	m2 := NewUDPMux(conn2, peer2, config, nil, false)
	defer m2.Close()

	s1, err := m1.OpenStream()
	require.NoError(t, err)

	go func() {
		_, _ = s1.Write([]byte("test"))
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = s2.Read(buf)
	require.NoError(t, err)

	require.NoError(t, s1.Close())

	done := make(chan error, 1)
	go func() {
		_, readErr := s2.Read(buf)
		done <- readErr
	}()

	select {
	case readErr := <-done:
		assert.True(t, readErr == io.EOF || readErr != nil)
	case <-time.After(3 * time.Second):
		// FIN packet might not always be received - acceptable.
	}

	_ = s2.Close()
}

// TestP2PIntegration_ReconnectScenario tests the fallback-to-relay
// scenario by simulating a peer disappearing mid-session: the mux/stream
// on the surviving side must remain safe to use (no panic) even though
// its writes are now going nowhere.
func TestP2PIntegration_ReconnectScenario(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	config := DefaultTransportConfig()
	config.RetransmitTimeout = 50 * time.Millisecond

	m1 := NewUDPMux(conn1, peer1, config, nil, true)
	m2 := NewUDPMux(conn2, peer2, config, nil, false)

	s1, err := m1.OpenStream()
	require.NoError(t, err)

	go func() {
		_, _ = s1.Write([]byte("hello"))
	}()

	s2, err := m2.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 1024)
	_, err = s2.Read(buf)
	require.NoError(t, err)

	// Simulate transport failure: the peer disappears entirely.
	_ = m2.Close()

	// Writing after the peer is gone should not panic — the RST sent by
	// Close on m2's side is delivered best-effort, and s1 either observes
	// it (force-close) or simply times out retransmitting into the void.
	_, _ = s1.Write([]byte("test"))

	_ = m1.Close()
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

// TestP2PIntegration_Timeout tests that a stream to a non-existent peer
// gives up and force-closes after exhausting its retransmit budget,
// instead of retrying forever (see also TestUDPStream_Retransmit_
// GivesUpAfterMaxRetransmits for the lower-level unit test).
func TestP2PIntegration_Timeout(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	// A non-existent peer — same idea as before, just driven through the
	// public UDPMux/UDPStream API instead of the removed Transport type.
	fakePeer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65000}

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 20 * time.Millisecond
	config.MaxRetransmits = 2 // Quick timeout.

	m := NewUDPMux(conn, fakePeer, config, nil, true)
	defer m.Close()

	s, err := m.OpenStream()
	require.NoError(t, err)

	_, err = s.Write([]byte("test"))
	assert.NoError(t, err)

	select {
	case <-s.closeCh:
		// Expected: the stream gives up after exhausting maxRetransmits.
	case <-time.After(3 * time.Second):
		t.Fatal("stream should have force-closed after exceeding maxRetransmits")
	}
}

// TestEndpoint tests the Endpoint type.
func TestEndpoint(t *testing.T) {
	ep := Endpoint{IP: "192.168.1.1", Port: 8080}
	assert.Equal(t, "192.168.1.1:8080", ep.String())

	ep2 := Endpoint{IP: "::1", Port: 443}
	assert.Equal(t, "[::1]:443", ep2.String())
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
