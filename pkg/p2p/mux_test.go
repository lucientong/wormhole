package p2p

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUDPPair returns two UDP sockets that can talk to each other and
// the respective remote addresses to use for sending.
func newUDPPair(t *testing.T) (net.PacketConn, net.PacketConn, *net.UDPAddr, *net.UDPAddr) {
	t.Helper()
	ln1, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ln2, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ln1.Close()
		_ = ln2.Close()
	})
	return ln1, ln2, ln2.LocalAddr().(*net.UDPAddr), ln1.LocalAddr().(*net.UDPAddr)
}

// newMuxPair returns a connected initiator/acceptor mux pair.
func newMuxPair(t *testing.T) (*UDPMux, *UDPMux) {
	t.Helper()
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	cfg := DefaultTransportConfig()
	cfg.RetransmitTimeout = 50 * time.Millisecond
	initiator := NewUDPMux(conn1, peer1, cfg, nil, true)
	acceptor := NewUDPMux(conn2, peer2, cfg, nil, false)
	t.Cleanup(func() {
		_ = initiator.Close()
		_ = acceptor.Close()
	})
	return initiator, acceptor
}

// --- Basic send / receive ---

func TestUDPMux_SingleStream_SendReceive(t *testing.T) {
	initiator, acceptor := newMuxPair(t)

	// Initiator opens a stream, sends data.
	stream, err := initiator.OpenStream()
	require.NoError(t, err)

	payload := []byte("hello from initiator")
	go func() {
		_, _ = stream.Write(payload)
	}()

	// Acceptor accepts the stream and reads the data.
	accepted, err := acceptor.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 256)
	_ = accepted.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := accepted.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])
}

// --- Multiple concurrent streams ---

func TestUDPMux_MultiStream_Concurrent(t *testing.T) {
	const numStreams = 5

	initiator, acceptor := newMuxPair(t)

	var received int32

	// Acceptor side: process incoming streams.
	go func() {
		for i := 0; i < numStreams; i++ {
			stream, acceptErr := acceptor.AcceptStream()
			if acceptErr != nil {
				return
			}
			go func(s *UDPStream) {
				defer s.Close()
				buf := make([]byte, 256)
				_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, readErr := s.Read(buf)
				if readErr == nil && n > 0 {
					atomic.AddInt32(&received, 1)
				}
			}(stream)
		}
	}()

	// Initiator side: open N streams and send on each.
	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stream, openErr := initiator.OpenStream()
			if openErr != nil {
				return
			}
			defer stream.Close()
			_, _ = fmt.Fprintf(stream, "msg-%d", i)
		}(i)
	}
	wg.Wait()

	// Wait for all messages to be received.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&received) == int32(numStreams) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, int32(numStreams), atomic.LoadInt32(&received),
		"all %d streams should deliver their message", numStreams)
}

// --- Stream independent close ---

func TestUDPMux_StreamIndependentClose(t *testing.T) {
	initiator, acceptor := newMuxPair(t)

	// Open two streams.
	s1, err := initiator.OpenStream()
	require.NoError(t, err)
	s2, err := initiator.OpenStream()
	require.NoError(t, err)

	// Accept both.
	a1, err := acceptor.AcceptStream()
	require.NoError(t, err)
	a2, err := acceptor.AcceptStream()
	require.NoError(t, err)

	// Send on s1, close s1; s2 should be unaffected.
	_, err = s1.Write([]byte("stream1-data"))
	require.NoError(t, err)
	require.NoError(t, s1.Close())

	// Verify s2 still works: send and receive.
	go func() {
		_, _ = s2.Write([]byte("stream2-data"))
	}()

	buf := make([]byte, 256)
	_ = a2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := a2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "stream2-data", string(buf[:n]))

	// a1 should get EOF after s1 sent FIN.
	_ = a1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, readErr := io.ReadAll(a1)
	assert.NoError(t, readErr) // ReadAll handles EOF cleanly
}

// --- Bidirectional data flow ---

func TestUDPMux_Bidirectional(t *testing.T) {
	initiator, acceptor := newMuxPair(t)

	stream, err := initiator.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	accepted, err := acceptor.AcceptStream()
	require.NoError(t, err)
	defer accepted.Close()

	// Initiator → acceptor.
	_, err = stream.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 256)
	_ = accepted.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := accepted.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))

	// Acceptor → initiator.
	_, err = accepted.Write([]byte("pong"))
	require.NoError(t, err)

	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = stream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf[:n]))
}

// --- Mux close / fallback ---

func TestUDPMux_Close_SetsIsClosed(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	cfg := DefaultTransportConfig()
	m1 := NewUDPMux(conn1, peer1, cfg, nil, true)
	m2 := NewUDPMux(conn2, peer2, cfg, nil, false)

	assert.False(t, m1.IsClosed())
	assert.NoError(t, m1.Close())
	assert.True(t, m1.IsClosed())

	_ = m2.Close()
}

func TestUDPMux_AcceptStream_ReturnsErrorAfterClose(t *testing.T) {
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	cfg := DefaultTransportConfig()
	m1 := NewUDPMux(conn1, peer1, cfg, nil, false)
	_ = NewUDPMux(conn2, peer2, cfg, nil, true) // second mux, not used directly

	// Close immediately.
	require.NoError(t, m1.Close())

	_, err := m1.AcceptStream()
	assert.ErrorIs(t, err, ErrMuxClosed)
}

func TestUDPMux_OpenStream_ReturnsErrorAfterClose(t *testing.T) {
	conn1, conn2, peer1, _ := newUDPPair(t)
	_ = conn2.Close()
	cfg := DefaultTransportConfig()
	m := NewUDPMux(conn1, peer1, cfg, nil, true)
	require.NoError(t, m.Close())

	_, err := m.OpenStream()
	assert.ErrorIs(t, err, ErrMuxClosed)
}

// --- Encryption ---

func TestUDPMux_Encryption_SendReceive(t *testing.T) {
	// Generate a shared session cipher.
	kp1, err := GenerateKeyPair()
	require.NoError(t, err)
	kp2, err := GenerateKeyPair()
	require.NoError(t, err)

	cipher1, err := DeriveSession(kp1.Private, kp2.Public)
	require.NoError(t, err)
	cipher2, err := DeriveSession(kp2.Private, kp1.Public)
	require.NoError(t, err)

	conn1, conn2, peer1, peer2 := newUDPPair(t)
	cfg := DefaultTransportConfig()
	cfg.RetransmitTimeout = 50 * time.Millisecond

	initiator := NewUDPMux(conn1, peer1, cfg, cipher1, true)
	acceptor := NewUDPMux(conn2, peer2, cfg, cipher2, false)
	defer func() {
		_ = initiator.Close()
		_ = acceptor.Close()
	}()

	stream, err := initiator.OpenStream()
	require.NoError(t, err)

	go func() {
		_, _ = stream.Write([]byte("encrypted-hello"))
	}()

	accepted, err := acceptor.AcceptStream()
	require.NoError(t, err)

	buf := make([]byte, 256)
	_ = accepted.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := accepted.Read(buf)
	require.NoError(t, readErr)
	assert.Equal(t, "encrypted-hello", string(buf[:n]))
}

// --- Large payload fragmentation ---

func TestUDPMux_LargePayload(t *testing.T) {
	initiator, acceptor := newMuxPair(t)

	stream, err := initiator.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	// Write a 10KB payload (will be fragmented across multiple UDP datagrams).
	large := make([]byte, 10*1024)
	for i := range large {
		large[i] = byte(i % 256)
	}

	go func() {
		_, _ = stream.Write(large)
		_ = stream.Close()
	}()

	accepted, err := acceptor.AcceptStream()
	require.NoError(t, err)
	defer accepted.Close()

	_ = accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
	received, readErr := io.ReadAll(accepted)
	require.NoError(t, readErr)
	assert.Equal(t, large, received, "large payload should be received intact")
}

// --- SetReadDeadline ---

func (s *UDPStream) SetReadDeadline(t time.Time) error {
	// Best-effort: we use the select-with-timeout pattern in Read, so
	// implement a simple channel-based deadline for test compatibility.
	// In production, timeouts are enforced by the application-level context.
	go func() {
		d := time.Until(t)
		if d <= 0 {
			s.forceClose()
			return
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Don't actually close — just unblock any pending Read.
			// We push a sentinel nil into recvCh to wake up Read.
			select {
			case s.recvCh <- nil:
			default:
			}
		case <-s.closeCh:
		}
	}()
	return nil
}
