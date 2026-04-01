package p2p

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransport_BasicSendReceive(t *testing.T) {
	// Create two UDP sockets.
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond

	// Create transports.
	t1 := NewTransport(conn1, addr2, config)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config)
	defer t2.Close()

	// Send data from t1 to t2.
	testData := []byte("Hello, P2P World!")
	n, err := t1.Write(testData)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Receive data on t2.
	buf := make([]byte, 1024)
	done := make(chan struct{})

	go func() {
		n, readErr := t2.Read(buf)
		if readErr == nil {
			assert.Equal(t, len(testData), n)
			assert.Equal(t, testData, buf[:n])
		}
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Read timed out")
	}
}

func TestTransport_Bidirectional(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond

	t1 := NewTransport(conn1, addr2, config)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config)
	defer t2.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// t1 -> t2
	go func() {
		defer wg.Done()
		_, writeErr := t1.Write([]byte("from t1"))
		assert.NoError(t, writeErr)
	}()

	// t2 -> t1
	go func() {
		defer wg.Done()
		_, writeErr := t2.Write([]byte("from t2"))
		assert.NoError(t, writeErr)
	}()

	wg.Wait()

	// Read both messages with timeout.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)

		// Read on t1.
		n, readErr := t1.Read(buf)
		if readErr == nil {
			assert.Equal(t, "from t2", string(buf[:n]))
		}

		// Read on t2.
		n, readErr = t2.Read(buf)
		if readErr == nil {
			assert.Equal(t, "from t1", string(buf[:n]))
		}

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Bidirectional read timed out")
	}
}

func TestTransport_LargeMessage(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	config.MaxPacketSize = 100 // Small packets to test fragmentation.

	t1 := NewTransport(conn1, addr2, config)
	defer t1.Close()

	t2 := NewTransport(conn2, addr1, config)
	defer t2.Close()

	// Send large data that will be split into multiple packets.
	largeData := bytes.Repeat([]byte("X"), 500)
	_, err = t1.Write(largeData)
	require.NoError(t, err)

	// Receive all fragments.
	received := make([]byte, 0, len(largeData))
	buf := make([]byte, 1024)

	done := make(chan struct{})
	go func() {
		for len(received) < len(largeData) {
			n, readErr := t2.Read(buf)
			if readErr != nil {
				break
			}
			received = append(received, buf[:n]...)
		}
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, largeData, received)
	case <-time.After(10 * time.Second):
		t.Fatalf("Large message read timed out, received %d/%d bytes", len(received), len(largeData))
	}
}

func TestTransport_Close(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	addr1 := conn1.LocalAddr().(*net.UDPAddr)
	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	t1 := NewTransport(conn1, addr2, config)
	t2 := NewTransport(conn2, addr1, config)

	// Close t1.
	err = t1.Close()
	assert.NoError(t, err)

	// Writing to closed transport should fail.
	_, err = t1.Write([]byte("test"))
	assert.Error(t, err)

	// Close t2 as well.
	_ = t2.Close()
	_ = conn1.Close()
	_ = conn2.Close()
}

func TestTransport_Stats(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn2.Close()

	addr2 := conn2.LocalAddr().(*net.UDPAddr)

	config := DefaultTransportConfig()
	tr := NewTransport(conn1, addr2, config)
	defer tr.Close()

	// Initial stats should be zero.
	stats := tr.Stats()
	assert.Equal(t, uint32(0), stats.SendSeq)
	assert.Equal(t, uint32(0), stats.RecvSeq)

	// Send some data.
	_, _ = tr.Write([]byte("test"))

	stats = tr.Stats()
	assert.Equal(t, uint32(1), stats.SendSeq)
}

func TestTransportConfig_Defaults(t *testing.T) {
	config := DefaultTransportConfig()

	assert.Equal(t, 1400, config.MaxPacketSize)
	assert.Equal(t, 200*time.Millisecond, config.RetransmitTimeout)
	assert.Equal(t, 10, config.MaxRetransmits)
	assert.Equal(t, 5*time.Second, config.AckTimeout)
	assert.Equal(t, 256, config.RecvBufferSize)
}
