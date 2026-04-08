package tunnel

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRingBuffer_Basic(t *testing.T) {
	rb := newRingBuffer(10)

	assert.Equal(t, 0, rb.Len())
	assert.Equal(t, 10, rb.Cap())
	assert.Equal(t, 10, rb.Available())
}

func TestRingBuffer_WriteRead(t *testing.T) {
	rb := newRingBuffer(10)

	// Write some data
	n := rb.Write([]byte("hello"))
	assert.Equal(t, 5, n)
	assert.Equal(t, 5, rb.Len())

	// Read it back
	buf := make([]byte, 10)
	n = rb.Read(buf)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(buf[:n]))
	assert.Equal(t, 0, rb.Len())
}

func TestRingBuffer_WrapAround(t *testing.T) {
	rb := newRingBuffer(10)

	// Fill partially
	rb.Write([]byte("12345"))
	// Read some
	buf := make([]byte, 3)
	rb.Read(buf)
	assert.Equal(t, "123", string(buf))

	// Write more (should wrap)
	rb.Write([]byte("67890123"))
	assert.Equal(t, 10, rb.Len())

	// Read all
	result := make([]byte, 10)
	n := rb.Read(result)
	assert.Equal(t, 10, n)
	assert.Equal(t, "4567890123", string(result[:n]))
}

func TestRingBuffer_Full(t *testing.T) {
	rb := newRingBuffer(5)

	// Fill completely
	n := rb.Write([]byte("12345"))
	assert.Equal(t, 5, n)
	assert.Equal(t, 5, rb.Len())
	assert.Equal(t, 0, rb.Available())

	// Write more - buffer should auto-grow
	n = rb.Write([]byte("678"))
	assert.Equal(t, 3, n)
	assert.Equal(t, 8, rb.Len())
	assert.True(t, rb.Cap() > 5, "Buffer should have grown")

	// Read all
	buf := make([]byte, 8)
	n = rb.Read(buf)
	assert.Equal(t, 8, n)
	assert.Equal(t, "12345678", string(buf[:n]))
}

func TestRingBuffer_GrowLimit(t *testing.T) {
	// initCap=4, maxCap=4*16=64
	rb := newRingBuffer(4)

	// Keep writing until buffer can't grow anymore
	totalWritten := 0
	for range 100 {
		n := rb.Write([]byte("ABCD"))
		if n == 0 {
			break
		}
		totalWritten += n
	}

	// Buffer should have grown to maxCap (4 * 16 = 64)
	assert.Equal(t, 64, rb.Cap(), "Buffer should have grown to max capacity")
	assert.Equal(t, 64, rb.Len(), "Buffer should be full")
	assert.Equal(t, 0, rb.Available())

	// Now writing should fail (no more room and can't grow)
	n := rb.Write([]byte("X"))
	assert.Equal(t, 0, n, "Write should fail when buffer is at max capacity and full")

	// Read everything back and verify data integrity
	buf := make([]byte, 64)
	n = rb.Read(buf)
	assert.Equal(t, 64, n)
	// All data should be "ABCD" repeated
	for i := 0; i < 64; i += 4 {
		assert.Equal(t, "ABCD", string(buf[i:i+4]))
	}
}

func TestRingBuffer_GrowPreservesData(t *testing.T) {
	rb := newRingBuffer(8)

	// Write and partially read to create wrap-around state
	rb.Write([]byte("ABCDEF")) // w=6, r=0
	buf := make([]byte, 4)
	rb.Read(buf) // w=6, r=4
	assert.Equal(t, "ABCD", string(buf))

	rb.Write([]byte("GHIJ"))     // w=2, r=4 (wrapped)
	assert.Equal(t, 6, rb.Len()) // "EF" + "GHIJ"

	// Now write more than available space to trigger grow
	// Available = 8-6 = 2, writing 4 bytes should trigger grow
	n := rb.Write([]byte("KLMN"))
	assert.Equal(t, 4, n)
	assert.True(t, rb.Cap() > 8, "Buffer should have grown")
	assert.Equal(t, 10, rb.Len())

	// Read all data and verify order
	result := make([]byte, 10)
	n = rb.Read(result)
	assert.Equal(t, 10, n)
	assert.Equal(t, "EFGHIJKLMN", string(result[:n]))
}

func TestRingBuffer_Reset(t *testing.T) {
	rb := newRingBuffer(10)
	rb.Write([]byte("hello"))
	rb.Reset()

	assert.Equal(t, 0, rb.Len())
	assert.Equal(t, 10, rb.Available())
}

func TestRemoteError(t *testing.T) {
	err := &RemoteError{Code: 500, Message: "internal error"}
	assert.Equal(t, "internal error", err.Error())

	err2 := &RemoteError{Code: 404}
	assert.Equal(t, "remote error", err2.Error())
}

func TestStream_ID(t *testing.T) {
	// Create a mock mux
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(42, DefaultStreamConfig(), mux)
	assert.Equal(t, uint32(42), s.ID())
}

func TestStream_IsClosed(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}
	mux.streams[1] = nil // Prevent nil pointer

	s := newStream(1, DefaultStreamConfig(), mux)
	assert.False(t, s.IsClosed())

	// Simulate close
	s.state = streamStateClosed
	assert.True(t, s.IsClosed())
}

func TestStream_SetDeadline(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)
	deadline := time.Now().Add(1 * time.Second)

	err := s.SetDeadline(deadline)
	require.NoError(t, err)

	assert.Equal(t, deadline, s.readTimeout)
	assert.Equal(t, deadline, s.writeTimeout)
}

func TestStream_ReceiveData(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)

	// Receive some data
	err := s.receiveData([]byte("hello"))
	require.NoError(t, err)

	// Read it back (non-blocking since data is in buffer)
	buf := make([]byte, 10)
	done := make(chan int)
	go func() {
		n, _ := s.Read(buf)
		done <- n
	}()

	select {
	case n := <-done:
		assert.Equal(t, 5, n)
		assert.Equal(t, "hello", string(buf[:n]))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Read timed out")
	}
}

func TestStream_ReceiveClose(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)

	// Start a read that will block
	readDone := make(chan error)
	go func() {
		buf := make([]byte, 10)
		_, err := s.Read(buf)
		readDone <- err
	}()

	// Small delay to ensure read is waiting
	time.Sleep(10 * time.Millisecond)

	// Receive close
	s.receiveClose()

	// Read should return EOF
	select {
	case err := <-readDone:
		assert.Equal(t, io.EOF, err)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Read did not unblock after close")
	}
}

func TestStream_ReceiveError(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)

	// Start a read
	readDone := make(chan error)
	go func() {
		buf := make([]byte, 10)
		_, err := s.Read(buf)
		readDone <- err
	}()

	time.Sleep(10 * time.Millisecond)

	// Receive error
	s.receiveError(500, "internal error")

	select {
	case err := <-readDone:
		require.Error(t, err)
		remoteErr, ok := err.(*RemoteError)
		require.True(t, ok)
		assert.Equal(t, uint32(500), remoteErr.Code)
		assert.Equal(t, "internal error", remoteErr.Message)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Read did not unblock after error")
	}
}

func TestStream_ReceiveWindowUpdate(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)
	initialWindow := s.sendWindow

	s.receiveWindowUpdate(1000)
	assert.Equal(t, initialWindow+1000, s.sendWindow)
}

func TestStream_Done(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}
	mux.streams[1] = nil

	s := newStream(1, DefaultStreamConfig(), mux)

	// Channel should not be closed initially
	select {
	case <-s.Done():
		t.Fatal("Done channel should not be closed")
	default:
		// Expected
	}

	// Close the stream
	s.closeWithError(nil)

	// Now it should be closed
	select {
	case <-s.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Done channel should be closed")
	}
}

func TestStream_ReadEmptyBuffer(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)

	// Read with empty buffer should return 0
	n, err := s.Read(nil)
	assert.Equal(t, 0, n)
	assert.NoError(t, err)

	n, err = s.Read([]byte{})
	assert.Equal(t, 0, n)
	assert.NoError(t, err)
}

func TestStream_WriteEmptyBuffer(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)

	// Write with empty buffer should return 0
	n, err := s.Write(nil)
	assert.Equal(t, 0, n)
	assert.NoError(t, err)

	n, err = s.Write([]byte{})
	assert.Equal(t, 0, n)
	assert.NoError(t, err)
}

func TestStream_ReadTimeout(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)
	s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	buf := make([]byte, 10)
	start := time.Now()
	_, err := s.Read(buf)
	elapsed := time.Since(start)

	assert.ErrorIs(t, err, ErrTimeout)
	assert.True(t, elapsed >= 40*time.Millisecond, "Should have waited for timeout")
	assert.True(t, elapsed < 200*time.Millisecond, "Should not wait too long")
}

// TestStream_WriteTimeout verifies that Write returns ErrTimeout when
// the send window is exhausted and the write deadline expires.
func TestStream_WriteTimeout(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	// Use a very small window so it drains quickly.
	cfg.StreamConfig.WindowSize = 64
	cfg.EnableFlowControl = true

	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	// Accept on server side but do NOT read — this prevents window updates
	// from being sent back, so the client's sendWindow will drain.
	_, err = serverMux.AcceptStream()
	require.NoError(t, err)

	// Set a tight write deadline.
	_ = clientStream.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))

	// Write enough data to exhaust the 64-byte send window, then block.
	// The first writes will succeed (up to 64 bytes), the rest will block
	// until the deadline fires.
	largeData := make([]byte, 1024) // Much larger than 64-byte window.
	_, writeErr := clientStream.Write(largeData)
	require.Error(t, writeErr)
	assert.ErrorIs(t, writeErr, ErrTimeout)
}

// TestStream_WriteClosed verifies that Write returns ErrStreamClosed
// when the stream is closed (locally) while writing.
func TestStream_WriteClosed(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0

	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)
	defer clientMux.Close()

	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	_, err = serverMux.AcceptStream()
	require.NoError(t, err)

	// Close the stream then attempt to write.
	_ = clientStream.Close()

	_, writeErr := clientStream.Write([]byte("should fail"))
	require.Error(t, writeErr)
	assert.ErrorIs(t, writeErr, ErrStreamClosed)
}

// TestStream_WriteAfterMuxClose verifies that Write returns an error
// when the underlying mux is closed mid-write.
func TestStream_WriteAfterMuxClose(t *testing.T) {
	clientConn, serverConn := testConn()

	cfg := DefaultMuxConfig()
	cfg.KeepAliveInterval = 0
	cfg.StreamConfig.WindowSize = 64 // Small window.

	serverMux, err := Server(serverConn, cfg)
	require.NoError(t, err)
	defer serverMux.Close()

	clientMux, err := Client(clientConn, cfg)
	require.NoError(t, err)

	clientStream, err := clientMux.OpenStream()
	require.NoError(t, err)

	// Accept on server but don't read (exhaust window).
	_, err = serverMux.AcceptStream()
	require.NoError(t, err)

	// Close mux while write is blocked.
	writeDone := make(chan error, 1)
	go func() {
		data := make([]byte, 1024)
		_, writeErr := clientStream.Write(data)
		writeDone <- writeErr
	}()

	// Give write goroutine time to start and block on sendWindow.
	time.Sleep(50 * time.Millisecond)

	// Close the mux — this should unblock the write.
	_ = clientMux.Close()

	select {
	case writeErr := <-writeDone:
		require.Error(t, writeErr)
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not unblock after mux close")
	}
}

// TestStream_ReceiveClose_AlreadyClosed verifies that receiveClose
// is a no-op when the stream is already in streamStateClosed.
func TestStream_ReceiveClose_AlreadyClosed(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}
	mux.streams[1] = nil

	s := newStream(1, DefaultStreamConfig(), mux)

	// Manually set state to Closed.
	s.state = streamStateClosed

	// receiveClose should be a no-op (not panic).
	s.receiveClose()
	assert.True(t, s.IsClosed())
}

// TestStream_ReceiveClose_FromLocalClose verifies that receiveClose
// transitions from streamStateLocalClose to streamStateClosed.
func TestStream_ReceiveClose_FromLocalClose(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}
	mux.streams[1] = nil

	s := newStream(1, DefaultStreamConfig(), mux)

	// Manually set state to LocalClose (as if we already called Close).
	s.state = streamStateLocalClose

	// receiveClose from remote should transition to Closed.
	s.receiveClose()
	assert.True(t, s.IsClosed())
}

// TestStream_ReceiveData_ClosedStream verifies that receiveData returns
// ErrStreamClosed when the stream is already closed.
func TestStream_ReceiveData_ClosedStream(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)
	s.state = streamStateClosed

	err := s.receiveData([]byte("should fail"))
	assert.ErrorIs(t, err, ErrStreamClosed)
}

// TestStream_ReceiveData_Empty verifies that empty data is a no-op.
func TestStream_ReceiveData_Empty(t *testing.T) {
	mux := &Mux{
		streams:    make(map[uint32]*Stream),
		closeCh:    make(chan struct{}),
		sendCh:     make(chan *Frame, 64),
		config:     DefaultMuxConfig(),
		codec:      NewFrameCodec(),
		streamLock: sync.RWMutex{},
	}

	s := newStream(1, DefaultStreamConfig(), mux)

	err := s.receiveData(nil)
	assert.NoError(t, err)

	err = s.receiveData([]byte{})
	assert.NoError(t, err)
}

func TestDefaultStreamConfig(t *testing.T) {
	config := DefaultStreamConfig()

	assert.Equal(t, uint32(256*1024), config.WindowSize)
	assert.Equal(t, uint32(16*1024*1024), config.MaxWindowSize)
	assert.Equal(t, 64*1024, config.ReadBufferSize)
}

// Integration test with actual mux would go here once mux is implemented

func BenchmarkRingBuffer_Write(b *testing.B) {
	rb := newRingBuffer(64 * 1024)
	data := make([]byte, 1024)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rb.Write(data)
		if rb.Available() < 1024 {
			rb.Reset()
		}
	}
}

func BenchmarkRingBuffer_Read(b *testing.B) {
	rb := newRingBuffer(64 * 1024)
	data := make([]byte, 1024)
	buf := make([]byte, 1024)

	// Pre-fill
	rb.Write(bytes.Repeat(data, 60))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if rb.Len() < 1024 {
			rb.Write(data)
		}
		rb.Read(buf)
	}
}
