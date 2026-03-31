package tunnel

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Stream state constants
const (
	streamStateOpen uint32 = iota
	streamStateLocalClose
	streamStateRemoteClose
	streamStateClosed
)

// StreamConfig contains configuration for a stream.
type StreamConfig struct {
	// WindowSize is the initial flow control window size.
	WindowSize uint32

	// MaxWindowSize is the maximum window size.
	MaxWindowSize uint32

	// ReadBufferSize is the size of the read buffer.
	ReadBufferSize int
}

// DefaultStreamConfig returns the default stream configuration.
func DefaultStreamConfig() StreamConfig {
	return StreamConfig{
		WindowSize:     256 * 1024,       // 256KB
		MaxWindowSize:  16 * 1024 * 1024, // 16MB
		ReadBufferSize: 64 * 1024,        // 64KB
	}
}

// Stream represents a virtual stream within a multiplexed connection.
// It implements io.ReadWriteCloser and provides flow control.
type Stream struct {
	id     uint32
	config StreamConfig
	mux    *Mux

	// State management
	state     uint32
	stateLock sync.Mutex
	closeOnce sync.Once

	// Read side
	readBuffer  *ringBuffer
	readCond    *sync.Cond
	readTimeout time.Time
	readLock    sync.Mutex

	// Write side
	sendWindow   int64
	sendCond     *sync.Cond
	writeTimeout time.Time
	writeLock    sync.Mutex

	// Receive window tracking
	recvWindow     int64
	recvWindowLock sync.Mutex

	// Close notification
	closeCh chan struct{}

	// Error from remote
	remoteErr error
}

// newStream creates a new stream with the given ID and configuration.
func newStream(id uint32, config StreamConfig, mux *Mux) *Stream {
	s := &Stream{
		id:         id,
		config:     config,
		mux:        mux,
		state:      streamStateOpen,
		readBuffer: newRingBuffer(config.ReadBufferSize),
		sendWindow: int64(config.WindowSize),
		recvWindow: int64(config.WindowSize),
		closeCh:    make(chan struct{}),
	}
	s.readCond = sync.NewCond(&s.readLock)
	s.sendCond = sync.NewCond(&s.writeLock)
	return s
}

// ID returns the stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// Read reads data from the stream.
// It blocks until data is available, the stream is closed, or the deadline expires.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.readLock.Lock()
	defer s.readLock.Unlock()

	for {
		// Check if stream is closed
		state := atomic.LoadUint32(&s.state)
		if state == streamStateClosed || state == streamStateRemoteClose {
			// Drain any remaining data in buffer first
			if s.readBuffer.Len() > 0 {
				n := s.readBuffer.Read(p)
				s.updateRecvWindow(n)
				return n, nil
			}
			if s.remoteErr != nil {
				return 0, s.remoteErr
			}
			return 0, io.EOF
		}

		// Try to read from buffer
		if s.readBuffer.Len() > 0 {
			n := s.readBuffer.Read(p)
			s.updateRecvWindow(n)
			return n, nil
		}

		// Check timeout
		if !s.readTimeout.IsZero() {
			if time.Now().After(s.readTimeout) {
				return 0, ErrTimeout
			}
			// Wait with timeout
			timeout := time.Until(s.readTimeout)
			timer := time.AfterFunc(timeout, func() {
				s.readCond.Broadcast()
			})
			s.readCond.Wait()
			timer.Stop()
		} else {
			// Wait indefinitely
			s.readCond.Wait()
		}
	}
}

// Write writes data to the stream.
// It blocks until all data is written, the stream is closed, or the deadline expires.
func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	// Check if stream is closed
	state := atomic.LoadUint32(&s.state)
	if state == streamStateClosed || state == streamStateLocalClose {
		return 0, ErrStreamClosed
	}

	written := 0
	for written < len(p) {
		// Wait for send window
		for atomic.LoadInt64(&s.sendWindow) <= 0 {
			state := atomic.LoadUint32(&s.state)
			if state == streamStateClosed || state == streamStateLocalClose {
				return written, ErrStreamClosed
			}

			// Check timeout
			if !s.writeTimeout.IsZero() {
				if time.Now().After(s.writeTimeout) {
					return written, ErrTimeout
				}
				timeout := time.Until(s.writeTimeout)
				timer := time.AfterFunc(timeout, func() {
					s.sendCond.Broadcast()
				})
				s.sendCond.Wait()
				timer.Stop()
			} else {
				s.sendCond.Wait()
			}
		}

		// Calculate how much we can send
		window := atomic.LoadInt64(&s.sendWindow)
		remaining := len(p) - written
		toSend := remaining
		if int64(toSend) > window {
			toSend = int(window)
		}
		if toSend > int(DefaultFramePayloadSize) {
			toSend = int(DefaultFramePayloadSize)
		}

		// Send the data
		if err := s.mux.sendData(s.id, p[written:written+toSend]); err != nil {
			return written, err
		}

		// Update window and written count
		atomic.AddInt64(&s.sendWindow, -int64(toSend))
		written += toSend
	}

	return written, nil
}

// Close closes the stream.
func (s *Stream) Close() error {
	return s.closeWithError(nil)
}

// forceClose closes the stream without sending close frame or removing from mux.
// This is used when the mux itself is closing to avoid deadlocks.
func (s *Stream) forceClose() {
	s.closeOnce.Do(func() {
		atomic.StoreUint32(&s.state, streamStateClosed)

		// Close notification channel
		select {
		case <-s.closeCh:
			// Already closed
		default:
			close(s.closeCh)
		}

		// Wake up any waiting readers/writers
		s.readCond.Broadcast()
		s.sendCond.Broadcast()
	})
}

// closeWithError closes the stream with the given error.
func (s *Stream) closeWithError(err error) error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.stateLock.Lock()
		state := atomic.LoadUint32(&s.state)

		switch state {
		case streamStateClosed:
			s.stateLock.Unlock()
			return
		case streamStateRemoteClose:
			// Remote already closed, just transition to fully closed
			atomic.StoreUint32(&s.state, streamStateClosed)
		default:
			// Send close frame (don't hold stateLock while sending)
			atomic.StoreUint32(&s.state, streamStateLocalClose)
			s.stateLock.Unlock()

			// Send close frame - ignore error as connection may be closed
			if s.mux != nil && !s.mux.IsClosed() {
				closeErr = s.mux.sendClose(s.id)
			}

			s.stateLock.Lock()
			s.readLock.Lock()
			hasRemoteErr := s.remoteErr != nil
			s.readLock.Unlock()
			if err == nil && !hasRemoteErr {
				atomic.StoreUint32(&s.state, streamStateClosed)
			}
		}
		s.stateLock.Unlock()

		// Close notification channel (safe to call multiple times due to closeOnce)
		select {
		case <-s.closeCh:
			// Already closed
		default:
			close(s.closeCh)
		}

		// Wake up any waiting readers/writers
		s.readCond.Broadcast()
		s.sendCond.Broadcast()

		// Remove from mux
		if s.mux != nil {
			s.mux.removeStream(s.id)
		}
	})
	return closeErr
}

// SetDeadline sets the read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readLock.Lock()
	s.readTimeout = t
	s.readLock.Unlock()
	s.readCond.Broadcast()
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeLock.Lock()
	s.writeTimeout = t
	s.writeLock.Unlock()
	s.sendCond.Broadcast()
	return nil
}

// IsClosed returns whether the stream is closed.
func (s *Stream) IsClosed() bool {
	state := atomic.LoadUint32(&s.state)
	return state == streamStateClosed
}

// Done returns a channel that is closed when the stream is closed.
func (s *Stream) Done() <-chan struct{} {
	return s.closeCh
}

// receiveData is called by the mux when data is received for this stream.
func (s *Stream) receiveData(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	s.readLock.Lock()
	defer s.readLock.Unlock()

	// Check if stream is closed
	state := atomic.LoadUint32(&s.state)
	if state == streamStateClosed || state == streamStateLocalClose {
		return ErrStreamClosed
	}

	// Write to buffer
	written := s.readBuffer.Write(data)
	if written < len(data) {
		// Buffer full, this shouldn't happen with proper flow control
		return errors.New("read buffer full")
	}

	// Wake up reader
	s.readCond.Signal()
	return nil
}

// receiveWindowUpdate is called when a window update is received.
func (s *Stream) receiveWindowUpdate(increment uint32) {
	atomic.AddInt64(&s.sendWindow, int64(increment))
	s.sendCond.Broadcast()
}

// receiveClose is called when a close frame is received.
func (s *Stream) receiveClose() {
	s.stateLock.Lock()
	state := atomic.LoadUint32(&s.state)

	switch state {
	case streamStateClosed:
		s.stateLock.Unlock()
		return
	case streamStateLocalClose:
		// We already closed, now fully closed
		atomic.StoreUint32(&s.state, streamStateClosed)
	default:
		atomic.StoreUint32(&s.state, streamStateRemoteClose)
	}
	s.stateLock.Unlock()

	// Wake up readers
	s.readCond.Broadcast()
}

// receiveError is called when an error frame is received.
func (s *Stream) receiveError(code uint32, message string) {
	s.readLock.Lock()
	s.remoteErr = &RemoteError{Code: code, Message: message}
	s.readLock.Unlock()
	s.receiveClose()
}

// updateRecvWindow updates the receive window and sends window update if needed.
func (s *Stream) updateRecvWindow(bytesRead int) {
	s.recvWindowLock.Lock()
	s.recvWindow += int64(bytesRead)

	// Send window update when we've consumed half the window
	threshold := int64(s.config.WindowSize / 2)
	if s.recvWindow >= threshold {
		increment := uint32(s.recvWindow)
		s.recvWindow = 0
		s.recvWindowLock.Unlock()

		// Send window update frame (ignore error, best effort)
		s.mux.sendWindowUpdate(s.id, increment)
		return
	}
	s.recvWindowLock.Unlock()
}

// RemoteError represents an error received from the remote end.
type RemoteError struct {
	Code    uint32
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "remote error"
}

// ringBuffer is a simple ring buffer for stream read buffering.
// It supports auto-growing when the buffer is full to handle large data transfers.
type ringBuffer struct {
	buf     []byte
	r       int // read position
	w       int // write position
	size    int // current data size
	initCap int // initial capacity for growth limit
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{
		buf:     make([]byte, capacity),
		initCap: capacity,
	}
}

func (rb *ringBuffer) Len() int {
	return rb.size
}

func (rb *ringBuffer) Cap() int {
	return len(rb.buf)
}

func (rb *ringBuffer) Available() int {
	return len(rb.buf) - rb.size
}

// grow doubles the buffer capacity, preserving existing data.
// Maximum growth is 16x the initial capacity.
func (rb *ringBuffer) grow() bool {
	maxCap := rb.initCap * 16
	if len(rb.buf) >= maxCap {
		return false
	}
	newCap := min(len(rb.buf)*2, maxCap)
	newBuf := make([]byte, newCap)

	// Linearize existing data into the new buffer
	if rb.size > 0 {
		if rb.r < rb.w {
			copy(newBuf, rb.buf[rb.r:rb.w])
		} else {
			n := copy(newBuf, rb.buf[rb.r:])
			copy(newBuf[n:], rb.buf[:rb.w])
		}
	}
	rb.buf = newBuf
	rb.r = 0
	rb.w = rb.size
	return true
}

func (rb *ringBuffer) Write(p []byte) int {
	if len(p) == 0 {
		return 0
	}

	// Auto-grow if not enough space
	for rb.Available() < len(p) {
		if !rb.grow() {
			break
		}
	}

	if rb.Available() == 0 {
		return 0
	}

	toWrite := min(len(p), rb.Available())

	// Two-phase copy to handle wrap-around
	// Phase 1: write from rb.w to end of buffer
	end := min(len(rb.buf)-rb.w, toWrite)
	copy(rb.buf[rb.w:rb.w+end], p[:end])

	// Phase 2: write remaining from beginning of buffer (wrap-around)
	remaining := toWrite - end
	if remaining > 0 {
		copy(rb.buf[0:remaining], p[end:toWrite])
	}

	rb.w = (rb.w + toWrite) % len(rb.buf)
	rb.size += toWrite
	return toWrite
}

func (rb *ringBuffer) Read(p []byte) int {
	if len(p) == 0 || rb.size == 0 {
		return 0
	}

	toRead := min(len(p), rb.size)

	// Two-phase copy to handle wrap-around
	// Phase 1: read from rb.r to end of buffer
	end := min(len(rb.buf)-rb.r, toRead)
	copy(p[:end], rb.buf[rb.r:rb.r+end])

	// Phase 2: read remaining from beginning of buffer (wrap-around)
	remaining := toRead - end
	if remaining > 0 {
		copy(p[end:toRead], rb.buf[0:remaining])
	}

	rb.r = (rb.r + toRead) % len(rb.buf)
	rb.size -= toRead
	return toRead
}

func (rb *ringBuffer) Reset() {
	rb.r = 0
	rb.w = 0
	rb.size = 0
}
