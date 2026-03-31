package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MuxConfig contains configuration for a multiplexer.
type MuxConfig struct {
	// AcceptBacklog is the maximum number of pending streams.
	AcceptBacklog int

	// StreamConfig is the configuration for new streams.
	StreamConfig StreamConfig

	// KeepAliveInterval is the interval between keep-alive pings.
	// Set to 0 to disable keep-alive.
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is the timeout for keep-alive pings.
	KeepAliveTimeout time.Duration

	// MaxFrameSize is the maximum frame size.
	MaxFrameSize uint32

	// EnableFlowControl enables flow control.
	EnableFlowControl bool
}

// DefaultMuxConfig returns the default multiplexer configuration.
func DefaultMuxConfig() MuxConfig {
	return MuxConfig{
		AcceptBacklog:     256,
		StreamConfig:      DefaultStreamConfig(),
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
		MaxFrameSize:      DefaultFramePayloadSize,
		EnableFlowControl: true,
	}
}

// Mux is a multiplexer that manages multiple streams over a single connection.
type Mux struct {
	conn   net.Conn
	config MuxConfig
	codec  *FrameCodec

	// Stream management
	streams      map[uint32]*Stream
	streamLock   sync.RWMutex
	nextStreamID uint32
	acceptCh     chan *Stream
	isClient     bool

	// State
	closed   uint32
	closeCh  chan struct{}
	closeErr error
	closeMu  sync.Mutex

	// Send queue
	sendCh   chan *Frame
	sendLock sync.Mutex

	// Keep-alive
	pingID   uint32
	lastPing time.Time
	pingLock sync.Mutex
	pongCh   chan uint32

	// Shutdown
	shutdownOnce sync.Once
}

// Server creates a new server-side multiplexer.
func Server(conn net.Conn, config MuxConfig) (*Mux, error) {
	return newMux(conn, config, false)
}

// Client creates a new client-side multiplexer.
func Client(conn net.Conn, config MuxConfig) (*Mux, error) {
	return newMux(conn, config, true)
}

// newMux creates a new multiplexer.
func newMux(conn net.Conn, config MuxConfig, isClient bool) (*Mux, error) {
	if conn == nil {
		return nil, errors.New("conn cannot be nil")
	}

	m := &Mux{
		conn:     conn,
		config:   config,
		codec:    NewFrameCodec(WithMaxPayloadSize(config.MaxFrameSize)),
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, config.AcceptBacklog),
		isClient: isClient,
		closeCh:  make(chan struct{}),
		sendCh:   make(chan *Frame, 64),
		pongCh:   make(chan uint32, 4),
	}

	// Stream IDs: client uses odd, server uses even
	if isClient {
		m.nextStreamID = 1
	} else {
		m.nextStreamID = 2
	}

	// Start background goroutines
	go m.recvLoop()
	go m.sendLoop()

	if config.KeepAliveInterval > 0 {
		go m.keepAliveLoop()
	}

	return m, nil
}

// AcceptStream waits for and returns the next incoming stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	select {
	case stream := <-m.acceptCh:
		return stream, nil
	case <-m.closeCh:
		return nil, m.getCloseErr()
	}
}

// AcceptStreamContext waits for the next incoming stream with context.
func (m *Mux) AcceptStreamContext(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-m.acceptCh:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.closeCh:
		return nil, m.getCloseErr()
	}
}

// OpenStream opens a new stream.
func (m *Mux) OpenStream() (*Stream, error) {
	return m.OpenStreamContext(context.Background())
}

// OpenStreamContext opens a new stream with context.
func (m *Mux) OpenStreamContext(ctx context.Context) (*Stream, error) {
	if m.IsClosed() {
		return nil, m.getCloseErr()
	}

	// Check context before proceeding
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Allocate stream ID
	m.streamLock.Lock()
	id := m.nextStreamID
	m.nextStreamID += 2 // Skip by 2 to maintain odd/even

	// Create stream
	stream := newStream(id, m.config.StreamConfig, m)
	m.streams[id] = stream
	m.streamLock.Unlock()

	// Send handshake frame to notify remote
	if err := m.sendHandshake(id); err != nil {
		m.removeStream(id)
		return nil, fmt.Errorf("send handshake: %w", err)
	}

	return stream, nil
}

// NumStreams returns the number of active streams.
func (m *Mux) NumStreams() int {
	m.streamLock.RLock()
	defer m.streamLock.RUnlock()
	return len(m.streams)
}

// Close closes the multiplexer and all streams.
func (m *Mux) Close() error {
	return m.closeWithError(nil)
}

// closeWithError closes the multiplexer with the given error.
func (m *Mux) closeWithError(err error) error {
	var closeErr error
	m.shutdownOnce.Do(func() {
		atomic.StoreUint32(&m.closed, 1)

		m.closeMu.Lock()
		if err != nil {
			m.closeErr = err
		} else {
			m.closeErr = ErrMuxClosed
		}
		m.closeMu.Unlock()

		close(m.closeCh)

		// Copy streams list to avoid holding lock while closing
		m.streamLock.Lock()
		streams := make([]*Stream, 0, len(m.streams))
		for _, stream := range m.streams {
			streams = append(streams, stream)
		}
		m.streams = make(map[uint32]*Stream)
		m.streamLock.Unlock()

		// Close all streams (without holding streamLock)
		for _, stream := range streams {
			stream.forceClose()
		}

		// Close the connection
		closeErr = m.conn.Close()
	})
	return closeErr
}

// IsClosed returns whether the multiplexer is closed.
func (m *Mux) IsClosed() bool {
	return atomic.LoadUint32(&m.closed) == 1
}

// LocalAddr returns the local network address.
func (m *Mux) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (m *Mux) RemoteAddr() net.Addr {
	return m.conn.RemoteAddr()
}

// getCloseErr returns the close error.
func (m *Mux) getCloseErr() error {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.closeErr != nil {
		return m.closeErr
	}
	return ErrMuxClosed
}

// recvLoop handles incoming frames.
func (m *Mux) recvLoop() {
	defer func() { _ = m.closeWithError(nil) }()

	for {
		frame, err := m.codec.Decode(m.conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return
			}
			if m.IsClosed() {
				return
			}
			_ = m.closeWithError(fmt.Errorf("decode frame: %w", err))
			return
		}

		if err := m.handleFrame(frame); err != nil {
			if m.IsClosed() {
				return
			}
			_ = m.closeWithError(fmt.Errorf("handle frame: %w", err))
			return
		}
	}
}

// handleFrame processes an incoming frame.
func (m *Mux) handleFrame(f *Frame) error {
	switch f.Type {
	case FrameData:
		return m.handleData(f)
	case FrameWindowUpdate:
		return m.handleWindowUpdate(f)
	case FramePing:
		return m.handlePing(f)
	case FramePong:
		return m.handlePong(f)
	case FrameClose:
		return m.handleClose(f)
	case FrameHandshake:
		return m.handleHandshake(f)
	case FrameError:
		return m.handleError(f)
	default:
		return fmt.Errorf("unknown frame type: %d", f.Type)
	}
}

// handleData handles a data frame.
func (m *Mux) handleData(f *Frame) error {
	stream := m.getStream(f.StreamID)
	if stream == nil {
		// Stream not found, ignore
		return nil
	}
	return stream.receiveData(f.Payload)
}

// handleWindowUpdate handles a window update frame.
func (m *Mux) handleWindowUpdate(f *Frame) error {
	stream := m.getStream(f.StreamID)
	if stream == nil {
		return nil
	}

	increment, err := ParseWindowUpdate(f)
	if err != nil {
		return err
	}

	stream.receiveWindowUpdate(increment)
	return nil
}

// handlePing handles a ping frame.
func (m *Mux) handlePing(f *Frame) error {
	pingID, err := ParsePing(f)
	if err != nil {
		return err
	}

	// Send pong (ping response with same ID)
	return m.sendPong(pingID)
}

// handlePong handles a pong (ping response) frame.
func (m *Mux) handlePong(f *Frame) error {
	pongID, err := ParsePong(f)
	if err != nil {
		return err
	}

	// Notify keep-alive loop that pong was received
	select {
	case m.pongCh <- pongID:
	default:
		// pongCh is full, discard (non-blocking)
	}
	return nil
}

// handleClose handles a close frame.
func (m *Mux) handleClose(f *Frame) error {
	stream := m.getStream(f.StreamID)
	if stream == nil {
		return nil
	}

	stream.receiveClose()
	return nil
}

// handleHandshake handles a handshake frame (new stream request).
func (m *Mux) handleHandshake(f *Frame) error {
	// Create new stream for the remote's request
	stream := newStream(f.StreamID, m.config.StreamConfig, m)

	m.streamLock.Lock()
	if _, exists := m.streams[f.StreamID]; exists {
		m.streamLock.Unlock()
		return ErrStreamAlreadyExist
	}
	m.streams[f.StreamID] = stream
	m.streamLock.Unlock()

	// Put in accept queue
	select {
	case m.acceptCh <- stream:
	default:
		// Accept queue full, reject stream
		m.removeStream(f.StreamID)
		return m.sendError(f.StreamID, 503, "accept queue full")
	}

	return nil
}

// handleError handles an error frame.
func (m *Mux) handleError(f *Frame) error {
	stream := m.getStream(f.StreamID)
	if stream == nil {
		return nil
	}

	code, message, err := ParseError(f)
	if err != nil {
		return err
	}

	stream.receiveError(code, message)
	return nil
}

// sendLoop handles outgoing frames.
func (m *Mux) sendLoop() {
	for {
		select {
		case frame := <-m.sendCh:
			if err := m.writeFrame(frame); err != nil {
				if !m.IsClosed() {
					_ = m.closeWithError(fmt.Errorf("write frame: %w", err))
				}
				return
			}
		case <-m.closeCh:
			return
		}
	}
}

// writeFrame writes a frame to the connection.
func (m *Mux) writeFrame(f *Frame) error {
	m.sendLock.Lock()
	defer m.sendLock.Unlock()
	return m.codec.Encode(m.conn, f)
}

// keepAliveLoop sends periodic keep-alive pings and checks for pong responses.
func (m *Mux) keepAliveLoop() {
	ticker := time.NewTicker(m.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send ping
			if err := m.sendPing(); err != nil {
				if !m.IsClosed() {
					_ = m.closeWithError(fmt.Errorf("keep-alive failed: %w", err))
				}
				return
			}

			// Wait for pong with timeout
			if m.config.KeepAliveTimeout > 0 {
				m.pingLock.Lock()
				expectedID := m.pingID
				m.pingLock.Unlock()

				timeout := time.NewTimer(m.config.KeepAliveTimeout)
				select {
				case pongID := <-m.pongCh:
					timeout.Stop()
					if pongID != expectedID {
						// Mismatched pong, but not fatal - could be delayed
						// Drain any stale pongs
						for {
							select {
							case <-m.pongCh:
							default:
								goto drained
							}
						}
					drained:
					}
				case <-timeout.C:
					// Pong timeout - connection is dead
					if !m.IsClosed() {
						_ = m.closeWithError(fmt.Errorf("keep-alive timeout: no pong received within %v", m.config.KeepAliveTimeout))
					}
					return
				case <-m.closeCh:
					timeout.Stop()
					return
				}
			}
		case <-m.closeCh:
			return
		}
	}
}

// sendData sends a data frame.
func (m *Mux) sendData(streamID uint32, data []byte) error {
	if m.IsClosed() {
		return ErrMuxClosed
	}

	frame := NewDataFrame(streamID, data)
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return m.getCloseErr()
	}
}

// sendWindowUpdate sends a window update frame.
func (m *Mux) sendWindowUpdate(streamID uint32, increment uint32) error {
	if m.IsClosed() {
		return ErrMuxClosed
	}

	frame := NewWindowUpdateFrame(streamID, increment)
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return m.getCloseErr()
	}
}

// sendClose sends a close frame.
func (m *Mux) sendClose(streamID uint32) error { //nolint:unparam // error return reserved for future use
	if m.IsClosed() {
		return nil
	}

	frame := NewCloseFrame(streamID)
	// Use non-blocking send to avoid deadlock during shutdown
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return nil
	default:
		// Channel full, try with timeout
		select {
		case m.sendCh <- frame:
			return nil
		case <-m.closeCh:
			return nil
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	}
}

// sendHandshake sends a handshake frame.
func (m *Mux) sendHandshake(streamID uint32) error {
	if m.IsClosed() {
		return ErrMuxClosed
	}

	frame := NewFrame(FrameHandshake, streamID, nil)
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return m.getCloseErr()
	}
}

// sendPing sends a ping frame.
func (m *Mux) sendPing() error {
	m.pingLock.Lock()
	m.pingID++
	pingID := m.pingID
	m.lastPing = time.Now()
	m.pingLock.Unlock()

	frame := NewPingFrame(pingID)
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return m.getCloseErr()
	}
}

// sendPong sends a pong (ping response) frame.
func (m *Mux) sendPong(pingID uint32) error {
	if m.IsClosed() {
		return nil
	}

	frame := NewPongFrame(pingID)
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return nil
	}
}

// sendError sends an error frame.
func (m *Mux) sendError(streamID uint32, code uint32, message string) error {
	if m.IsClosed() {
		return nil
	}

	frame := NewErrorFrame(streamID, code, message)
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		return nil
	}
}

// getStream returns the stream with the given ID.
func (m *Mux) getStream(id uint32) *Stream {
	m.streamLock.RLock()
	defer m.streamLock.RUnlock()
	return m.streams[id]
}

// removeStream removes a stream from the multiplexer.
func (m *Mux) removeStream(id uint32) {
	m.streamLock.Lock()
	delete(m.streams, id)
	m.streamLock.Unlock()
}
