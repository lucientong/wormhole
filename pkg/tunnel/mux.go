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
}

// DefaultMuxConfig returns the default multiplexer configuration.
func DefaultMuxConfig() MuxConfig {
	return MuxConfig{
		AcceptBacklog:     256,
		StreamConfig:      DefaultStreamConfig(),
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
		MaxFrameSize:      DefaultFramePayloadSize,
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

	// Send queues. DATA frames (bulk, potentially large volume) and
	// control frames (WINDOW_UPDATE/PING/PONG/HANDSHAKE/ERROR, small and
	// latency-sensitive) are kept in a separate channel — see sendLoop for
	// why sharing one queue between them is a deadlock risk. CLOSE stays on
	// sendCh (with DATA) because it must never overtake a stream's own
	// still-queued data frames — see sendClose.
	sendCh   chan *Frame // DATA and CLOSE frames, per-stream order matters
	ctrlCh   chan *Frame // WINDOW_UPDATE/PING/PONG/HANDSHAKE/ERROR
	sendLock sync.Mutex

	// Keep-alive
	pingID   uint32
	lastPing time.Time
	pingLock sync.Mutex
	pongCh   chan uint32

	// dataBufPool recycles the payload buffers sendData copies outgoing
	// writes into, replacing a fresh make+copy per Stream.Write
	// call with pool reuse on the hot data path. Buffers are always
	// DefaultFramePayloadSize (the cap that stream.go's Write ever
	// requests); sendData falls back to a plain make for anything larger,
	// which should not happen in practice.
	dataBufPool sync.Pool

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
		ctrlCh:   make(chan *Frame, 64),
		pongCh:   make(chan uint32, 4),
	}
	m.dataBufPool.New = func() any {
		buf := make([]byte, DefaultFramePayloadSize)
		return &buf
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

// CloseNotify returns a channel that is closed when the multiplexer is
// closed, either explicitly via Close() or because the underlying
// connection died. Callers can select on this channel to detect connection
// loss without polling IsClosed(). The channel is closed exactly once and
// never sends a value.
func (m *Mux) CloseNotify() <-chan struct{} {
	return m.closeCh
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
//
// Control frames (ctrlCh) are always drained ahead of data frames
// (sendCh): a WINDOW_UPDATE that unblocks the peer's flow control, or a
// PONG that answers a keep-alive PING, must never sit queued behind a
// backlog of bulk DATA frames. Without this priority, a connection
// saturated with data in both directions could deadlock — this side's
// recvLoop calls sendPong synchronously from handlePing, and if that send
// blocked on a full shared queue, recvLoop would stop draining the
// socket, which stalls the peer's writes via TCP backpressure, which
// stalls the peer's own recvLoop the same way, and so on. Giving control
// frames their own queue (checked first, and never so backlogged that
// sendPong/sendWindowUpdate block for long) keeps recvLoop always able to
// make progress regardless of how much data is queued.
func (m *Mux) sendLoop() {
	for {
		// Opportunistically drain any already-queued control frames
		// before considering data frames, so a control frame enqueued
		// while sendCh was being serviced doesn't wait behind it.
		select {
		case frame := <-m.ctrlCh:
			if err := m.writeFrame(frame); err != nil {
				if !m.IsClosed() {
					_ = m.closeWithError(fmt.Errorf("write frame: %w", err))
				}
				return
			}
			continue
		default:
		}

		select {
		case frame := <-m.ctrlCh:
			if err := m.writeFrame(frame); err != nil {
				if !m.IsClosed() {
					_ = m.closeWithError(fmt.Errorf("write frame: %w", err))
				}
				return
			}
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

// writeFrame writes a frame to the connection. If the frame's payload was
// borrowed from dataBufPool, it is returned to the pool once the
// write completes (success or failure) — the wire encoder never retains a
// reference to Payload past Encode returning, so reuse is always safe here.
func (m *Mux) writeFrame(f *Frame) error {
	m.sendLock.Lock()
	err := m.codec.Encode(m.conn, f)
	m.sendLock.Unlock()

	if f.pooledPayload {
		m.putDataBuf(f.Payload)
	}
	return err
}

// getDataBuf returns a pooled buffer able to hold n bytes, or false if n
// exceeds what the pool provides (the caller should make() its own).
func (m *Mux) getDataBuf(n int) ([]byte, bool) {
	if n > DefaultFramePayloadSize {
		return nil, false
	}
	bufPtr := m.dataBufPool.Get().(*[]byte)
	return (*bufPtr)[:n], true
}

// putDataBuf returns a buffer obtained from getDataBuf back to the pool.
func (m *Mux) putDataBuf(buf []byte) {
	full := buf[:cap(buf)]
	m.dataBufPool.Put(&full)
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

	// Copy the payload because the caller (e.g., io.CopyBuffer) may
	// reuse the underlying buffer before the sendLoop writes the frame.
	// The copy target comes from dataBufPool when possible,
	// turning what was a make+copy on every Stream.Write call into a
	// pool-reuse + copy; writeFrame returns the buffer once sent.
	payload, pooled := m.getDataBuf(len(data))
	if !pooled {
		payload = make([]byte, len(data))
	}
	copy(payload, data)

	frame := NewDataFrame(streamID, payload)
	frame.pooledPayload = pooled
	select {
	case m.sendCh <- frame:
		return nil
	case <-m.closeCh:
		if pooled {
			m.putDataBuf(payload)
		}
		return m.getCloseErr()
	}
}

// sendWindowUpdate sends a window update frame. Routed through ctrlCh (see
// sendLoop) so it's never stuck behind a backlog of bulk DATA frames —
// this is what actually unblocks the peer's Stream.WriteContext, so a
// delay here directly delays the peer's throughput.
func (m *Mux) sendWindowUpdate(streamID uint32, increment uint32) error {
	if m.IsClosed() {
		return ErrMuxClosed
	}

	frame := NewWindowUpdateFrame(streamID, increment)
	select {
	case m.ctrlCh <- frame:
		return nil
	case <-m.closeCh:
		return m.getCloseErr()
	}
}

// sendClose sends a close frame.
//
// This intentionally goes on sendCh, not ctrlCh: CLOSE marks the end of a
// stream's data, so it must be delivered after every DATA frame already
// queued for that stream. Sending it on the prioritized ctrlCh would let it
// overtake still-buffered DATA frames and the peer would see EOF before all
// bytes arrived.
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
	case m.ctrlCh <- frame:
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
	case m.ctrlCh <- frame:
		return nil
	case <-m.closeCh:
		return m.getCloseErr()
	}
}

// sendPong sends a pong (ping response) frame. This is called
// synchronously from recvLoop's handlePing, so it's routed through ctrlCh
// (small, kept well-drained by sendLoop's priority) rather than sendCh —
// see sendLoop's doc comment for why a shared queue here is a deadlock
// risk: if this blocked, recvLoop would stop draining the socket.
func (m *Mux) sendPong(pingID uint32) error {
	if m.IsClosed() {
		return nil
	}

	frame := NewPongFrame(pingID)
	select {
	case m.ctrlCh <- frame:
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
	case m.ctrlCh <- frame:
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
