package p2p

// UDPStream is a reliable, ordered, bidirectional stream multiplexed over a
// UDPMux connection.  Each stream maintains its own ARQ state (sequence
// numbers, send/receive buffers) independently of sibling streams.
//
// Lifecycle:
//  1. Created by UDPMux.OpenStream() (initiator) or UDPMux.AcceptStream()
//     (responder) after a SYN frame is exchanged.
//  2. Read/Write as io.ReadWriteCloser.
//  3. Close() sends FIN; the peer's read returns io.EOF when the FIN is
//     processed.  Force-closure (RST) is handled by UDPMux internally.

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Default flow-control window: max segments in flight before Write blocks.
const (
	maxSendWindow     = 64
	streamRecvBufSize = 256 // must be >= maxSendWindow to avoid deadlocks
)

// streamPacket represents a sent, unacknowledged data fragment.
type streamPacket struct {
	seq         uint32
	data        []byte // plaintext payload for retransmit
	sentAt      time.Time
	retransmits int
}

// UDPStream is a single logical stream within a UDPMux.
type UDPStream struct {
	id  uint32
	mux *UDPMux

	// ARQ send state.
	sendSeq     uint32
	sendBuf     map[uint32]*streamPacket
	sendBufLock sync.Mutex

	// Flow-control: each ACK releases one credit, allowing the next Write.
	// The channel is pre-filled with maxSendWindow tokens.
	sendCreditCh chan struct{}

	// ARQ receive state.
	recvSeq     uint32
	recvBuf     map[uint32][]byte
	recvBufLock sync.Mutex

	// Ordered delivery channel.
	recvCh chan []byte

	// readBuf holds leftover bytes from the last Read call when the caller's
	// buffer was smaller than the received data segment.
	readBuf []byte

	// Finalization.
	closed    uint32
	closeCh   chan struct{}
	closeOnce sync.Once
}

// newUDPStream creates a stream for the given ID, bound to mux m.
func newUDPStream(id uint32, m *UDPMux) *UDPStream {
	credits := make(chan struct{}, maxSendWindow)
	for range maxSendWindow {
		credits <- struct{}{}
	}
	return &UDPStream{
		id:           id,
		mux:          m,
		sendBuf:      make(map[uint32]*streamPacket),
		sendCreditCh: credits,
		recvBuf:      make(map[uint32][]byte),
		recvCh:       make(chan []byte, streamRecvBufSize),
		closeCh:      make(chan struct{}),
	}
}

// StreamID returns the numeric identifier of this stream.
func (s *UDPStream) StreamID() uint32 { return s.id }

// ---------------------------------------------------------------------------
// io.ReadWriteCloser
// ---------------------------------------------------------------------------

// Write sends data to the peer.  Large payloads are automatically fragmented
// so each UDP datagram stays below config.MaxPacketSize.
// Write blocks if the number of unacknowledged segments reaches maxSendWindow
// (simple sliding-window flow control).
func (s *UDPStream) Write(data []byte) (int, error) {
	if atomic.LoadUint32(&s.closed) == 1 {
		return 0, io.ErrClosedPipe
	}
	if atomic.LoadUint32(&s.mux.closed) == 1 {
		return 0, ErrMuxClosed
	}

	maxPayload := s.mux.config.MaxPacketSize - muxHeaderSize
	if maxPayload <= 0 {
		maxPayload = 1391 // 1400 - 9
	}
	if s.mux.cipher != nil {
		maxPayload -= s.mux.cipher.Overhead()
	}
	if maxPayload <= 0 {
		return 0, fmt.Errorf("p2p stream: max packet size too small for cipher overhead")
	}

	written := 0
	for len(data) > 0 {
		// Acquire a send credit (blocks when window is full).
		select {
		case <-s.sendCreditCh:
		case <-s.closeCh:
			return written, io.ErrClosedPipe
		case <-s.mux.closeCh:
			return written, ErrMuxClosed
		}

		chunkSize := len(data)
		if chunkSize > maxPayload {
			chunkSize = maxPayload
		}
		chunk := data[:chunkSize]
		data = data[chunkSize:]

		seq := atomic.AddUint32(&s.sendSeq, 1)

		if err := s.mux.sendPacket(s.id, muxTypeData, seq, chunk); err != nil {
			// Return credit so the window doesn't stall permanently.
			select {
			case s.sendCreditCh <- struct{}{}:
			default:
			}
			return written, fmt.Errorf("p2p stream write: %w", err)
		}

		// Record in send buffer (store plaintext; retransmit will re-encrypt).
		payload := make([]byte, len(chunk))
		copy(payload, chunk)

		s.sendBufLock.Lock()
		s.sendBuf[seq] = &streamPacket{
			seq:    seq,
			data:   payload,
			sentAt: time.Now(),
		}
		s.sendBufLock.Unlock()

		written += chunkSize
	}
	return written, nil
}

// Read blocks until data arrives from the peer.
// It honors the io.Reader contract: if the caller's buffer is smaller than
// one incoming segment, the remainder is buffered and returned on the next call.
func (s *UDPStream) Read(buf []byte) (int, error) {
	// Return any leftover bytes from a previous partial read first.
	if len(s.readBuf) > 0 {
		n := copy(buf, s.readBuf)
		s.readBuf = s.readBuf[n:]
		if len(s.readBuf) == 0 {
			s.readBuf = nil
		}
		return n, nil
	}

	deliver := func(data []byte) int {
		n := copy(buf, data)
		if n < len(data) {
			// Buffer the remainder for the next Read call.
			remainder := make([]byte, len(data)-n)
			copy(remainder, data[n:])
			s.readBuf = remainder
		}
		return n
	}

	select {
	case data, ok := <-s.recvCh:
		if !ok {
			return 0, io.EOF
		}
		if len(data) == 0 {
			// Deadline sentinel — return without data so caller retries.
			return 0, nil
		}
		return deliver(data), nil
	case <-s.closeCh:
		// Drain any remaining buffered data before signaling EOF.
		select {
		case data := <-s.recvCh:
			if len(data) == 0 {
				return 0, io.EOF
			}
			return deliver(data), nil
		default:
			return 0, io.EOF
		}
	case <-s.mux.closeCh:
		return 0, ErrMuxClosed
	}
}

// Close sends a FIN to the peer and marks this stream as closed.
func (s *UDPStream) Close() error {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.closeCh)
		// Send FIN — best effort.
		_ = s.mux.sendPacket(s.id, muxTypeFin, 0, nil)
		s.mux.removeStream(s.id)
		log.Debug().Uint32("stream_id", s.id).Msg("P2P stream: closed (FIN sent)")
	})
	return nil
}

// forceClose closes the stream without sending FIN (used when RST is received
// or mux is closing).
func (s *UDPStream) forceClose() {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return
	}
	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.drainCredits()
		log.Debug().Uint32("stream_id", s.id).Msg("P2P stream: force closed (RST)")
	})
}

// drainCredits releases all remaining send credits so that any blocked
// Write() goroutine can unblock and observe the closeCh.
// Called after forceClose or Close to avoid goroutine leaks.
func (s *UDPStream) drainCredits() {
	for range maxSendWindow {
		select {
		case s.sendCreditCh <- struct{}{}:
		default:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// ARQ handlers — called by UDPMux.dispatch()
// ---------------------------------------------------------------------------

// handleData processes an incoming DATA frame.
func (s *UDPStream) handleData(seq uint32, payload []byte) {
	if atomic.LoadUint32(&s.closed) == 1 {
		return
	}

	// Send ACK immediately.
	_ = s.mux.sendPacket(s.id, muxTypeAck, seq, nil)

	s.recvBufLock.Lock()
	defer s.recvBufLock.Unlock()

	expected := atomic.LoadUint32(&s.recvSeq) + 1

	if seq == expected {
		s.deliverLocked(seq, payload)

		// Deliver any buffered out-of-order segments.
		for {
			next := atomic.LoadUint32(&s.recvSeq) + 1
			if buf, ok := s.recvBuf[next]; ok {
				s.deliverLocked(next, buf)
				delete(s.recvBuf, next)
			} else {
				break
			}
		}
	} else if seq > expected {
		// Out-of-order: buffer.
		if _, exists := s.recvBuf[seq]; !exists {
			copied := make([]byte, len(payload))
			copy(copied, payload)
			s.recvBuf[seq] = copied
		}
	}
	// seq < expected: duplicate, already ACKed — ignore.
}

// deliverLocked pushes decrypted data to recvCh and advances recvSeq.
// Must be called with recvBufLock held.
func (s *UDPStream) deliverLocked(seq uint32, data []byte) {
	copied := make([]byte, len(data))
	copy(copied, data)
	select {
	case s.recvCh <- copied:
	default:
		log.Warn().Uint32("stream_id", s.id).Msg("P2P stream: recv buffer full, dropping packet")
	}
	atomic.StoreUint32(&s.recvSeq, seq)
}

// handleAck removes the acknowledged segment from the send buffer and
// releases a flow-control credit to unblock a waiting Write.
func (s *UDPStream) handleAck(seq uint32) {
	s.sendBufLock.Lock()
	_, existed := s.sendBuf[seq]
	delete(s.sendBuf, seq)
	s.sendBufLock.Unlock()

	if existed {
		// Release one send credit so the window advances.
		select {
		case s.sendCreditCh <- struct{}{}:
		default:
			// Channel full — window already has maximum credits; ignore.
		}
	}
}

// handleFin processes a FIN from the peer: signals EOF on the read side.
func (s *UDPStream) handleFin() {
	if atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		s.closeOnce.Do(func() {
			close(s.closeCh)
		})
	}
}

// ---------------------------------------------------------------------------
// Retransmission — called by UDPMux.retransmitLoop()
// ---------------------------------------------------------------------------

// retransmit resends unacknowledged packets that have exceeded the timeout.
// If a packet exceeds maxRetransmits, the stream is force-closed (connection lost).
func (s *UDPStream) retransmit(timeout time.Duration, maxRetransmits int) {
	if atomic.LoadUint32(&s.closed) == 1 {
		return
	}

	s.sendBufLock.Lock()
	defer s.sendBufLock.Unlock()

	now := time.Now()
	for seq, pkt := range s.sendBuf {
		if now.Sub(pkt.sentAt) < timeout {
			continue
		}
		if pkt.retransmits >= maxRetransmits {
			log.Warn().Uint32("stream_id", s.id).Uint32("seq", seq).
				Msg("P2P stream: max retransmits reached, closing stream")
			delete(s.sendBuf, seq)
			go s.forceClose()
			continue
		}
		pkt.retransmits++
		pkt.sentAt = now
		// Re-send by re-calling sendPacket with the stored plaintext.
		if err := s.mux.sendPacket(s.id, muxTypeData, seq, pkt.data); err != nil {
			log.Warn().Err(err).Uint32("stream_id", s.id).Uint32("seq", seq).
				Msg("P2P stream: retransmit failed")
		}
	}
}

// Ensure UDPStream satisfies io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*UDPStream)(nil)
