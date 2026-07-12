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

	// recvDeliverTimeout bounds how long deliverLocked blocks trying to
	// push a segment into recvCh when the buffer is full. Kept short
	// because it runs on the mux's single readLoop goroutine, which is
	// shared by every other stream on the same connection.
	recvDeliverTimeout = 200 * time.Millisecond

	// maxConsecutiveDeliverFailures is the number of consecutive delivery
	// timeouts after which the stream is reset (RST) instead of retrying
	// forever against a consumer that has stopped draining Read().
	maxConsecutiveDeliverFailures = 25 // ~5s at 200ms each
)

// Adaptive retransmission: RFC 6298-style SRTT/RTTVAR/RTO estimation.
// alpha/beta match the RFC's recommended gains; the RTO bounds are tuned
// down from RFC 6298's 1s floor because P2P paths here are typically a
// single hole-punched hop (tens to low hundreds of ms), not a general
// Internet path — a 1s minimum would make loss recovery unacceptably slow.
const (
	rtoAlpha = 0.125 // SRTT gain
	rtoBeta  = 0.25  // RTTVAR gain
	rtoK     = 4     // RTO = SRTT + K*RTTVAR

	minRTO = 100 * time.Millisecond
	maxRTO = 3 * time.Second // ceiling for the SRTT-derived base estimate

	// maxBackoffRTO bounds the *per-segment* exponential backoff applied on
	// top of the base RTO (see backoffRTO) — deliberately higher than
	// maxRTO so repeated losses of the same segment progressively slow
	// down without the backoff being clamped back to a no-op by maxRTO.
	maxBackoffRTO = 10 * time.Second

	// maxBackoffShift caps the exponential backoff at 2^5 = 32x the base
	// RTO, both to avoid absurd wait times and to avoid overflowing
	// time.Duration for pathological retransmit counts.
	maxBackoffShift = 5
)

const (
	// closeDrainTimeout bounds how long a graceful Close() waits for
	// already-sent-but-unacknowledged segments to be acked before giving
	// up and closing anyway. Without this, Close() called right after
	// Write() returns could send FIN and disable further retransmission
	// (see the s.closed guard in retransmit()) while data sent in the
	// final flow-control window is still legitimately in flight —
	// silently truncating the stream even though Write() reported success
	// for every byte.
	closeDrainTimeout = 5 * time.Second

	// drainPollInterval is how often drainSendBuffer polls the send
	// buffer while waiting for it to empty.
	drainPollInterval = 20 * time.Millisecond
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

	// Adaptive retransmission: RFC 6298-style RTO estimator, fed by
	// RTT samples from handleAck (Karn's algorithm: only from segments that
	// were never retransmitted, since a retransmitted segment's ACK is
	// ambiguous about which transmission it's acknowledging).
	rtoMu  sync.Mutex
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration
	hasRTT bool

	// ARQ receive state.
	recvSeq                    uint32
	recvBuf                    map[uint32][]byte
	recvBufLock                sync.Mutex
	consecutiveDeliverFailures uint32 // count of consecutive deliverLocked timeouts, see handleData

	// Ordered delivery channel.
	recvCh chan []byte

	// readBuf holds leftover bytes from the last Read call when the caller's
	// buffer was smaller than the received data segment.
	readBuf []byte

	// Finalization. closing is set as soon as Close() is called (blocking
	// further Writes immediately); closed is only set once any pending
	// sends have drained (or closeDrainTimeout elapses) — see Close() and
	// drainSendBuffer. Keeping these separate lets retransmit() (gated on
	// closed) keep retrying not-yet-acked segments during the drain.
	closing   uint32
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
	// closing is set immediately by Close() (before the drain that keeps
	// retransmit() alive for already-sent data — see Close()); closed is
	// set by forceClose() for abrupt shutdown. Either one must reject new
	// writes.
	if atomic.LoadUint32(&s.closing) == 1 || atomic.LoadUint32(&s.closed) == 1 {
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

// Close blocks new Writes immediately, then waits (up to
// closeDrainTimeout) for any segments already handed to Write — and thus
// already counted in its returned byte count — to actually be
// acknowledged, before sending FIN and marking the stream closed. Skipping
// the drain would let retransmit()'s closed-guard kill retransmission of
// a still-in-flight tail segment the instant Close() is called, which a
// caller that does `Write(all); Close()` (the common pattern) would have
// no way to know about or guard against — Write() already told them every
// byte succeeded.
func (s *UDPStream) Close() error {
	if !atomic.CompareAndSwapUint32(&s.closing, 0, 1) {
		return nil
	}

	s.drainSendBuffer(closeDrainTimeout)

	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		// Force-closed concurrently (e.g. peer RST) while draining —
		// that path already ran closeOnce, nothing left to do here.
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

// drainSendBuffer blocks until the send buffer is empty (all segments
// handed to Write have been acknowledged), the stream is force-closed
// concurrently, the mux is closed, or timeout elapses — whichever first.
func (s *UDPStream) drainSendBuffer(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		s.sendBufLock.Lock()
		pending := len(s.sendBuf)
		s.sendBufLock.Unlock()
		if pending == 0 {
			return
		}
		if atomic.LoadUint32(&s.closed) == 1 {
			return
		}
		if time.Now().After(deadline) {
			log.Warn().Uint32("stream_id", s.id).Int("pending", pending).
				Msg("P2P stream: graceful close timed out waiting for pending sends to ack")
			return
		}
		select {
		case <-s.mux.closeCh:
			return
		case <-time.After(drainPollInterval):
		}
	}
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
//
// Backpressure: if the local consumer isn't draining Read() fast
// enough, recvCh fills up. Rather than silently dropping the segment
// while still ACKing it (which would desync recvSeq from what was
// actually delivered — permanent, silent data loss with no recovery),
// we withhold the ACK on delivery failure. The peer's ARQ then retransmits
// the segment after its RTO, naturally slowing the sender down (implicit
// window-shrink) until the consumer catches up. If the consumer stays
// stuck long enough, the stream is reset instead of retrying forever.
func (s *UDPStream) handleData(seq uint32, payload []byte) {
	if atomic.LoadUint32(&s.closed) == 1 {
		return
	}

	s.recvBufLock.Lock()

	expected := atomic.LoadUint32(&s.recvSeq) + 1

	if seq == expected {
		if !s.deliverLocked(seq, payload) {
			// Delivery timed out: don't ACK, don't advance recvSeq, don't
			// touch the out-of-order buffer. The sender will retransmit.
			s.recvBufLock.Unlock()
			if atomic.LoadUint32(&s.consecutiveDeliverFailures) >= maxConsecutiveDeliverFailures {
				log.Warn().
					Uint32("stream_id", s.id).
					Msg("P2P stream: consumer stalled too long, resetting stream")
				_ = s.mux.sendPacket(s.id, muxTypeRST, 0, nil)
				s.forceClose()
			}
			return
		}

		// Deliver any buffered out-of-order segments now unblocked.
		for {
			next := atomic.LoadUint32(&s.recvSeq) + 1
			buf, ok := s.recvBuf[next]
			if !ok {
				break
			}
			if !s.deliverLocked(next, buf) {
				// Leave it buffered; will retry on the next in-order DATA.
				break
			}
			delete(s.recvBuf, next)
		}
	} else if seq > expected {
		// Out-of-order: buffer. payload is already a freshly-allocated
		// slice owned by this call (see decryptPayload/dispatch in
		// mux.go — it's never the read loop's reused scratch buffer), so
		// it's safe to retain directly without another copy.
		if _, exists := s.recvBuf[seq]; !exists {
			s.recvBuf[seq] = payload
		}
	}
	// seq < expected: duplicate, already delivered — fall through to ACK
	// below so a peer retransmit (e.g. its own ACK was lost) is confirmed.

	s.recvBufLock.Unlock()
	_ = s.mux.sendPacket(s.id, muxTypeAck, seq, nil)
}

// deliverLocked pushes decrypted data to recvCh and advances recvSeq. It
// blocks for up to recvDeliverTimeout waiting for room in recvCh — this
// runs on the UDPMux's single readLoop goroutine, so the timeout is kept
// short to bound how long other streams sharing this mux are stalled.
// Must be called with recvBufLock held. Returns false on timeout, in
// which case recvSeq is deliberately left unadvanced (see handleData).
//
// data is always either the fresh, independently-allocated payload for a
// just-arrived in-order segment, or a slice previously stored (and thus
// already independently owned — see handleData's out-of-order branch) in
// recvBuf; either way it's never aliased to the read loop's reused scratch
// buffer, so it can be handed to recvCh directly without copying.
// On a failed send (timeout/close), the value is simply left untouched for
// the caller to retry — channel sends only take effect when they succeed.
func (s *UDPStream) deliverLocked(seq uint32, data []byte) bool {
	timer := time.NewTimer(recvDeliverTimeout)
	defer timer.Stop()

	select {
	case s.recvCh <- data:
		atomic.StoreUint32(&s.recvSeq, seq)
		atomic.StoreUint32(&s.consecutiveDeliverFailures, 0)
		return true
	case <-timer.C:
		n := atomic.AddUint32(&s.consecutiveDeliverFailures, 1)
		log.Warn().
			Uint32("stream_id", s.id).
			Uint32("seq", seq).
			Uint32("consecutive_failures", n).
			Msg("P2P stream: recv buffer full, withholding ACK for backpressure")
		return false
	case <-s.closeCh:
		return false
	}
}

// handleAck removes the acknowledged segment from the send buffer, feeds an
// RTT sample into the adaptive RTO estimator, and, for data segments,
// releases a flow-control credit to unblock a waiting Write. seq 0 is
// reserved for the SYN handshake pseudo-segment (see registerPendingSYN) —
// acknowledging it only clears the pending SYN retry state and does not
// carry a flow-control credit (but its RTT still seeds the estimator).
func (s *UDPStream) handleAck(seq uint32) {
	s.sendBufLock.Lock()
	pkt, existed := s.sendBuf[seq]
	delete(s.sendBuf, seq)
	s.sendBufLock.Unlock()

	if !existed {
		return
	}

	// Karn's algorithm: only sample RTT from segments acknowledged on their
	// first transmission — an ACK for a retransmitted segment is ambiguous
	// about which of the (re)transmissions it's actually acknowledging, so
	// using it would poison the estimator with a misleadingly low or high
	// sample.
	if pkt.retransmits == 0 {
		s.updateRTO(time.Since(pkt.sentAt))
	}

	if seq > 0 {
		// Release one send credit so the window advances.
		select {
		case s.sendCreditCh <- struct{}{}:
		default:
			// Channel full — window already has maximum credits; ignore.
		}
	}
}

// updateRTO feeds a fresh RTT sample into the RFC 6298 SRTT/RTTVAR/RTO
// estimator. The first sample seeds SRTT/RTTVAR directly; subsequent
// samples use exponentially-weighted moving averages per the RFC.
func (s *UDPStream) updateRTO(sample time.Duration) {
	s.rtoMu.Lock()
	defer s.rtoMu.Unlock()

	if !s.hasRTT {
		s.srtt = sample
		s.rttvar = sample / 2
		s.hasRTT = true
	} else {
		diff := sample - s.srtt
		if diff < 0 {
			diff = -diff
		}
		s.rttvar += time.Duration(rtoBeta * float64(diff-s.rttvar))
		s.srtt += time.Duration(rtoAlpha * float64(sample-s.srtt))
	}

	s.rto = clampRTO(s.srtt + rtoK*s.rttvar)
}

// currentRTO returns the current base RTO estimate, or fallback (clamped)
// if no RTT sample has been taken yet (e.g. before the first ACK).
func (s *UDPStream) currentRTO(fallback time.Duration) time.Duration {
	s.rtoMu.Lock()
	defer s.rtoMu.Unlock()
	if !s.hasRTT {
		return clampRTO(fallback)
	}
	return s.rto
}

// clampRTO bounds d to [minRTO, maxRTO].
func clampRTO(d time.Duration) time.Duration {
	if d < minRTO {
		return minRTO
	}
	if d > maxRTO {
		return maxRTO
	}
	return d
}

// backoffRTO applies RFC 6298 §5.5-style exponential backoff on top of the
// base RTO for a segment that has already been retransmitted retransmits
// times, so repeated loss of the same segment progressively slows down
// instead of hammering an already-congested or broken path.
func backoffRTO(base time.Duration, retransmits int) time.Duration {
	shift := retransmits
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	d := base << shift
	if d > maxBackoffRTO || d < 0 { // d < 0: defend against shift overflow
		return maxBackoffRTO
	}
	if d < minRTO {
		return minRTO
	}
	return d
}

// registerPendingSYN records the just-sent SYN under seq 0 in the send
// buffer so it's retried by UDPMux.retransmitLoop exactly like a data
// segment, until the peer's SYN-ACK (an ordinary muxTypeAck for seq 0)
// arrives or maxRetransmits is exhausted. Real data segments always use
// seq >= 1 (see Write), so seq 0 can never collide with them.
func (s *UDPStream) registerPendingSYN() {
	s.sendBufLock.Lock()
	s.sendBuf[0] = &streamPacket{seq: 0, sentAt: time.Now()}
	s.sendBufLock.Unlock()
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

// retransmit resends unacknowledged packets that have exceeded their
// adaptive RTO: each segment's effective timeout is the stream's
// current RFC 6298 RTO estimate (falling back to defaultTimeout before the
// first RTT sample), backed off exponentially per how many times that
// specific segment has already been retransmitted. If a packet exceeds
// maxRetransmits, the stream is dead: we notify the peer with an RST (best
// effort) and force-close locally. Without the RST, the peer would never
// learn the sender gave up and could block in Read() indefinitely waiting
// for data that will never arrive (previously observed as flaky timeouts
// in TestStress_PacketLoss30Pct).
func (s *UDPStream) retransmit(defaultTimeout time.Duration, maxRetransmits int) {
	if atomic.LoadUint32(&s.closed) == 1 {
		return
	}

	baseRTO := s.currentRTO(defaultTimeout)

	s.sendBufLock.Lock()
	defer s.sendBufLock.Unlock()

	now := time.Now()
	for seq, pkt := range s.sendBuf {
		if now.Sub(pkt.sentAt) < backoffRTO(baseRTO, pkt.retransmits) {
			continue
		}
		if pkt.retransmits >= maxRetransmits {
			log.Warn().Uint32("stream_id", s.id).Uint32("seq", seq).
				Msg("P2P stream: max retransmits reached, closing stream")
			s.sendBuf = make(map[uint32]*streamPacket)
			if err := s.mux.sendPacket(s.id, muxTypeRST, 0, nil); err != nil {
				log.Warn().Err(err).Uint32("stream_id", s.id).
					Msg("P2P stream: failed to notify peer of RST after max retransmits")
			}
			go s.forceClose()
			return
		}
		pkt.retransmits++
		pkt.sentAt = now
		if seq == 0 {
			// Pending SYN handshake (see registerPendingSYN) — resend the
			// SYN itself, not a data segment.
			if err := s.mux.sendPacket(s.id, muxTypeSYN, 0, nil); err != nil {
				log.Warn().Err(err).Uint32("stream_id", s.id).
					Msg("P2P stream: SYN retransmit failed")
			}
			continue
		}
		// Re-send by re-calling sendPacket with the stored plaintext.
		if err := s.mux.sendPacket(s.id, muxTypeData, seq, pkt.data); err != nil {
			log.Warn().Err(err).Uint32("stream_id", s.id).Uint32("seq", seq).
				Msg("P2P stream: retransmit failed")
		}
	}
}

// Ensure UDPStream satisfies io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*UDPStream)(nil)
