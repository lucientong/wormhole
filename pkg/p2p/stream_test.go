package p2p

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- clampRTO / backoffRTO (pure functions) ---

func TestClampRTO_BoundsToMinMax(t *testing.T) {
	assert.Equal(t, minRTO, clampRTO(10*time.Millisecond), "below min clamps up")
	assert.Equal(t, maxRTO, clampRTO(10*time.Second), "above max clamps down")
	mid := 500 * time.Millisecond
	assert.Equal(t, mid, clampRTO(mid), "within range passes through")
}

func TestBackoffRTO_DoublesPerRetransmit(t *testing.T) {
	base := 200 * time.Millisecond

	assert.Equal(t, base, backoffRTO(base, 0), "no retransmits: no backoff")
	assert.Equal(t, 2*base, backoffRTO(base, 1))
	assert.Equal(t, 4*base, backoffRTO(base, 2))
	assert.Equal(t, 8*base, backoffRTO(base, 3))
}

func TestBackoffRTO_CapsAtMaxBackoffShift(t *testing.T) {
	base := 200 * time.Millisecond
	atCap := backoffRTO(base, maxBackoffShift)
	beyondCap := backoffRTO(base, maxBackoffShift+10)
	assert.Equal(t, atCap, beyondCap, "retransmit counts beyond the shift cap must not keep growing")
	assert.LessOrEqual(t, atCap, maxBackoffRTO)
}

func TestBackoffRTO_ClampsToMaxBackoffRTO(t *testing.T) {
	// A large base combined with a few doublings should saturate at
	// maxBackoffRTO rather than overflow or exceed the ceiling.
	got := backoffRTO(maxRTO, 4)
	assert.Equal(t, maxBackoffRTO, got)
}

func TestBackoffRTO_NeverBelowMinRTO(t *testing.T) {
	got := backoffRTO(1*time.Millisecond, 0)
	assert.Equal(t, minRTO, got)
}

// --- UDPStream.updateRTO / currentRTO (RFC 6298 estimator) ---

func TestUDPStream_UpdateRTO_FirstSampleSeedsEstimate(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	sample := 100 * time.Millisecond
	s.updateRTO(sample)

	assert.Equal(t, sample, s.srtt)
	assert.Equal(t, sample/2, s.rttvar)
	// RTO = SRTT + K*RTTVAR = 100ms + 4*50ms = 300ms.
	assert.Equal(t, 300*time.Millisecond, s.currentRTO(999*time.Second))
}

func TestUDPStream_UpdateRTO_ConvergesTowardStableRTT(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	stable := 80 * time.Millisecond
	for range 50 {
		s.updateRTO(stable)
	}

	// After many samples at a constant RTT, SRTT should converge close to
	// it and RTTVAR should shrink toward zero, so RTO approaches SRTT.
	assert.InDelta(t, float64(stable), float64(s.srtt), float64(2*time.Millisecond))
	assert.Less(t, s.rttvar, 5*time.Millisecond)
}

func TestUDPStream_UpdateRTO_HighVarianceWidensRTTVAR(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	samples := []time.Duration{
		50 * time.Millisecond, 500 * time.Millisecond,
		50 * time.Millisecond, 500 * time.Millisecond,
		50 * time.Millisecond, 500 * time.Millisecond,
	}
	for _, sample := range samples {
		s.updateRTO(sample)
	}

	// Wildly oscillating RTTs should produce a large RTTVAR, and thus a
	// much larger RTO than the mean RTT alone would suggest.
	assert.Greater(t, s.rttvar, 50*time.Millisecond)
	assert.Greater(t, s.currentRTO(0), s.srtt)
}

func TestUDPStream_CurrentRTO_FallsBackBeforeFirstSample(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	fallback := 250 * time.Millisecond
	assert.Equal(t, fallback, s.currentRTO(fallback))

	// An out-of-range fallback is still clamped.
	assert.Equal(t, maxRTO, s.currentRTO(30*time.Second))
}

func TestUDPStream_CurrentRTO_UsesEstimateAfterFirstSample(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})
	s.updateRTO(100 * time.Millisecond)

	// Once a sample has been taken, the fallback argument is ignored.
	assert.NotEqual(t, 9999*time.Second, s.currentRTO(9999*time.Second))
	assert.Equal(t, s.rto, s.currentRTO(9999*time.Second))
}

// --- UDPStream.handleAck feeding the estimator (Karn's algorithm) ---

func TestUDPStream_HandleAck_SamplesRTTOnFirstTransmission(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	sentAt := time.Now().Add(-42 * time.Millisecond)
	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, sentAt: sentAt, retransmits: 0}
	s.sendBufLock.Unlock()

	s.handleAck(1)

	require.True(t, s.hasRTT, "an ACK for a never-retransmitted segment must seed the RTO estimator")
	assert.InDelta(t, float64(42*time.Millisecond), float64(s.srtt), float64(15*time.Millisecond))
}

func TestUDPStream_HandleAck_IgnoresRTTForRetransmittedSegment(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, sentAt: time.Now(), retransmits: 2}
	s.sendBufLock.Unlock()

	s.handleAck(1)

	assert.False(t, s.hasRTT, "Karn's algorithm: ACKs for retransmitted segments must not feed the estimator")
}

func TestUDPStream_HandleAck_UnknownSeqIsNoOp(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	// No panic, no state change, for an ACK that doesn't match any
	// outstanding segment (e.g. a duplicate ACK after removal).
	s.handleAck(999)

	assert.False(t, s.hasRTT)
}

// --- retransmit() end-to-end backoff behavior on the send buffer ---

// newBareMux builds a minimal, unstarted UDPMux (no readLoop/retransmitLoop
// goroutines) backed by a real UDP socket, for tests that want to drive
// UDPStream.retransmit()/sendPacket() directly without the background loops.
func newBareMux(t *testing.T) *UDPMux {
	t.Helper()
	conn, _, _, peerAddr := newUDPPair(t)
	return &UDPMux{
		conn:     conn,
		peerAddr: peerAddr,
		config:   DefaultTransportConfig(),
		streams:  map[uint32]*UDPStream{},
		closeCh:  make(chan struct{}),
	}
}

func TestUDPStream_Retransmit_SkipsSegmentsWithinRTO(t *testing.T) {
	mux := newBareMux(t)
	s := newUDPStream(1, mux)
	mux.streams[1] = s

	// A segment sent "now" shouldn't be due for retransmit yet under any
	// reasonable default RTO.
	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, data: []byte("x"), sentAt: time.Now()}
	s.sendBufLock.Unlock()

	s.retransmit(200*time.Millisecond, 10)

	s.sendBufLock.Lock()
	_, stillPending := s.sendBuf[1]
	pkt := s.sendBuf[1]
	s.sendBufLock.Unlock()

	assert.True(t, stillPending)
	assert.Equal(t, 0, pkt.retransmits, "must not have been retransmitted before its RTO elapsed")
}

func TestUDPStream_Retransmit_ResendsAfterRTOElapses(t *testing.T) {
	mux := newBareMux(t)
	s := newUDPStream(1, mux)
	mux.streams[1] = s

	// currentRTO() clamps any fallback below minRTO up to minRTO, so use a
	// default comfortably above it and an elapsed time well past that.
	defaultTimeout := 150 * time.Millisecond
	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, data: []byte("x"), sentAt: time.Now().Add(-2 * defaultTimeout)}
	s.sendBufLock.Unlock()

	s.retransmit(defaultTimeout, 10)

	s.sendBufLock.Lock()
	pkt, ok := s.sendBuf[1]
	s.sendBufLock.Unlock()

	require.True(t, ok)
	assert.Equal(t, 1, pkt.retransmits)
}

// --- Close() / drainSendBuffer: graceful close must not silently drop
// data that Write() already reported as sent but that isn't acked yet
// (regression coverage for the bug this fix addresses — see
// TestUDPMux_SlowConsumer_NoSilentDataLoss for the end-to-end scenario). ---

func TestUDPStream_Close_WaitsForPendingSendsBeforeFIN(t *testing.T) {
	mux := newBareMux(t)
	s := newUDPStream(1, mux)
	mux.streams[1] = s

	// Simulate a still-in-flight, unacknowledged segment, as if Write()
	// just returned having sent it but before its ACK arrived.
	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, data: []byte("x"), sentAt: time.Now()}
	s.sendBufLock.Unlock()

	closeDone := make(chan struct{})
	go func() {
		_ = s.Close()
		close(closeDone)
	}()

	// New writes must be rejected immediately, even while still draining.
	time.Sleep(20 * time.Millisecond)
	_, err := s.Write([]byte("y"))
	assert.ErrorIs(t, err, io.ErrClosedPipe)

	// closeCh/FIN must not fire yet: the pending segment hasn't been
	// acked, so Close() must still be draining rather than having
	// disabled retransmission of it.
	select {
	case <-s.closeCh:
		t.Fatal("stream closed before its pending send was acknowledged")
	default:
	}
	assert.Equal(t, uint32(0), atomic.LoadUint32(&s.closed))

	// Now simulate the peer's ACK for the pending segment arriving.
	s.handleAck(1)

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete after its pending send was acknowledged")
	}
	assert.Equal(t, uint32(1), atomic.LoadUint32(&s.closed))
}

func TestUDPStream_Close_IsIdempotent(t *testing.T) {
	mux := newBareMux(t)
	s := newUDPStream(1, mux)
	mux.streams[1] = s

	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "a second Close() must be a safe no-op")
}

func TestUDPStream_DrainSendBuffer_ReturnsImmediatelyWhenEmpty(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	start := time.Now()
	s.drainSendBuffer(5 * time.Second)
	assert.Less(t, time.Since(start), 200*time.Millisecond)
}

func TestUDPStream_DrainSendBuffer_TimesOutWithPendingSends(t *testing.T) {
	s := newUDPStream(1, &UDPMux{config: DefaultTransportConfig()})

	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, data: []byte("x"), sentAt: time.Now()}
	s.sendBufLock.Unlock()

	start := time.Now()
	s.drainSendBuffer(50 * time.Millisecond)
	assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)

	// The (still-unacked) segment must be left untouched — draining gives
	// up on *waiting*, it never discards outstanding state itself.
	s.sendBufLock.Lock()
	_, stillPending := s.sendBuf[1]
	s.sendBufLock.Unlock()
	assert.True(t, stillPending)
}

func TestUDPStream_DrainSendBuffer_ReturnsPromptlyWhenForceClosed(t *testing.T) {
	mux := newBareMux(t)
	s := newUDPStream(1, mux)
	mux.streams[1] = s

	s.sendBufLock.Lock()
	s.sendBuf[1] = &streamPacket{seq: 1, data: []byte("x"), sentAt: time.Now()}
	s.sendBufLock.Unlock()

	go func() {
		time.Sleep(30 * time.Millisecond)
		s.forceClose()
	}()

	start := time.Now()
	s.drainSendBuffer(5 * time.Second)
	assert.Less(t, time.Since(start), 1*time.Second,
		"should return promptly once force-closed instead of waiting out the full timeout")
}

func TestUDPStream_Retransmit_GivesUpAfterMaxRetransmits(t *testing.T) {
	mux := newBareMux(t)
	s := newUDPStream(1, mux)
	mux.streams[1] = s

	defaultTimeout := 150 * time.Millisecond
	s.sendBufLock.Lock()
	// Backed off 3 retransmits deep, the effective timeout is base*2^3 —
	// make the elapsed time comfortably exceed even that.
	s.sendBuf[1] = &streamPacket{seq: 1, data: []byte("x"), sentAt: time.Now().Add(-20 * defaultTimeout), retransmits: 3}
	s.sendBufLock.Unlock()

	s.retransmit(defaultTimeout, 3)

	// The stream force-closes asynchronously; wait for it rather than
	// asserting on the (now possibly-cleared) sendBuf directly.
	select {
	case <-s.closeCh:
	case <-time.After(2 * time.Second):
		t.Fatal("stream should have force-closed after exceeding maxRetransmits")
	}
}
