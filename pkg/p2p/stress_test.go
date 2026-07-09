package p2p

import (
	"bytes"
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lossyConn wraps a net.PacketConn and randomly drops outgoing packets to
// simulate an unreliable network for stress testing.
type lossyConn struct {
	net.PacketConn
	dropRate float64 // 0.0 = no drops, 1.0 = drop everything
}

func (c *lossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if rand.Float64() < c.dropRate { // #nosec G404 -- non-security random for test simulation
		return len(p), nil // silently drop
	}
	return c.PacketConn.WriteTo(p, addr)
}

// newLossyMuxPair creates a mux pair where both sides drop packets at the
// given rate.
func newLossyMuxPair(t *testing.T, dropRate float64) (*UDPMux, *UDPMux) {
	t.Helper()
	conn1, conn2, peer1, peer2 := newUDPPair(t)
	cfg := DefaultTransportConfig()
	cfg.RetransmitTimeout = 30 * time.Millisecond
	cfg.MaxRetransmits = 50

	lossy1 := &lossyConn{PacketConn: conn1, dropRate: dropRate}
	lossy2 := &lossyConn{PacketConn: conn2, dropRate: dropRate}

	initiator := NewUDPMux(lossy1, peer1, cfg, nil, true)
	acceptor := NewUDPMux(lossy2, peer2, cfg, nil, false)
	t.Cleanup(func() {
		_ = initiator.Close()
		_ = acceptor.Close()
	})
	return initiator, acceptor
}

// --- Stress tests ---

// TestStress_HighConcurrency opens many streams simultaneously and verifies
// that all bytes are transmitted correctly (one-directional: initiator→acceptor).
// Streams are accepted in arbitrary order so we verify byte count + content hash
// rather than per-stream identity.
func TestStress_HighConcurrency(t *testing.T) {
	initiator, acceptor := newMuxPair(t)

	const numStreams = 20
	const msgSize = 512

	// All streams send the same payload so we can verify without stream tracking.
	payload := bytes.Repeat([]byte{0xAB}, msgSize)
	var totalRecv int64
	received := make(chan int, numStreams)

	// Acceptor: accept all streams and read exactly msgSize bytes from each.
	for i := 0; i < numStreams; i++ {
		go func() {
			s, err := acceptor.AcceptStream()
			if err != nil {
				received <- 0
				return
			}
			defer s.Close()
			buf := make([]byte, msgSize)
			n, err := io.ReadFull(s, buf)
			if err != nil || !bytes.Equal(buf[:n], payload[:n]) {
				received <- 0
				return
			}
			received <- n
		}()
	}

	// Initiator: open streams and send payload.
	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := initiator.OpenStream()
			if err != nil {
				return
			}
			defer s.Close()
			_, _ = s.Write(payload)
		}()
	}
	wg.Wait()

	for i := 0; i < numStreams; i++ {
		select {
		case n := <-received:
			totalRecv += int64(n)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for stream result %d", i)
		}
	}
	assert.Equal(t, int64(numStreams*msgSize), totalRecv, "total bytes received mismatch")
}

// TestStress_PacketLoss10Pct verifies reliable delivery under 10% packet loss.
func TestStress_PacketLoss10Pct(t *testing.T) {
	initiator, acceptor := newLossyMuxPair(t, 0.10)
	runReliabilityCheck(t, initiator, acceptor, 4*1024)
}

// TestStress_PacketLoss30Pct verifies reliable delivery under 30% packet loss.
// Runs with a reduced payload to keep the test within a reasonable time budget.
func TestStress_PacketLoss30Pct(t *testing.T) {
	initiator, acceptor := newLossyMuxPair(t, 0.30)
	runReliabilityCheck(t, initiator, acceptor, 512)
}

// runReliabilityCheck sends payloadSize bytes across a single stream and
// verifies the data arrives intact, even under packet loss.
// Uses io.ReadFull instead of io.ReadAll to avoid dependence on FIN delivery,
// since ARQ retransmissions stop when the sending stream is closed.
func runReliabilityCheck(t *testing.T, initiator, acceptor *UDPMux, payloadSize int) {
	t.Helper()

	payload := make([]byte, payloadSize)
	_, _ = cryptorand.Read(payload)

	done := make(chan []byte, 1)
	go func() {
		s, err := acceptor.AcceptStream()
		if err != nil {
			done <- nil
			return
		}
		defer s.Close()
		buf := make([]byte, payloadSize)
		if _, err := io.ReadFull(s, buf); err != nil {
			done <- nil
			return
		}
		done <- buf
	}()

	s, err := initiator.OpenStream()
	require.NoError(t, err)
	defer s.Close()

	_, err = s.Write(payload)
	require.NoError(t, err)

	select {
	case got := <-done:
		require.NotNil(t, got, "acceptor failed to receive data")
		require.Equal(t, payload, got, "data mismatch under packet loss")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for data under packet loss")
	}
}

// TestStress_RapidOpenClose rapidly opens and closes streams to check for
// race conditions and resource leaks.
func TestStress_RapidOpenClose(t *testing.T) {
	initiator, acceptor := newMuxPair(t)

	const rounds = 50

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			s, err := acceptor.AcceptStream()
			if err != nil {
				return
			}
			go func(stream *UDPStream) {
				defer stream.Close()
				buf := make([]byte, 64)
				_, _ = stream.Read(buf)
			}(s)
		}
	}()

	for i := 0; i < rounds; i++ {
		s, err := initiator.OpenStream()
		require.NoError(t, err)
		_, err = s.Write([]byte("ping"))
		require.NoError(t, err)
		s.Close()
	}

	wg.Wait()
}

// --- Benchmarks ---

// BenchmarkUDPMux_Throughput measures single-stream throughput over loopback.
func BenchmarkUDPMux_Throughput(b *testing.B) {
	conn1, conn2, peer1, peer2 := newUDPPairBench(b)
	cfg := DefaultTransportConfig()
	cfg.RetransmitTimeout = 20 * time.Millisecond
	initiator := NewUDPMux(conn1, peer1, cfg, nil, true)
	acceptor := NewUDPMux(conn2, peer2, cfg, nil, false)
	defer initiator.Close()
	defer acceptor.Close()

	const chunkSize = 1400 // close to MTU

	ready := make(chan *UDPStream, 1)
	go func() {
		s, _ := acceptor.AcceptStream()
		ready <- s
	}()

	snd, err := initiator.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	rcv := <-ready

	chunk := make([]byte, chunkSize)
	_, _ = cryptorand.Read(chunk)

	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkSize)
		total := 0
		for total < b.N*chunkSize {
			n, err := rcv.Read(buf)
			if err != nil {
				return
			}
			total += n
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, err := snd.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	wg.Wait()
}

// BenchmarkUDPMux_StreamOpen measures the latency to open a new stream.
func BenchmarkUDPMux_StreamOpen(b *testing.B) {
	conn1, conn2, peer1, peer2 := newUDPPairBench(b)
	cfg := DefaultTransportConfig()
	cfg.RetransmitTimeout = 20 * time.Millisecond
	initiator := NewUDPMux(conn1, peer1, cfg, nil, true)
	acceptor := NewUDPMux(conn2, peer2, cfg, nil, false)
	defer initiator.Close()
	defer acceptor.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			s, _ := acceptor.AcceptStream()
			if s != nil {
				s.Close()
			}
		}()
		s, err := initiator.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		s.Close()
	}
}

// BenchmarkUDPMux_MultiStream benchmarks concurrent throughput across multiple
// streams multiplexed over a single connection.
func BenchmarkUDPMux_MultiStream(b *testing.B) {
	for _, numStreams := range []int{1, 4, 8} {
		b.Run(fmt.Sprintf("streams=%d", numStreams), func(b *testing.B) {
			conn1, conn2, peer1, peer2 := newUDPPairBench(b)
			cfg := DefaultTransportConfig()
			cfg.RetransmitTimeout = 20 * time.Millisecond
			initiator := NewUDPMux(conn1, peer1, cfg, nil, true)
			acceptor := NewUDPMux(conn2, peer2, cfg, nil, false)
			defer initiator.Close()
			defer acceptor.Close()

			const chunkSize = 1400
			chunk := make([]byte, chunkSize)

			streams := make([]*UDPStream, numStreams)
			for i := range streams {
				go func() {
					s, _ := acceptor.AcceptStream()
					if s != nil {
						io.Copy(io.Discard, s)
					}
				}()
				s, err := initiator.OpenStream()
				if err != nil {
					b.Fatal(err)
				}
				streams[i] = s
			}

			b.SetBytes(int64(chunkSize * numStreams))
			b.ResetTimer()

			var wg sync.WaitGroup
			for _, s := range streams {
				wg.Add(1)
				go func(stream *UDPStream) {
					defer wg.Done()
					for i := 0; i < b.N; i++ {
						if _, err := stream.Write(chunk); err != nil {
							return
						}
					}
				}(s)
			}
			wg.Wait()
		})
	}
}

// BenchmarkUDPMux_Throughput_Encrypted is the encrypted counterpart to
// BenchmarkUDPMux_Throughput, used to quantify the DP-14 send-path copy
// reduction (SessionCipher.EncryptInto writing straight into the mux
// frame buffer instead of via a standalone ciphertext buffer that then
// gets copied again).
func BenchmarkUDPMux_Throughput_Encrypted(b *testing.B) {
	kpA, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	kpB, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	cipherA, err := DeriveSession(kpA.Private, kpB.Public)
	if err != nil {
		b.Fatal(err)
	}
	cipherB, err := DeriveSession(kpB.Private, kpA.Public)
	if err != nil {
		b.Fatal(err)
	}

	conn1, conn2, peer1, peer2 := newUDPPairBench(b)
	cfg := DefaultTransportConfig()
	cfg.RetransmitTimeout = 20 * time.Millisecond
	initiator := NewUDPMux(conn1, peer1, cfg, cipherA, true)
	acceptor := NewUDPMux(conn2, peer2, cfg, cipherB, false)
	defer initiator.Close()
	defer acceptor.Close()

	const chunkSize = 1400

	ready := make(chan *UDPStream, 1)
	go func() {
		s, _ := acceptor.AcceptStream()
		ready <- s
	}()

	snd, err := initiator.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	rcv := <-ready

	chunk := make([]byte, chunkSize)
	_, _ = cryptorand.Read(chunk)

	b.SetBytes(int64(chunkSize))
	b.ReportAllocs()
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkSize)
		total := 0
		for total < b.N*chunkSize {
			n, readErr := rcv.Read(buf)
			if readErr != nil {
				return
			}
			total += n
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, writeErr := snd.Write(chunk); writeErr != nil {
			b.Fatal(writeErr)
		}
	}
	wg.Wait()
}

// delayedLossyConn wraps a net.PacketConn to simulate a WAN-like link:
// outgoing packets are dropped at dropRate and, if not dropped, delayed by
// delay before actually being written — approximating a fixed one-way
// latency plus random loss. Used by BenchmarkUDPMux_Throughput_SimulatedWAN
// to validate DP-13 (adaptive RTO)/DP-14 (reduced copies) don't regress
// throughput under realistic non-LAN conditions.
type delayedLossyConn struct {
	net.PacketConn
	dropRate float64
	delay    time.Duration
}

func (c *delayedLossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if rand.Float64() < c.dropRate { // #nosec G404 -- non-security random for benchmark simulation
		return len(p), nil
	}
	if c.delay <= 0 {
		return c.PacketConn.WriteTo(p, addr)
	}
	// Delay delivery asynchronously rather than blocking the caller: real
	// network latency delays when a packet *arrives*, not how long the
	// local socket call to send it takes — blocking here would instead
	// serialize every send at delay-per-call and defeat the whole point
	// of the sliding window (each Write would cost a full RTT instead of
	// only the tail segment once the window fills).
	buf := make([]byte, len(p))
	copy(buf, p)
	go func() {
		time.Sleep(c.delay)
		_, _ = c.PacketConn.WriteTo(buf, addr)
	}()
	return len(p), nil
}

// BenchmarkUDPMux_Throughput_SimulatedWAN measures single-stream throughput
// over a simulated ~50ms-RTT, 1%-loss link (25ms one-way delay each way),
// the condition class DP-13's adaptive RTO/backoff targets — as opposed to
// the near-zero-RTT loopback conditions of BenchmarkUDPMux_Throughput.
func BenchmarkUDPMux_Throughput_SimulatedWAN(b *testing.B) {
	conn1, conn2, peer1, peer2 := newUDPPairBench(b)
	cfg := DefaultTransportConfig()

	const oneWayDelay = 25 * time.Millisecond
	const dropRate = 0.01

	wan1 := &delayedLossyConn{PacketConn: conn1, dropRate: dropRate, delay: oneWayDelay}
	wan2 := &delayedLossyConn{PacketConn: conn2, dropRate: dropRate, delay: oneWayDelay}

	initiator := NewUDPMux(wan1, peer1, cfg, nil, true)
	acceptor := NewUDPMux(wan2, peer2, cfg, nil, false)
	defer initiator.Close()
	defer acceptor.Close()

	const chunkSize = 1400

	ready := make(chan *UDPStream, 1)
	go func() {
		s, _ := acceptor.AcceptStream()
		ready <- s
	}()

	snd, err := initiator.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	rcv := <-ready

	chunk := make([]byte, chunkSize)
	_, _ = cryptorand.Read(chunk)

	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkSize)
		total := 0
		for total < b.N*chunkSize {
			n, readErr := rcv.Read(buf)
			if readErr != nil {
				return
			}
			total += n
		}
	}()

	for i := 0; i < b.N; i++ {
		if _, writeErr := snd.Write(chunk); writeErr != nil {
			b.Fatal(writeErr)
		}
	}
	wg.Wait()
}

// BenchmarkMux_SendPacket isolates the allocation cost of a single
// sendPacket call (DP-14: encryption now appends straight into the frame
// buffer via SessionCipher.EncryptInto instead of encrypting into a
// standalone buffer that then gets copied into the frame). No receiver
// reads these packets — this benchmark only measures encode+write cost.
func BenchmarkMux_SendPacket(b *testing.B) {
	conn1, _, _, peer2 := newUDPPairBench(b)

	cfg := DefaultTransportConfig()
	plainMux := NewUDPMux(conn1, peer2, cfg, nil, true)
	defer plainMux.Close()

	kpA, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	kpB, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	sessionCipher, err := DeriveSession(kpA.Private, kpB.Public)
	if err != nil {
		b.Fatal(err)
	}

	conn3, _, _, peer4 := newUDPPairBench(b)
	encMux := NewUDPMux(conn3, peer4, cfg, sessionCipher, true)
	defer encMux.Close()

	const payloadSize = 1200
	payload := make([]byte, payloadSize)
	_, _ = cryptorand.Read(payload)

	b.Run("plain", func(b *testing.B) {
		b.ReportAllocs()
		seq := uint32(1)
		for i := 0; i < b.N; i++ {
			_ = plainMux.sendPacket(1, muxTypeData, seq, payload)
			seq++
		}
	})

	b.Run("encrypted", func(b *testing.B) {
		b.ReportAllocs()
		seq := uint32(1)
		for i := 0; i < b.N; i++ {
			_ = encMux.sendPacket(1, muxTypeData, seq, payload)
			seq++
		}
	})
}

// newUDPPairBench is a testing.B-compatible version of newUDPPair.
func newUDPPairBench(b *testing.B) (net.PacketConn, net.PacketConn, *net.UDPAddr, *net.UDPAddr) {
	b.Helper()
	ln1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ln2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = ln1.Close()
		_ = ln2.Close()
	})
	return ln1, ln2, ln2.LocalAddr().(*net.UDPAddr), ln1.LocalAddr().(*net.UDPAddr)
}
