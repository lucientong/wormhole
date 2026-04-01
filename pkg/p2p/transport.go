package p2p

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Transport provides a reliable stream-like interface over UDP.
// It implements a simple ARQ (Automatic Repeat reQuest) protocol
// for data reliability over the unreliable UDP connection.
type Transport struct {
	conn     net.PacketConn
	peerAddr *net.UDPAddr

	// Sequence numbers.
	sendSeq uint32
	recvSeq uint32

	// Send buffer for unacknowledged packets.
	sendBuf     map[uint32]*packet
	sendBufLock sync.Mutex

	// Receive buffer for out-of-order packets.
	recvBuf     map[uint32][]byte
	recvBufLock sync.Mutex

	// Ordered receive channel.
	recvCh chan []byte

	// Configuration.
	config TransportConfig

	// State.
	closed  uint32
	closeCh chan struct{}
	closeWg sync.WaitGroup
}

// TransportConfig holds configuration for the UDP transport.
type TransportConfig struct {
	// MaxPacketSize is the maximum UDP packet size.
	MaxPacketSize int
	// RetransmitTimeout is the timeout before retransmitting a packet.
	RetransmitTimeout time.Duration
	// MaxRetransmits is the maximum number of retransmissions before giving up.
	MaxRetransmits int
	// AckTimeout is the timeout for waiting for an ACK.
	AckTimeout time.Duration
	// RecvBufferSize is the size of the receive channel buffer.
	RecvBufferSize int
}

// DefaultTransportConfig returns sensible defaults.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxPacketSize:     1400, // Safe for most MTUs.
		RetransmitTimeout: 200 * time.Millisecond,
		MaxRetransmits:    10,
		AckTimeout:        5 * time.Second,
		RecvBufferSize:    256,
	}
}

// packet represents a sent packet awaiting acknowledgment.
type packet struct {
	seq         uint32
	data        []byte
	sentAt      time.Time
	retransmits int
}

// Packet types.
const (
	pktTypeData = 0x01
	pktTypeAck  = 0x02
	pktTypeFin  = 0x03
)

// Header size: type (1) + seq (4) = 5 bytes.
const headerSize = 5

// NewTransport creates a new UDP transport.
func NewTransport(conn net.PacketConn, peerAddr *net.UDPAddr, config TransportConfig) *Transport {
	t := &Transport{
		conn:     conn,
		peerAddr: peerAddr,
		config:   config,
		sendBuf:  make(map[uint32]*packet),
		recvBuf:  make(map[uint32][]byte),
		recvCh:   make(chan []byte, config.RecvBufferSize),
		closeCh:  make(chan struct{}),
	}

	t.closeWg.Add(2)
	go t.readLoop()
	go t.retransmitLoop()

	return t
}

// Write sends data to the peer with reliability.
func (t *Transport) Write(data []byte) (int, error) {
	if atomic.LoadUint32(&t.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	// Split data into packets if needed.
	maxPayload := t.config.MaxPacketSize - headerSize
	totalWritten := 0

	for len(data) > 0 {
		chunkSize := len(data)
		if chunkSize > maxPayload {
			chunkSize = maxPayload
		}

		chunk := data[:chunkSize]
		data = data[chunkSize:]

		seq := atomic.AddUint32(&t.sendSeq, 1)
		pkt := t.buildPacket(pktTypeData, seq, chunk)

		// Store in send buffer for potential retransmission.
		t.sendBufLock.Lock()
		t.sendBuf[seq] = &packet{
			seq:    seq,
			data:   pkt,
			sentAt: time.Now(),
		}
		t.sendBufLock.Unlock()

		// Send the packet.
		if _, err := t.conn.WriteTo(pkt, t.peerAddr); err != nil {
			return totalWritten, fmt.Errorf("write to peer: %w", err)
		}

		totalWritten += chunkSize
	}

	return totalWritten, nil
}

// Read receives data from the peer.
func (t *Transport) Read(buf []byte) (int, error) {
	select {
	case data, ok := <-t.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(buf, data)
		return n, nil
	case <-t.closeCh:
		return 0, io.EOF
	}
}

// Close closes the transport.
func (t *Transport) Close() error {
	if !atomic.CompareAndSwapUint32(&t.closed, 0, 1) {
		return nil
	}

	// Send FIN packet.
	finPkt := t.buildPacket(pktTypeFin, 0, nil)
	_, _ = t.conn.WriteTo(finPkt, t.peerAddr)

	close(t.closeCh)
	t.closeWg.Wait()
	close(t.recvCh)

	return nil
}

// LocalAddr returns the local address.
func (t *Transport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns the peer address.
func (t *Transport) RemoteAddr() net.Addr {
	return t.peerAddr
}

// buildPacket constructs a packet with header.
func (t *Transport) buildPacket(pktType byte, seq uint32, payload []byte) []byte {
	pkt := make([]byte, headerSize+len(payload))
	pkt[0] = pktType
	binary.BigEndian.PutUint32(pkt[1:5], seq)
	if len(payload) > 0 {
		copy(pkt[5:], payload)
	}
	return pkt
}

// readLoop reads incoming packets.
func (t *Transport) readLoop() {
	defer t.closeWg.Done()

	buf := make([]byte, t.config.MaxPacketSize)

	for {
		select {
		case <-t.closeCh:
			return
		default:
		}

		// Set read deadline to allow checking closeCh periodically.
		if err := t.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return
		}

		n, addr, err := t.conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		// Verify sender.
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || !udpAddr.IP.Equal(t.peerAddr.IP) || udpAddr.Port != t.peerAddr.Port {
			continue
		}

		if n < headerSize {
			continue
		}

		pktType := buf[0]
		seq := binary.BigEndian.Uint32(buf[1:5])
		payload := buf[5:n]

		switch pktType {
		case pktTypeData:
			t.handleDataPacket(seq, payload)
		case pktTypeAck:
			t.handleAckPacket(seq)
		case pktTypeFin:
			t.handleFinPacket()
		}
	}
}

// handleDataPacket processes an incoming data packet.
func (t *Transport) handleDataPacket(seq uint32, payload []byte) {
	// Send ACK immediately.
	ackPkt := t.buildPacket(pktTypeAck, seq, nil)
	_, _ = t.conn.WriteTo(ackPkt, t.peerAddr)

	t.recvBufLock.Lock()
	defer t.recvBufLock.Unlock()

	expectedSeq := atomic.LoadUint32(&t.recvSeq) + 1

	if seq == expectedSeq {
		// In-order packet - deliver immediately.
		data := make([]byte, len(payload))
		copy(data, payload)
		select {
		case t.recvCh <- data:
		default:
			log.Warn().Msg("P2P transport: receive buffer full, dropping packet")
		}
		atomic.StoreUint32(&t.recvSeq, seq)

		// Check if we can deliver buffered out-of-order packets.
		for {
			nextSeq := atomic.LoadUint32(&t.recvSeq) + 1
			if buffered, ok := t.recvBuf[nextSeq]; ok {
				select {
				case t.recvCh <- buffered:
				default:
				}
				delete(t.recvBuf, nextSeq)
				atomic.StoreUint32(&t.recvSeq, nextSeq)
			} else {
				break
			}
		}
	} else if seq > expectedSeq {
		// Out-of-order packet - buffer for later.
		if _, exists := t.recvBuf[seq]; !exists {
			data := make([]byte, len(payload))
			copy(data, payload)
			t.recvBuf[seq] = data
		}
	}
	// seq < expectedSeq means duplicate - already ACKed, ignore.
}

// handleAckPacket processes an incoming ACK packet.
func (t *Transport) handleAckPacket(seq uint32) {
	t.sendBufLock.Lock()
	defer t.sendBufLock.Unlock()

	delete(t.sendBuf, seq)
}

// handleFinPacket processes an incoming FIN packet.
func (t *Transport) handleFinPacket() {
	// Peer is closing - close our side too.
	go func() {
		_ = t.Close()
	}()
}

// retransmitLoop handles packet retransmission.
func (t *Transport) retransmitLoop() {
	defer t.closeWg.Done()

	ticker := time.NewTicker(t.config.RetransmitTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-t.closeCh:
			return
		case <-ticker.C:
			t.checkRetransmits()
		}
	}
}

// checkRetransmits retransmits packets that have timed out.
func (t *Transport) checkRetransmits() {
	t.sendBufLock.Lock()
	defer t.sendBufLock.Unlock()

	now := time.Now()

	for seq, pkt := range t.sendBuf {
		if now.Sub(pkt.sentAt) > t.config.RetransmitTimeout {
			if pkt.retransmits >= t.config.MaxRetransmits {
				// Give up on this packet.
				log.Warn().Uint32("seq", seq).Msg("P2P transport: max retransmits reached")
				delete(t.sendBuf, seq)
				continue
			}

			// Retransmit.
			pkt.retransmits++
			pkt.sentAt = now
			_, _ = t.conn.WriteTo(pkt.data, t.peerAddr)
		}
	}
}

// Stats returns transport statistics.
func (t *Transport) Stats() TransportStats {
	t.sendBufLock.Lock()
	pendingAcks := len(t.sendBuf)
	t.sendBufLock.Unlock()

	t.recvBufLock.Lock()
	outOfOrder := len(t.recvBuf)
	t.recvBufLock.Unlock()

	return TransportStats{
		SendSeq:     atomic.LoadUint32(&t.sendSeq),
		RecvSeq:     atomic.LoadUint32(&t.recvSeq),
		PendingAcks: pendingAcks,
		OutOfOrder:  outOfOrder,
	}
}

// TransportStats contains transport statistics.
type TransportStats struct {
	SendSeq     uint32
	RecvSeq     uint32
	PendingAcks int
	OutOfOrder  int
}
