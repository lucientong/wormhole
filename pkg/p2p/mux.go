package p2p

// UDPMux provides multiple logical streams over a single UDP connection.
//
// Wire frame format (9-byte header):
//
//	[StreamID(4B big-endian)][Type(1B)][Seq(4B big-endian)][Payload...]
//
// Type values:
//
//	muxTypeSYN  = 0x05  — open a new stream
//	muxTypeData = 0x01  — data segment
//	muxTypeAck  = 0x02  — acknowledgement
//	muxTypeFin  = 0x03  — graceful close (half-close)
//	muxTypeRST  = 0x04  — reset / abrupt close
//
// Encryption: if a SessionCipher is configured, the *payload* is encrypted
// (header fields remain plaintext so the read-loop can dispatch by StreamID).
//
// Stream ID allocation: the "isInitiator" side uses odd IDs (1, 3, 5 …),
// the accepting side uses even IDs (2, 4, 6 …).  This prevents collisions
// when both sides open streams simultaneously.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	muxHeaderSize = 9 // StreamID(4) + Type(1) + Seq(4)

	muxTypeSYN  byte = 0x05
	muxTypeData byte = 0x01
	muxTypeAck  byte = 0x02
	muxTypeFin  byte = 0x03
	muxTypeRST  byte = 0x04

	// defaultAcceptBacklog is the number of incoming streams that can be
	// queued before AcceptStream returns them.
	defaultAcceptBacklog = 32
)

// ErrMuxClosed is returned when operations are attempted on a closed mux.
var ErrMuxClosed = errors.New("p2p: mux closed")

// UDPMux multiplexes multiple bidirectional streams over one UDP connection.
type UDPMux struct {
	conn     net.PacketConn
	peerAddr *net.UDPAddr
	cipher   *SessionCipher
	config   TransportConfig

	// Live streams, keyed by StreamID.
	streams     map[uint32]*UDPStream
	streamsLock sync.RWMutex

	// Incoming streams waiting to be accepted.
	acceptCh chan *UDPStream

	// Next stream ID to allocate.  Odd for initiator, even for acceptor.
	nextStreamID uint32
	idStep       uint32 // always 2

	// State.
	closed  uint32
	closeCh chan struct{}
	closeWg sync.WaitGroup
}

// NewUDPMux creates a multiplexer over conn/peerAddr.
// isInitiator must be true on exactly one side of a P2P connection to ensure
// stream-ID uniqueness; the other side must pass false.
func NewUDPMux(conn net.PacketConn, peerAddr *net.UDPAddr, config TransportConfig, cipher *SessionCipher, isInitiator bool) *UDPMux {
	var firstID uint32
	if isInitiator {
		firstID = 1 // odd IDs: 1, 3, 5 …
	} else {
		firstID = 2 // even IDs: 2, 4, 6 …
	}
	// Randomise the starting offset so repeated sessions are less predictable.
	offset := rand.Uint32() & 0xFFFE // even number in [0, 65534]
	firstID += uint32(offset) * 2

	m := &UDPMux{
		conn:         conn,
		peerAddr:     peerAddr,
		cipher:       cipher,
		config:       config,
		streams:      make(map[uint32]*UDPStream),
		acceptCh:     make(chan *UDPStream, defaultAcceptBacklog),
		nextStreamID: firstID,
		idStep:       2,
		closeCh:      make(chan struct{}),
	}

	m.closeWg.Add(2)
	go m.readLoop()
	go m.retransmitLoop()

	return m
}

// OpenStream creates a new outbound stream and performs the SYN handshake.
func (m *UDPMux) OpenStream() (*UDPStream, error) {
	if atomic.LoadUint32(&m.closed) == 1 {
		return nil, ErrMuxClosed
	}

	// Allocate a unique stream ID.
	streamID := atomic.AddUint32(&m.nextStreamID, m.idStep) - m.idStep

	s := newUDPStream(streamID, m)

	m.streamsLock.Lock()
	m.streams[streamID] = s
	m.streamsLock.Unlock()

	// Send SYN.
	if err := m.sendPacket(streamID, muxTypeSYN, 0, nil); err != nil {
		m.removeStream(streamID)
		return nil, fmt.Errorf("send SYN for stream %d: %w", streamID, err)
	}

	log.Debug().Uint32("stream_id", streamID).Msg("P2P mux: opened stream")
	return s, nil
}

// AcceptStream blocks until an incoming stream is available.
func (m *UDPMux) AcceptStream() (*UDPStream, error) {
	select {
	case s := <-m.acceptCh:
		return s, nil
	case <-m.closeCh:
		return nil, ErrMuxClosed
	}
}

// Close closes the mux and all its streams.
func (m *UDPMux) Close() error {
	if !atomic.CompareAndSwapUint32(&m.closed, 0, 1) {
		return nil
	}

	// RST all open streams.
	m.streamsLock.Lock()
	for id := range m.streams {
		_ = m.sendPacket(id, muxTypeRST, 0, nil)
	}
	m.streamsLock.Unlock()

	close(m.closeCh)
	m.closeWg.Wait()

	// Close all stream channels.
	m.streamsLock.Lock()
	for _, s := range m.streams {
		s.forceClose()
	}
	m.streams = make(map[uint32]*UDPStream)
	m.streamsLock.Unlock()

	return nil
}

// IsClosed returns whether the mux has been closed.
func (m *UDPMux) IsClosed() bool {
	return atomic.LoadUint32(&m.closed) == 1
}

// LocalAddr returns the local UDP address.
func (m *UDPMux) LocalAddr() net.Addr { return m.conn.LocalAddr() }

// RemoteAddr returns the peer UDP address.
func (m *UDPMux) RemoteAddr() net.Addr { return m.peerAddr }

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// sendPacket constructs and sends a mux frame.
// payload is encrypted if a cipher is configured.
func (m *UDPMux) sendPacket(streamID uint32, pktType byte, seq uint32, payload []byte) error {
	// Encrypt payload if cipher configured.
	encPayload := payload
	if m.cipher != nil && len(payload) > 0 {
		var err error
		encPayload, err = m.cipher.Encrypt(payload)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
	}

	// Build frame: [StreamID(4)][Type(1)][Seq(4)][Payload...]
	frame := make([]byte, muxHeaderSize+len(encPayload))
	binary.BigEndian.PutUint32(frame[0:4], streamID)
	frame[4] = pktType
	binary.BigEndian.PutUint32(frame[5:9], seq)
	if len(encPayload) > 0 {
		copy(frame[9:], encPayload)
	}

	_, err := m.conn.WriteTo(frame, m.peerAddr)
	return err
}

// removeStream removes a stream from the active map.
func (m *UDPMux) removeStream(id uint32) {
	m.streamsLock.Lock()
	delete(m.streams, id)
	m.streamsLock.Unlock()
}

// readLoop reads UDP datagrams and dispatches them to the correct stream.
func (m *UDPMux) readLoop() {
	defer m.closeWg.Done()

	maxPkt := m.config.MaxPacketSize
	if maxPkt == 0 {
		maxPkt = 1500
	}
	// Account for possible encryption overhead.
	bufSize := maxPkt + 64
	buf := make([]byte, bufSize)

	for {
		select {
		case <-m.closeCh:
			return
		default:
		}

		// Set a short read deadline so we can check closeCh periodically.
		if err := m.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return
		}

		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if atomic.LoadUint32(&m.closed) == 1 {
				return
			}
			log.Debug().Err(err).Msg("P2P mux: read error")
			continue
		}

		// Verify sender.
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || !udpAddr.IP.Equal(m.peerAddr.IP) || udpAddr.Port != m.peerAddr.Port {
			continue
		}

		if n < muxHeaderSize {
			continue // too short
		}

		streamID := binary.BigEndian.Uint32(buf[0:4])
		pktType := buf[4]
		seq := binary.BigEndian.Uint32(buf[5:9])
		rawPayload := buf[9:n]

		// Decrypt payload.
		var payload []byte
		if m.cipher != nil && len(rawPayload) > 0 {
			decrypted, decErr := m.cipher.Decrypt(rawPayload)
			if decErr != nil {
				log.Warn().Err(decErr).Uint32("stream_id", streamID).Msg("P2P mux: decrypt failed, dropping")
				continue
			}
			payload = decrypted
		} else {
			// Copy to avoid buf overwrite on next iteration.
			payload = make([]byte, len(rawPayload))
			copy(payload, rawPayload)
		}

		m.dispatch(streamID, pktType, seq, payload)
	}
}

// dispatch routes a decoded frame to the appropriate stream.
func (m *UDPMux) dispatch(streamID uint32, pktType byte, seq uint32, payload []byte) {
	if pktType == muxTypeSYN {
		// Peer is opening a new stream.
		m.streamsLock.Lock()
		if _, exists := m.streams[streamID]; exists {
			m.streamsLock.Unlock()
			return // duplicate SYN, ignore
		}
		s := newUDPStream(streamID, m)
		m.streams[streamID] = s
		m.streamsLock.Unlock()

		log.Debug().Uint32("stream_id", streamID).Msg("P2P mux: accepted incoming stream")

		select {
		case m.acceptCh <- s:
		default:
			// backlog full – close stream immediately.
			log.Warn().Uint32("stream_id", streamID).Msg("P2P mux: accept backlog full, rejecting stream")
			_ = m.sendPacket(streamID, muxTypeRST, 0, nil)
			m.removeStream(streamID)
		}
		return
	}

	m.streamsLock.RLock()
	s, ok := m.streams[streamID]
	m.streamsLock.RUnlock()

	if !ok {
		return // unknown stream, ignore
	}

	switch pktType {
	case muxTypeData:
		s.handleData(seq, payload)
	case muxTypeAck:
		s.handleAck(seq)
	case muxTypeFin:
		s.handleFin()
		m.removeStream(streamID)
	case muxTypeRST:
		s.forceClose()
		m.removeStream(streamID)
	}
}

// retransmitLoop periodically retransmits unacknowledged packets for all streams.
func (m *UDPMux) retransmitLoop() {
	defer m.closeWg.Done()

	interval := m.config.RetransmitTimeout / 2
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.closeCh:
			return
		case <-ticker.C:
			m.streamsLock.RLock()
			streams := make([]*UDPStream, 0, len(m.streams))
			for _, s := range m.streams {
				streams = append(streams, s)
			}
			m.streamsLock.RUnlock()

			for _, s := range streams {
				s.retransmit(m.config.RetransmitTimeout, m.config.MaxRetransmits)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// io.ReadWriteCloser adapter — wraps the mux so callers can use it directly
// for simple single-stream scenarios (e.g. testing).
// ---------------------------------------------------------------------------

// MuxStream is a convenience wrapper returned by NewUDPMux that also implements
// the stream-level interface when only one stream is needed.  Not used in the
// multi-stream path — use OpenStream/AcceptStream instead.

// Ensure UDPMux satisfies io.Closer.
var _ io.Closer = (*UDPMux)(nil)
