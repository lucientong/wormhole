package p2p

import "time"

// TransportConfig holds configuration shared by the UDP transport layer
// (UDPMux/UDPStream): packet sizing, retransmission bounds, and buffering.
type TransportConfig struct {
	// MaxPacketSize is the maximum UDP packet size.
	MaxPacketSize int
	// RetransmitTimeout is the fallback retransmit timeout used before a
	// stream has taken its first RTT sample; once samples are available,
	// UDPStream's RFC 6298 estimator (see stream.go) takes over per-stream.
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
