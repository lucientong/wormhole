package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Frame protocol constants
const (
	// FrameVersion is the current protocol version.
	FrameVersion uint8 = 1

	// FrameHeaderSize is the size of the frame header in bytes.
	// [Version:1][Type:1][StreamID:4][Length:4] = 10 bytes
	FrameHeaderSize = 10

	// MaxFramePayloadSize is the maximum payload size (16MB).
	MaxFramePayloadSize = 16 * 1024 * 1024

	// DefaultFramePayloadSize is the default payload size (32KB).
	DefaultFramePayloadSize = 32 * 1024
)

// FrameType represents the type of a frame.
type FrameType uint8

// Frame types
const (
	// FrameData carries stream data.
	FrameData FrameType = 0x01

	// FrameWindowUpdate updates the flow control window.
	FrameWindowUpdate FrameType = 0x02

	// FramePing is used for keep-alive.
	FramePing FrameType = 0x03

	// FramePong is the response to a ping frame.
	FramePong FrameType = 0x04

	// FrameClose signals stream closure.
	FrameClose FrameType = 0x05

	// FrameHandshake is used for initial handshake.
	FrameHandshake FrameType = 0x06

	// FrameError signals an error condition.
	FrameError FrameType = 0x07
)

// String returns the string representation of the frame type.
func (t FrameType) String() string {
	switch t {
	case FrameData:
		return "DATA"
	case FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameClose:
		return "CLOSE"
	case FrameHandshake:
		return "HANDSHAKE"
	case FrameError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// IsValid returns whether the frame type is valid.
func (t FrameType) IsValid() bool {
	return t >= FrameData && t <= FrameError // FrameError is 0x07
}

// Frame errors
var (
	ErrInvalidVersion     = errors.New("tunnel: invalid frame version")
	ErrInvalidFrameType   = errors.New("tunnel: invalid frame type")
	ErrPayloadTooLarge    = errors.New("tunnel: payload too large")
	ErrFrameTooShort      = errors.New("tunnel: frame too short")
	ErrInvalidStreamID    = errors.New("tunnel: invalid stream ID")
	ErrUnexpectedEOF      = errors.New("tunnel: unexpected EOF")
	ErrChecksumMismatch   = errors.New("tunnel: checksum mismatch")
	ErrConnectionClosed   = errors.New("tunnel: connection closed")
	ErrStreamClosed       = errors.New("tunnel: stream closed")
	ErrStreamNotFound     = errors.New("tunnel: stream not found")
	ErrStreamAlreadyExist = errors.New("tunnel: stream already exists")
	ErrTimeout            = errors.New("tunnel: operation timeout")
	ErrMuxClosed          = errors.New("tunnel: mux closed")
)

// Frame represents a single protocol frame.
//
// Frame format:
//
//	+----------+----------+------------+----------+------------------+
//	| Version  |   Type   |  StreamID  |  Length  |     Payload      |
//	|  1 byte  |  1 byte  |  4 bytes   |  4 bytes |    N bytes       |
//	+----------+----------+------------+----------+------------------+
type Frame struct {
	// Version is the protocol version (always 1 for now).
	Version uint8

	// Type indicates the frame type.
	Type FrameType

	// StreamID identifies the stream this frame belongs to.
	// StreamID 0 is reserved for connection-level frames.
	StreamID uint32

	// Payload contains the frame data.
	// The length is stored in the header but derived from len(Payload).
	Payload []byte
}

// NewFrame creates a new frame with the given parameters.
func NewFrame(frameType FrameType, streamID uint32, payload []byte) *Frame {
	return &Frame{
		Version:  FrameVersion,
		Type:     frameType,
		StreamID: streamID,
		Payload:  payload,
	}
}

// NewDataFrame creates a new data frame.
func NewDataFrame(streamID uint32, payload []byte) *Frame {
	return NewFrame(FrameData, streamID, payload)
}

// NewWindowUpdateFrame creates a new window update frame.
func NewWindowUpdateFrame(streamID uint32, increment uint32) *Frame {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment)
	return NewFrame(FrameWindowUpdate, streamID, payload)
}

// NewPingFrame creates a new ping frame.
func NewPingFrame(pingID uint32) *Frame {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, pingID)
	return NewFrame(FramePing, 0, payload)
}

// NewPongFrame creates a new pong (ping response) frame.
func NewPongFrame(pingID uint32) *Frame {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, pingID)
	return NewFrame(FramePong, 0, payload)
}

// NewCloseFrame creates a new close frame.
func NewCloseFrame(streamID uint32) *Frame {
	return NewFrame(FrameClose, streamID, nil)
}

// NewHandshakeFrame creates a new handshake frame.
func NewHandshakeFrame(payload []byte) *Frame {
	return NewFrame(FrameHandshake, 0, payload)
}

// NewErrorFrame creates a new error frame.
func NewErrorFrame(streamID uint32, code uint32, message string) *Frame {
	payload := make([]byte, 4+len(message))
	binary.BigEndian.PutUint32(payload[:4], code)
	copy(payload[4:], message)
	return NewFrame(FrameError, streamID, payload)
}

// Length returns the payload length.
func (f *Frame) Length() uint32 {
	return uint32(len(f.Payload))
}

// TotalSize returns the total frame size including header.
func (f *Frame) TotalSize() int {
	return FrameHeaderSize + len(f.Payload)
}

// IsConnectionLevel returns true if this is a connection-level frame.
func (f *Frame) IsConnectionLevel() bool {
	return f.StreamID == 0
}

// Validate checks if the frame is valid.
func (f *Frame) Validate() error {
	if f.Version != FrameVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrInvalidVersion, f.Version, FrameVersion)
	}
	if !f.Type.IsValid() {
		return fmt.Errorf("%w: %d", ErrInvalidFrameType, f.Type)
	}
	if len(f.Payload) > MaxFramePayloadSize {
		return fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, len(f.Payload), MaxFramePayloadSize)
	}
	return nil
}

// String returns a string representation of the frame.
func (f *Frame) String() string {
	return fmt.Sprintf("Frame{Version:%d, Type:%s, StreamID:%d, Length:%d}",
		f.Version, f.Type, f.StreamID, f.Length())
}

// Clone creates a deep copy of the frame.
func (f *Frame) Clone() *Frame {
	clone := &Frame{
		Version:  f.Version,
		Type:     f.Type,
		StreamID: f.StreamID,
	}
	if len(f.Payload) > 0 {
		clone.Payload = make([]byte, len(f.Payload))
		copy(clone.Payload, f.Payload)
	}
	return clone
}

// FrameCodec handles encoding and decoding of frames.
// It is safe for concurrent use.
type FrameCodec struct {
	maxPayloadSize uint32
	bufferPool     *sync.Pool
}

// FrameCodecOption is a function that configures a FrameCodec.
type FrameCodecOption func(*FrameCodec)

// WithMaxPayloadSize sets the maximum payload size.
func WithMaxPayloadSize(size uint32) FrameCodecOption {
	return func(c *FrameCodec) {
		c.maxPayloadSize = size
	}
}

// NewFrameCodec creates a new frame codec with the given options.
func NewFrameCodec(opts ...FrameCodecOption) *FrameCodec {
	c := &FrameCodec{
		maxPayloadSize: MaxFramePayloadSize,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, FrameHeaderSize)
				return &buf
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// DefaultCodec is the default frame codec.
var DefaultCodec = NewFrameCodec()

// Encode writes the frame to the writer.
func (c *FrameCodec) Encode(w io.Writer, f *Frame) error {
	if err := f.Validate(); err != nil {
		return err
	}

	// Get header buffer from pool
	bufPtr := c.bufferPool.Get().(*[]byte)
	header := *bufPtr
	defer c.bufferPool.Put(bufPtr)

	// Encode header
	header[0] = f.Version
	header[1] = byte(f.Type)
	binary.BigEndian.PutUint32(header[2:6], f.StreamID)
	binary.BigEndian.PutUint32(header[6:10], uint32(len(f.Payload)))

	// Write header
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write payload
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

// Decode reads a frame from the reader.
func (c *FrameCodec) Decode(r io.Reader) (*Frame, error) {
	// Get header buffer from pool
	bufPtr := c.bufferPool.Get().(*[]byte)
	header := *bufPtr
	defer c.bufferPool.Put(bufPtr)

	// Read header
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Parse header
	version := header[0]
	frameType := FrameType(header[1])
	streamID := binary.BigEndian.Uint32(header[2:6])
	length := binary.BigEndian.Uint32(header[6:10])

	// Validate version
	if version != FrameVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidVersion, version, FrameVersion)
	}

	// Validate frame type
	if !frameType.IsValid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidFrameType, frameType)
	}

	// Validate payload length
	if length > c.maxPayloadSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, length, c.maxPayloadSize)
	}

	// Read payload
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &Frame{
		Version:  version,
		Type:     frameType,
		StreamID: streamID,
		Payload:  payload,
	}, nil
}

// EncodeFrame is a convenience function that uses the default codec.
func EncodeFrame(w io.Writer, f *Frame) error {
	return DefaultCodec.Encode(w, f)
}

// DecodeFrame is a convenience function that uses the default codec.
func DecodeFrame(r io.Reader) (*Frame, error) {
	return DefaultCodec.Decode(r)
}

// ParseWindowUpdate extracts the increment from a window update frame.
func ParseWindowUpdate(f *Frame) (uint32, error) {
	if f.Type != FrameWindowUpdate {
		return 0, fmt.Errorf("expected WINDOW_UPDATE frame, got %s", f.Type)
	}
	if len(f.Payload) < 4 {
		return 0, fmt.Errorf("WINDOW_UPDATE payload too short: %d", len(f.Payload))
	}
	return binary.BigEndian.Uint32(f.Payload), nil
}

// ParsePing extracts the ping ID from a ping frame.
func ParsePing(f *Frame) (uint32, error) {
	if f.Type != FramePing {
		return 0, fmt.Errorf("expected PING frame, got %s", f.Type)
	}
	if len(f.Payload) < 4 {
		return 0, fmt.Errorf("PING payload too short: %d", len(f.Payload))
	}
	return binary.BigEndian.Uint32(f.Payload), nil
}

// ParsePong extracts the ping ID from a pong frame.
func ParsePong(f *Frame) (uint32, error) {
	if f.Type != FramePong {
		return 0, fmt.Errorf("expected PONG frame, got %s", f.Type)
	}
	if len(f.Payload) < 4 {
		return 0, fmt.Errorf("PONG payload too short: %d", len(f.Payload))
	}
	return binary.BigEndian.Uint32(f.Payload), nil
}

// ParseError extracts the error code and message from an error frame.
func ParseError(f *Frame) (code uint32, message string, err error) {
	if f.Type != FrameError {
		return 0, "", fmt.Errorf("expected ERROR frame, got %s", f.Type)
	}
	if len(f.Payload) < 4 {
		return 0, "", fmt.Errorf("ERROR payload too short: %d", len(f.Payload))
	}
	code = binary.BigEndian.Uint32(f.Payload[:4])
	message = string(f.Payload[4:])
	return code, message, nil
}
