package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameType_String(t *testing.T) {
	tests := []struct {
		frameType FrameType
		expected  string
	}{
		{FrameData, "DATA"},
		{FrameWindowUpdate, "WINDOW_UPDATE"},
		{FramePing, "PING"},
		{FramePong, "PONG"},
		{FrameClose, "CLOSE"},
		{FrameHandshake, "HANDSHAKE"},
		{FrameError, "ERROR"},
		{FrameType(99), "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.frameType.String())
		})
	}
}

func TestFrameType_IsValid(t *testing.T) {
	tests := []struct {
		frameType FrameType
		valid     bool
	}{
		{FrameData, true},
		{FrameWindowUpdate, true},
		{FramePing, true},
		{FramePong, true},
		{FrameClose, true},
		{FrameHandshake, true},
		{FrameError, true},
		{FrameType(0), false},
		{FrameType(8), false},
		{FrameType(255), false},
	}

	for _, tt := range tests {
		t.Run(tt.frameType.String(), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.frameType.IsValid())
		})
	}
}

func TestNewFrame(t *testing.T) {
	payload := []byte("hello")
	f := NewFrame(FrameData, 42, payload)

	assert.Equal(t, FrameVersion, f.Version)
	assert.Equal(t, FrameData, f.Type)
	assert.Equal(t, uint32(42), f.StreamID)
	assert.Equal(t, payload, f.Payload)
}

func TestNewDataFrame(t *testing.T) {
	payload := []byte("test data")
	f := NewDataFrame(123, payload)

	assert.Equal(t, FrameData, f.Type)
	assert.Equal(t, uint32(123), f.StreamID)
	assert.Equal(t, payload, f.Payload)
}

func TestNewWindowUpdateFrame(t *testing.T) {
	f := NewWindowUpdateFrame(100, 65535)

	assert.Equal(t, FrameWindowUpdate, f.Type)
	assert.Equal(t, uint32(100), f.StreamID)

	increment, err := ParseWindowUpdate(f)
	require.NoError(t, err)
	assert.Equal(t, uint32(65535), increment)
}

func TestNewPingFrame(t *testing.T) {
	f := NewPingFrame(12345)

	assert.Equal(t, FramePing, f.Type)
	assert.Equal(t, uint32(0), f.StreamID)

	pingID, err := ParsePing(f)
	require.NoError(t, err)
	assert.Equal(t, uint32(12345), pingID)
}

func TestNewCloseFrame(t *testing.T) {
	f := NewCloseFrame(200)

	assert.Equal(t, FrameClose, f.Type)
	assert.Equal(t, uint32(200), f.StreamID)
	assert.Nil(t, f.Payload)
}

func TestNewHandshakeFrame(t *testing.T) {
	payload := []byte("handshake data")
	f := NewHandshakeFrame(payload)

	assert.Equal(t, FrameHandshake, f.Type)
	assert.Equal(t, uint32(0), f.StreamID)
	assert.Equal(t, payload, f.Payload)
}

func TestNewErrorFrame(t *testing.T) {
	f := NewErrorFrame(50, 500, "internal error")

	assert.Equal(t, FrameError, f.Type)
	assert.Equal(t, uint32(50), f.StreamID)

	code, message, err := ParseError(f)
	require.NoError(t, err)
	assert.Equal(t, uint32(500), code)
	assert.Equal(t, "internal error", message)
}

func TestFrame_Length(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected uint32
	}{
		{"nil payload", nil, 0},
		{"empty payload", []byte{}, 0},
		{"small payload", []byte("hello"), 5},
		{"larger payload", make([]byte, 1000), 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewDataFrame(1, tt.payload)
			assert.Equal(t, tt.expected, f.Length())
		})
	}
}

func TestFrame_TotalSize(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected int
	}{
		{"nil payload", nil, FrameHeaderSize},
		{"empty payload", []byte{}, FrameHeaderSize},
		{"small payload", []byte("hello"), FrameHeaderSize + 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewDataFrame(1, tt.payload)
			assert.Equal(t, tt.expected, f.TotalSize())
		})
	}
}

func TestFrame_IsConnectionLevel(t *testing.T) {
	tests := []struct {
		name     string
		streamID uint32
		expected bool
	}{
		{"stream 0", 0, true},
		{"stream 1", 1, false},
		{"stream 100", 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewDataFrame(tt.streamID, nil)
			assert.Equal(t, tt.expected, f.IsConnectionLevel())
		})
	}
}

func TestFrame_Validate(t *testing.T) {
	tests := []struct {
		name        string
		frame       *Frame
		expectError error
	}{
		{
			name:        "valid frame",
			frame:       NewDataFrame(1, []byte("test")),
			expectError: nil,
		},
		{
			name: "invalid version",
			frame: &Frame{
				Version:  2,
				Type:     FrameData,
				StreamID: 1,
			},
			expectError: ErrInvalidVersion,
		},
		{
			name: "invalid frame type (0)",
			frame: &Frame{
				Version:  FrameVersion,
				Type:     FrameType(0),
				StreamID: 1,
			},
			expectError: ErrInvalidFrameType,
		},
		{
			name: "invalid frame type (high)",
			frame: &Frame{
				Version:  FrameVersion,
				Type:     FrameType(99),
				StreamID: 1,
			},
			expectError: ErrInvalidFrameType,
		},
		{
			name: "payload too large",
			frame: &Frame{
				Version:  FrameVersion,
				Type:     FrameData,
				StreamID: 1,
				Payload:  make([]byte, MaxFramePayloadSize+1),
			},
			expectError: ErrPayloadTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.frame.Validate()
			if tt.expectError != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tt.expectError) || errors.Is(errors.Unwrap(err), tt.expectError),
					"expected error %v, got %v", tt.expectError, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFrame_Clone(t *testing.T) {
	original := NewDataFrame(42, []byte("original data"))
	clone := original.Clone()

	// Check equality
	assert.Equal(t, original.Version, clone.Version)
	assert.Equal(t, original.Type, clone.Type)
	assert.Equal(t, original.StreamID, clone.StreamID)
	assert.Equal(t, original.Payload, clone.Payload)

	// Modify clone and verify original is unchanged
	clone.StreamID = 100
	clone.Payload[0] = 'X'

	assert.Equal(t, uint32(42), original.StreamID)
	assert.Equal(t, byte('o'), original.Payload[0])
}

func TestFrame_String(t *testing.T) {
	f := NewDataFrame(123, []byte("hello"))
	s := f.String()

	assert.Contains(t, s, "DATA")
	assert.Contains(t, s, "123")
	assert.Contains(t, s, "5") // length
}

func TestFrameCodec_EncodeDecode(t *testing.T) {
	codec := NewFrameCodec()

	tests := []struct {
		name  string
		frame *Frame
	}{
		{
			name:  "data frame",
			frame: NewDataFrame(1, []byte("hello world")),
		},
		{
			name:  "window update",
			frame: NewWindowUpdateFrame(2, 65535),
		},
		{
			name:  "ping",
			frame: NewPingFrame(12345),
		},
		{
			name:  "close",
			frame: NewCloseFrame(3),
		},
		{
			name:  "handshake",
			frame: NewHandshakeFrame([]byte("handshake")),
		},
		{
			name:  "error",
			frame: NewErrorFrame(4, 500, "error message"),
		},
		{
			name:  "empty payload",
			frame: NewDataFrame(5, nil),
		},
		{
			name:  "large payload",
			frame: NewDataFrame(6, make([]byte, 10000)),
		},
		{
			name:  "stream 0",
			frame: NewDataFrame(0, []byte("connection level")),
		},
		{
			name:  "max stream id",
			frame: NewDataFrame(0xFFFFFFFF, []byte("max")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			var buf bytes.Buffer
			err := codec.Encode(&buf, tt.frame)
			require.NoError(t, err)

			// Decode
			decoded, err := codec.Decode(&buf)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.frame.Version, decoded.Version)
			assert.Equal(t, tt.frame.Type, decoded.Type)
			assert.Equal(t, tt.frame.StreamID, decoded.StreamID)
			assert.Equal(t, tt.frame.Payload, decoded.Payload)
		})
	}
}

func TestFrameCodec_EncodeValidation(t *testing.T) {
	codec := NewFrameCodec()

	invalidFrame := &Frame{
		Version:  2, // Invalid version
		Type:     FrameData,
		StreamID: 1,
		Payload:  []byte("test"),
	}

	var buf bytes.Buffer
	err := codec.Encode(&buf, invalidFrame)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVersion)
}

func TestFrameCodec_DecodeErrors(t *testing.T) {
	codec := NewFrameCodec()

	t.Run("EOF", func(t *testing.T) {
		buf := bytes.NewReader(nil)
		_, err := codec.Decode(buf)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("short header", func(t *testing.T) {
		buf := bytes.NewReader([]byte{1, 2, 3})
		_, err := codec.Decode(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnexpectedEOF)
	})

	t.Run("invalid version", func(t *testing.T) {
		header := make([]byte, FrameHeaderSize)
		header[0] = 99 // Invalid version
		header[1] = byte(FrameData)

		buf := bytes.NewReader(header)
		_, err := codec.Decode(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidVersion)
	})

	t.Run("invalid frame type", func(t *testing.T) {
		header := make([]byte, FrameHeaderSize)
		header[0] = FrameVersion
		header[1] = 99 // Invalid type

		buf := bytes.NewReader(header)
		_, err := codec.Decode(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidFrameType)
	})

	t.Run("payload too large", func(t *testing.T) {
		header := make([]byte, FrameHeaderSize)
		header[0] = FrameVersion
		header[1] = byte(FrameData)
		binary.BigEndian.PutUint32(header[6:10], MaxFramePayloadSize+1)

		buf := bytes.NewReader(header)
		_, err := codec.Decode(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPayloadTooLarge)
	})

	t.Run("truncated payload", func(t *testing.T) {
		header := make([]byte, FrameHeaderSize)
		header[0] = FrameVersion
		header[1] = byte(FrameData)
		binary.BigEndian.PutUint32(header[6:10], 100) // Expect 100 bytes

		// Only provide header + 10 bytes of payload
		data := make([]byte, 0, FrameHeaderSize+10)
		data = append(data, header...)
		data = append(data, make([]byte, 10)...)
		buf := bytes.NewReader(data)
		_, err := codec.Decode(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnexpectedEOF)
	})
}

func TestFrameCodec_WithMaxPayloadSize(t *testing.T) {
	smallCodec := NewFrameCodec(WithMaxPayloadSize(100))

	t.Run("accept small payload", func(t *testing.T) {
		var buf bytes.Buffer
		frame := NewDataFrame(1, make([]byte, 50))
		err := smallCodec.Encode(&buf, frame)
		require.NoError(t, err)

		decoded, err := smallCodec.Decode(&buf)
		require.NoError(t, err)
		assert.Equal(t, 50, len(decoded.Payload))
	})

	t.Run("reject large payload on decode", func(t *testing.T) {
		// Create header with length > 100
		header := make([]byte, FrameHeaderSize)
		header[0] = FrameVersion
		header[1] = byte(FrameData)
		binary.BigEndian.PutUint32(header[6:10], 200)

		buf := bytes.NewReader(header)
		_, err := smallCodec.Decode(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPayloadTooLarge)
	})
}

func TestDefaultCodec(t *testing.T) {
	// Test EncodeFrame and DecodeFrame convenience functions
	original := NewDataFrame(42, []byte("test"))

	var buf bytes.Buffer
	err := EncodeFrame(&buf, original)
	require.NoError(t, err)

	decoded, err := DecodeFrame(&buf)
	require.NoError(t, err)

	assert.Equal(t, original.StreamID, decoded.StreamID)
	assert.Equal(t, original.Payload, decoded.Payload)
}

func TestParseWindowUpdate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := NewWindowUpdateFrame(1, 12345)
		inc, err := ParseWindowUpdate(f)
		require.NoError(t, err)
		assert.Equal(t, uint32(12345), inc)
	})

	t.Run("wrong type", func(t *testing.T) {
		f := NewDataFrame(1, nil)
		_, err := ParseWindowUpdate(f)
		require.Error(t, err)
	})

	t.Run("short payload", func(t *testing.T) {
		f := NewFrame(FrameWindowUpdate, 1, []byte{1, 2})
		_, err := ParseWindowUpdate(f)
		require.Error(t, err)
	})
}

func TestParsePing(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := NewPingFrame(99999)
		pingID, err := ParsePing(f)
		require.NoError(t, err)
		assert.Equal(t, uint32(99999), pingID)
	})

	t.Run("wrong type", func(t *testing.T) {
		f := NewDataFrame(0, nil)
		_, err := ParsePing(f)
		require.Error(t, err)
	})

	t.Run("short payload", func(t *testing.T) {
		f := NewFrame(FramePing, 0, []byte{1})
		_, err := ParsePing(f)
		require.Error(t, err)
	})
}

func TestParsePong(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := NewPongFrame(54321)
		pongID, err := ParsePong(f)
		require.NoError(t, err)
		assert.Equal(t, uint32(54321), pongID)
	})

	t.Run("wrong type", func(t *testing.T) {
		f := NewDataFrame(0, nil)
		_, err := ParsePong(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected PONG frame")
	})

	t.Run("short payload", func(t *testing.T) {
		f := NewFrame(FramePong, 0, []byte{1, 2})
		_, err := ParsePong(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PONG payload too short")
	})

	t.Run("nil payload", func(t *testing.T) {
		f := NewFrame(FramePong, 0, nil)
		_, err := ParsePong(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PONG payload too short")
	})
}

func TestParseError(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f := NewErrorFrame(1, 404, "not found")
		code, msg, err := ParseError(f)
		require.NoError(t, err)
		assert.Equal(t, uint32(404), code)
		assert.Equal(t, "not found", msg)
	})

	t.Run("empty message", func(t *testing.T) {
		f := NewErrorFrame(1, 500, "")
		code, msg, err := ParseError(f)
		require.NoError(t, err)
		assert.Equal(t, uint32(500), code)
		assert.Equal(t, "", msg)
	})

	t.Run("wrong type", func(t *testing.T) {
		f := NewDataFrame(1, nil)
		_, _, err := ParseError(f)
		require.Error(t, err)
	})

	t.Run("short payload", func(t *testing.T) {
		f := NewFrame(FrameError, 1, []byte{1, 2})
		_, _, err := ParseError(f)
		require.Error(t, err)
	})
}

func TestFrameCodec_Concurrent(t *testing.T) {
	codec := NewFrameCodec()
	iterations := 100

	// Test concurrent encoding
	t.Run("concurrent encode", func(t *testing.T) {
		done := make(chan bool, iterations)
		for i := 0; i < iterations; i++ {
			go func(id int) {
				var buf bytes.Buffer
				frame := NewDataFrame(uint32(id), []byte("test data"))
				err := codec.Encode(&buf, frame)
				assert.NoError(t, err)
				done <- true
			}(i)
		}
		for i := 0; i < iterations; i++ {
			<-done
		}
	})

	// Test concurrent decode
	t.Run("concurrent decode", func(t *testing.T) {
		// Prepare encoded frames
		var encoded bytes.Buffer
		frame := NewDataFrame(1, []byte("test"))
		for i := 0; i < iterations; i++ {
			codec.Encode(&encoded, frame)
		}

		// Decode concurrently from separate readers
		done := make(chan bool, iterations)
		for i := 0; i < iterations; i++ {
			// Create separate reader for each goroutine
			data := make([]byte, frame.TotalSize())
			copy(data, encoded.Bytes()[i*frame.TotalSize():(i+1)*frame.TotalSize()])

			go func(data []byte) {
				reader := bytes.NewReader(data)
				decoded, err := codec.Decode(reader)
				assert.NoError(t, err)
				assert.Equal(t, frame.StreamID, decoded.StreamID)
				done <- true
			}(data)
		}
		for i := 0; i < iterations; i++ {
			<-done
		}
	})
}

// Benchmarks

func BenchmarkFrameCodec_Encode(b *testing.B) {
	codec := NewFrameCodec()
	frame := NewDataFrame(1, make([]byte, 1024))
	var buf bytes.Buffer
	buf.Grow(frame.TotalSize() * b.N)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		codec.Encode(&buf, frame)
	}
}

func BenchmarkFrameCodec_Decode(b *testing.B) {
	codec := NewFrameCodec()
	frame := NewDataFrame(1, make([]byte, 1024))

	var buf bytes.Buffer
	codec.Encode(&buf, frame)
	data := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		codec.Decode(reader)
	}
}

func BenchmarkFrameCodec_EncodeSmall(b *testing.B) {
	codec := NewFrameCodec()
	frame := NewDataFrame(1, []byte("hello"))
	var buf bytes.Buffer

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		codec.Encode(&buf, frame)
	}
}

func BenchmarkFrameCodec_EncodeLarge(b *testing.B) {
	codec := NewFrameCodec()
	frame := NewDataFrame(1, make([]byte, 32*1024))
	var buf bytes.Buffer
	buf.Grow(frame.TotalSize())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		codec.Encode(&buf, frame)
	}
}
