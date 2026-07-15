package tunnel

// NT-08: DecodeFrame parses an attacker-controlled byte stream (whatever
// arrives on the tunnel control/data connection) directly into header
// fields via unchecked binary.BigEndian reads — exactly the kind of
// parser fuzzing is best at hardening. This never found a crash during
// development, but the whole point of running it in CI (see
// .github/workflows/ci.yml) is to keep catching future regressions
// rather than to prove today's code is already safe.

import (
	"bytes"
	"testing"
)

func FuzzDecodeFrame(f *testing.F) {
	seeds := [][]byte{
		{},
		{FrameVersion},
		encodeFrameForFuzz(f, NewFrame(FrameData, 1, []byte("hello"))),
		encodeFrameForFuzz(f, NewFrame(FrameData, 1, nil)),
		encodeFrameForFuzz(f, NewFrame(FrameWindowUpdate, 3, []byte{0, 0, 0, 1})),
		encodeFrameForFuzz(f, NewFrame(FramePing, 0, []byte{0, 0, 0, 1})),
		encodeFrameForFuzz(f, NewFrame(FrameClose, 5, nil)),
		encodeFrameForFuzz(f, NewFrame(FrameHandshake, 7, nil)),
		encodeFrameForFuzz(f, &Frame{Version: FrameVersion, Type: FrameError, StreamID: 9, Payload: []byte{0, 1, 2, 3}}),
		// Malformed: valid version/type but a length field wildly
		// exceeding what follows — must error, not read out of bounds.
		{FrameVersion, byte(FrameData), 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF},
		// Unknown frame type byte.
		{FrameVersion, 0xEE, 0, 0, 0, 1, 0, 0, 0, 0},
		// Wrong version.
		{0xFF, byte(FrameData), 0, 0, 0, 1, 0, 0, 0, 0},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := DecodeFrame(bytes.NewReader(data))
		if err != nil {
			if frame != nil {
				t.Fatalf("DecodeFrame returned both a non-nil frame and an error: %v", err)
			}
			return
		}
		// A successfully decoded frame must always satisfy the same
		// invariants Encode would enforce on its way back out —
		// otherwise Decode accepted something Encode couldn't have
		// produced, which is its own kind of parser bug.
		if err := frame.Validate(); err != nil {
			t.Fatalf("DecodeFrame produced an invalid frame: %v", err)
		}
	})
}

// encodeFrameForFuzz encodes f into its wire form for use as fuzz seed
// data, failing the fuzz target's setup (not a generated case) on error.
func encodeFrameForFuzz(f *testing.F, frame *Frame) []byte {
	f.Helper()
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, frame); err != nil {
		f.Fatalf("failed to encode seed frame: %v", err)
	}
	return buf.Bytes()
}
