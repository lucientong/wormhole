package proto

// DecodeControlMessage is the entry point for every byte the control
// plane reads off the wire — both the protobuf fast path and the
// legacy-JSON fallback — before this build's own code ever sees a typed
// message. Fuzzing it (see .github/workflows/ci.yml for the short CI
// budget) guards against a future regression introducing a panic on
// malformed/adversarial input, which a fixed table of unit tests can't
// exhaustively rule out.

import (
	"testing"
)

func FuzzDecodeControlMessage(f *testing.F) {
	seeds := [][]byte{
		{},
		[]byte("{}"),
		[]byte(`{"type":"auth_request"`), // truncated JSON
		encodeForFuzz(f, NewAuthRequest("tok", "1.0.0", "myapp")),
		encodeForFuzz(f, NewAuthResponse(true, "", "myapp", "https://myapp.test", "sess-1")),
		encodeForFuzz(f, NewRegisterRequest(8080, ProtocolHTTP, "myapp", "", "")),
		encodeForFuzz(f, NewRegisterResponse(true, "", "tid-1", "https://myapp.test", 0)),
		encodeForFuzz(f, NewPingRequest(1)),
		encodeForFuzz(f, NewPingResponse(1)),
		encodeForFuzz(f, NewStreamRequest("tid-1", "req-1", "1.2.3.4:5678", ProtocolHTTP)),
		encodeForFuzz(f, NewStreamResponse("req-1", true, "")),
		encodeForFuzz(f, NewStatsRequest("sess-1")),
		encodeForFuzz(f, NewStatsResponse(1, 2, 3, 4, 5, 6)),
		encodeForFuzz(f, NewCloseRequest("tid-1", "done")),
		encodeForFuzz(f, NewCloseResponse(true)),
		encodeForFuzz(f, NewP2POfferRequest("tid-1", "full-cone", "1.2.3.4:1", "10.0.0.1:2", "pubkey", "target")),
		encodeForFuzz(f, NewP2POfferResponse(true, "", "1.2.3.4:1", "full-cone", "peerkey", "tid-2")),
		encodeForFuzz(f, NewP2PCandidates("tid-1", []string{"1.2.3.4:1", "10.0.0.1:2"})),
		encodeForFuzz(f, NewP2PResult("tid-1", true, "1.2.3.4:1", "")),
		encodeJSONForFuzz(f, NewAuthRequest("tok", "1.0.0", "myapp")),
		encodeJSONForFuzz(f, NewRegisterResponse(true, "", "tid-1", "https://myapp.test", 0)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeControlMessage(data)
		if err != nil {
			if msg != nil {
				t.Fatalf("DecodeControlMessage returned both a non-nil message and an error: %v", err)
			}
			return
		}
		// A successfully decoded message must always be re-encodable —
		// Decode accepting something Encode can't reproduce would be a
		// parser/serializer asymmetry bug in its own right.
		if _, encErr := msg.Encode(); encErr != nil {
			t.Fatalf("re-encoding a successfully decoded message failed: %v", encErr)
		}
	})
}

func encodeForFuzz(f *testing.F, msg *ControlMessage) []byte {
	f.Helper()
	data, err := msg.Encode()
	if err != nil {
		f.Fatalf("failed to encode seed message: %v", err)
	}
	return data
}

func encodeJSONForFuzz(f *testing.F, msg *ControlMessage) []byte {
	f.Helper()
	data, err := msg.EncodeJSON()
	if err != nil {
		f.Fatalf("failed to JSON-encode seed message: %v", err)
	}
	return data
}
