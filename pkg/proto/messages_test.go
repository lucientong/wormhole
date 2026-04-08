package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Protocol.String() tests ---

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		proto    Protocol
		expected string
	}{
		{ProtocolUnknown, "Unknown"},
		{ProtocolHTTP, "HTTP"},
		{ProtocolHTTPS, "HTTPS"},
		{ProtocolTCP, "TCP"},
		{ProtocolUDP, "UDP"},
		{ProtocolWebSocket, "WebSocket"},
		{ProtocolGRPC, "gRPC"},
		{Protocol(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.proto.String())
		})
	}
}

// --- Encode / Decode round-trip ---

func TestControlMessage_EncodeDecode(t *testing.T) {
	original := NewAuthRequest("token123", "v1.0.0", "myapp")
	original.Sequence = 42

	data, err := original.Encode()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)

	assert.Equal(t, MessageTypeAuthRequest, decoded.Type)
	assert.Equal(t, uint64(42), decoded.Sequence)
	require.NotNil(t, decoded.AuthRequest)
	assert.Equal(t, "token123", decoded.AuthRequest.Token)
	assert.Equal(t, "v1.0.0", decoded.AuthRequest.Version)
	assert.Equal(t, "myapp", decoded.AuthRequest.Subdomain)
}

func TestDecodeControlMessage_InvalidJSON(t *testing.T) {
	_, err := DecodeControlMessage([]byte("not json"))
	require.Error(t, err)
}

func TestDecodeControlMessage_EmptyPayload(t *testing.T) {
	msg, err := DecodeControlMessage([]byte(`{"type":1,"sequence":0}`))
	require.NoError(t, err)
	assert.Equal(t, MessageTypeAuthRequest, msg.Type)
	assert.Nil(t, msg.AuthRequest) // No payload set.
}

// --- Factory function tests ---

func TestNewAuthRequest(t *testing.T) {
	msg := NewAuthRequest("tok", "v2", "sub")
	assert.Equal(t, MessageTypeAuthRequest, msg.Type)
	require.NotNil(t, msg.AuthRequest)
	assert.Equal(t, "tok", msg.AuthRequest.Token)
	assert.Equal(t, "v2", msg.AuthRequest.Version)
	assert.Equal(t, "sub", msg.AuthRequest.Subdomain)
}

func TestNewAuthResponse(t *testing.T) {
	msg := NewAuthResponse(true, "", "sub", "https://sub.example.com", "sess-1")
	assert.Equal(t, MessageTypeAuthResponse, msg.Type)
	require.NotNil(t, msg.AuthResponse)
	assert.True(t, msg.AuthResponse.Success)
	assert.Empty(t, msg.AuthResponse.Error)
	assert.Equal(t, "sub", msg.AuthResponse.Subdomain)
	assert.Equal(t, "https://sub.example.com", msg.AuthResponse.PublicURL)
	assert.Equal(t, "sess-1", msg.AuthResponse.SessionID)
}

func TestNewAuthResponse_Error(t *testing.T) {
	msg := NewAuthResponse(false, "invalid token", "", "", "")
	require.NotNil(t, msg.AuthResponse)
	assert.False(t, msg.AuthResponse.Success)
	assert.Equal(t, "invalid token", msg.AuthResponse.Error)
}

func TestNewRegisterRequest(t *testing.T) {
	msg := NewRegisterRequest(8080, ProtocolHTTP, "myapp")
	assert.Equal(t, MessageTypeRegisterRequest, msg.Type)
	require.NotNil(t, msg.RegisterRequest)
	assert.Equal(t, uint32(8080), msg.RegisterRequest.LocalPort)
	assert.Equal(t, ProtocolHTTP, msg.RegisterRequest.Protocol)
	assert.Equal(t, "myapp", msg.RegisterRequest.Subdomain)
}

func TestNewRegisterResponse(t *testing.T) {
	msg := NewRegisterResponse(true, "", "tunnel-1", "https://myapp.example.com", 0)
	assert.Equal(t, MessageTypeRegisterResponse, msg.Type)
	require.NotNil(t, msg.RegisterResponse)
	assert.True(t, msg.RegisterResponse.Success)
	assert.Equal(t, "tunnel-1", msg.RegisterResponse.TunnelID)
	assert.Equal(t, "https://myapp.example.com", msg.RegisterResponse.PublicURL)
}

func TestNewRegisterResponse_WithTCPPort(t *testing.T) {
	msg := NewRegisterResponse(true, "", "tcp-1", "", 15000)
	require.NotNil(t, msg.RegisterResponse)
	assert.Equal(t, uint32(15000), msg.RegisterResponse.TCPPort)
}

func TestNewRegisterResponse_Error(t *testing.T) {
	msg := NewRegisterResponse(false, "subdomain taken", "", "", 0)
	require.NotNil(t, msg.RegisterResponse)
	assert.False(t, msg.RegisterResponse.Success)
	assert.Equal(t, "subdomain taken", msg.RegisterResponse.Error)
}

func TestNewPingRequest(t *testing.T) {
	msg := NewPingRequest(123)
	assert.Equal(t, MessageTypePingRequest, msg.Type)
	require.NotNil(t, msg.PingRequest)
	assert.Equal(t, uint64(123), msg.PingRequest.PingID)
	assert.NotZero(t, msg.PingRequest.Timestamp)
}

func TestNewPingResponse(t *testing.T) {
	msg := NewPingResponse(456)
	assert.Equal(t, MessageTypePingResponse, msg.Type)
	require.NotNil(t, msg.PingResponse)
	assert.Equal(t, uint64(456), msg.PingResponse.PingID)
	assert.NotZero(t, msg.PingResponse.Timestamp)
}

func TestNewStreamRequest(t *testing.T) {
	msg := NewStreamRequest("tunnel-1", "req-abc", "192.168.1.1:5000", ProtocolHTTP)
	assert.Equal(t, MessageTypeStreamRequest, msg.Type)
	require.NotNil(t, msg.StreamRequest)
	assert.Equal(t, "tunnel-1", msg.StreamRequest.TunnelID)
	assert.Equal(t, "req-abc", msg.StreamRequest.RequestID)
	assert.Equal(t, "192.168.1.1:5000", msg.StreamRequest.RemoteAddr)
	assert.Equal(t, ProtocolHTTP, msg.StreamRequest.Protocol)
}

func TestNewStreamResponse(t *testing.T) {
	msg := NewStreamResponse("req-abc", true, "")
	assert.Equal(t, MessageTypeStreamResponse, msg.Type)
	require.NotNil(t, msg.StreamResponse)
	assert.Equal(t, "req-abc", msg.StreamResponse.RequestID)
	assert.True(t, msg.StreamResponse.Accepted)
	assert.Empty(t, msg.StreamResponse.Error)
}

func TestNewStreamResponse_Rejected(t *testing.T) {
	msg := NewStreamResponse("req-abc", false, "connection refused")
	require.NotNil(t, msg.StreamResponse)
	assert.False(t, msg.StreamResponse.Accepted)
	assert.Equal(t, "connection refused", msg.StreamResponse.Error)
}

func TestNewCloseRequest(t *testing.T) {
	msg := NewCloseRequest("tunnel-1", "shutdown")
	assert.Equal(t, MessageTypeCloseRequest, msg.Type)
	require.NotNil(t, msg.CloseRequest)
	assert.Equal(t, "tunnel-1", msg.CloseRequest.TunnelID)
	assert.Equal(t, "shutdown", msg.CloseRequest.Reason)
}

func TestNewCloseResponse(t *testing.T) {
	msg := NewCloseResponse(true)
	assert.Equal(t, MessageTypeCloseResponse, msg.Type)
	require.NotNil(t, msg.CloseResponse)
	assert.True(t, msg.CloseResponse.Success)
}

func TestNewCloseResponse_Failure(t *testing.T) {
	msg := NewCloseResponse(false)
	require.NotNil(t, msg.CloseResponse)
	assert.False(t, msg.CloseResponse.Success)
}

func TestNewP2POfferRequest(t *testing.T) {
	msg := NewP2POfferRequest("tunnel-1", "Full Cone", "1.2.3.4:5000", "192.168.1.1:5000", "cHViS2V5")
	assert.Equal(t, MessageTypeP2POfferRequest, msg.Type)
	require.NotNil(t, msg.P2POfferRequest)
	assert.Equal(t, "tunnel-1", msg.P2POfferRequest.TunnelID)
	assert.Equal(t, "Full Cone", msg.P2POfferRequest.NATType)
	assert.Equal(t, "1.2.3.4:5000", msg.P2POfferRequest.PublicAddr)
	assert.Equal(t, "192.168.1.1:5000", msg.P2POfferRequest.LocalAddr)
	assert.Equal(t, "cHViS2V5", msg.P2POfferRequest.PublicKey)
}

func TestNewP2POfferResponse(t *testing.T) {
	msg := NewP2POfferResponse(true, "", "5.6.7.8:6000", "Restricted Cone", "cGVlcktleQ==")
	assert.Equal(t, MessageTypeP2POfferResponse, msg.Type)
	require.NotNil(t, msg.P2POfferResponse)
	assert.True(t, msg.P2POfferResponse.Success)
	assert.Empty(t, msg.P2POfferResponse.Error)
	assert.Equal(t, "5.6.7.8:6000", msg.P2POfferResponse.PeerAddr)
	assert.Equal(t, "Restricted Cone", msg.P2POfferResponse.PeerNATType)
	assert.Equal(t, "cGVlcktleQ==", msg.P2POfferResponse.PeerPublicKey)
}

func TestNewP2POfferResponse_Error(t *testing.T) {
	msg := NewP2POfferResponse(false, "no peer found", "", "", "")
	require.NotNil(t, msg.P2POfferResponse)
	assert.False(t, msg.P2POfferResponse.Success)
	assert.Equal(t, "no peer found", msg.P2POfferResponse.Error)
}

func TestNewP2PCandidates(t *testing.T) {
	candidates := []string{"1.2.3.4:5000", "5.6.7.8:6000"}
	msg := NewP2PCandidates("tunnel-1", candidates)
	assert.Equal(t, MessageTypeP2PCandidates, msg.Type)
	require.NotNil(t, msg.P2PCandidates)
	assert.Equal(t, "tunnel-1", msg.P2PCandidates.TunnelID)
	assert.Equal(t, candidates, msg.P2PCandidates.Candidates)
}

func TestNewP2PCandidates_Empty(t *testing.T) {
	msg := NewP2PCandidates("tunnel-1", nil)
	require.NotNil(t, msg.P2PCandidates)
	assert.Nil(t, msg.P2PCandidates.Candidates)
}

func TestNewP2PResult(t *testing.T) {
	msg := NewP2PResult("tunnel-1", true, "1.2.3.4:5000", "")
	assert.Equal(t, MessageTypeP2PResult, msg.Type)
	require.NotNil(t, msg.P2PResult)
	assert.Equal(t, "tunnel-1", msg.P2PResult.TunnelID)
	assert.True(t, msg.P2PResult.Success)
	assert.Equal(t, "1.2.3.4:5000", msg.P2PResult.PeerAddr)
	assert.Empty(t, msg.P2PResult.Error)
}

func TestNewP2PResult_Failure(t *testing.T) {
	msg := NewP2PResult("tunnel-1", false, "", "timeout")
	require.NotNil(t, msg.P2PResult)
	assert.False(t, msg.P2PResult.Success)
	assert.Equal(t, "timeout", msg.P2PResult.Error)
}

// --- Round-trip tests for all message types ---

func TestRoundTrip_AuthResponse(t *testing.T) {
	original := NewAuthResponse(true, "", "app", "https://app.worm.io", "s-1")
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypeAuthResponse, decoded.Type)
	require.NotNil(t, decoded.AuthResponse)
	assert.True(t, decoded.AuthResponse.Success)
	assert.Equal(t, "app", decoded.AuthResponse.Subdomain)
}

func TestRoundTrip_RegisterRequest(t *testing.T) {
	original := NewRegisterRequest(3000, ProtocolTCP, "tcp-tunnel")
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypeRegisterRequest, decoded.Type)
	require.NotNil(t, decoded.RegisterRequest)
	assert.Equal(t, uint32(3000), decoded.RegisterRequest.LocalPort)
	assert.Equal(t, ProtocolTCP, decoded.RegisterRequest.Protocol)
}

func TestRoundTrip_PingRequest(t *testing.T) {
	original := NewPingRequest(999)
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypePingRequest, decoded.Type)
	require.NotNil(t, decoded.PingRequest)
	assert.Equal(t, uint64(999), decoded.PingRequest.PingID)
}

func TestRoundTrip_StreamRequest(t *testing.T) {
	original := NewStreamRequest("t-1", "r-1", "10.0.0.1:80", ProtocolWebSocket)
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypeStreamRequest, decoded.Type)
	require.NotNil(t, decoded.StreamRequest)
	assert.Equal(t, "t-1", decoded.StreamRequest.TunnelID)
	assert.Equal(t, ProtocolWebSocket, decoded.StreamRequest.Protocol)
}

func TestRoundTrip_CloseRequest(t *testing.T) {
	original := NewCloseRequest("t-1", "user disconnect")
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypeCloseRequest, decoded.Type)
	require.NotNil(t, decoded.CloseRequest)
	assert.Equal(t, "t-1", decoded.CloseRequest.TunnelID)
	assert.Equal(t, "user disconnect", decoded.CloseRequest.Reason)
}

func TestRoundTrip_P2POfferRequest(t *testing.T) {
	original := NewP2POfferRequest("t-1", "Full Cone", "1.2.3.4:5000", "192.168.1.1:5000", "key123")
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypeP2POfferRequest, decoded.Type)
	require.NotNil(t, decoded.P2POfferRequest)
	assert.Equal(t, "Full Cone", decoded.P2POfferRequest.NATType)
	assert.Equal(t, "key123", decoded.P2POfferRequest.PublicKey)
}

func TestRoundTrip_P2PResult(t *testing.T) {
	original := NewP2PResult("t-1", true, "1.2.3.4:5000", "")
	data, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeControlMessage(data)
	require.NoError(t, err)
	assert.Equal(t, MessageTypeP2PResult, decoded.Type)
	require.NotNil(t, decoded.P2PResult)
	assert.True(t, decoded.P2PResult.Success)
	assert.Equal(t, "1.2.3.4:5000", decoded.P2PResult.PeerAddr)
}

// --- MessageType constants ---

func TestMessageTypeConstants(t *testing.T) {
	// Verify message type constant values are distinct and sequential.
	types := []MessageType{
		MessageTypeUnknown,
		MessageTypeAuthRequest,
		MessageTypeAuthResponse,
		MessageTypeRegisterRequest,
		MessageTypeRegisterResponse,
		MessageTypePingRequest,
		MessageTypePingResponse,
		MessageTypeStreamRequest,
		MessageTypeStreamResponse,
		MessageTypeStatsRequest,
		MessageTypeStatsResponse,
		MessageTypeCloseRequest,
		MessageTypeCloseResponse,
		MessageTypeP2POfferRequest,
		MessageTypeP2POfferResponse,
		MessageTypeP2PCandidates,
		MessageTypeP2PResult,
	}

	seen := make(map[MessageType]bool)
	for _, mt := range types {
		assert.False(t, seen[mt], "duplicate MessageType value: %d", mt)
		seen[mt] = true
	}
}

// --- ProtocolConstants ---

func TestProtocolConstants(t *testing.T) {
	protocols := []Protocol{
		ProtocolUnknown,
		ProtocolHTTP,
		ProtocolHTTPS,
		ProtocolTCP,
		ProtocolUDP,
		ProtocolWebSocket,
		ProtocolGRPC,
	}

	seen := make(map[Protocol]bool)
	for _, p := range protocols {
		assert.False(t, seen[p], "duplicate Protocol value: %d", p)
		seen[p] = true
	}
}
