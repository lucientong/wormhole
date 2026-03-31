// Package proto provides control protocol definitions for Wormhole.
//
// This file contains helper functions for creating protocol messages.
// The actual protobuf-generated code would be in control.pb.go.
// For now, we use a simplified JSON-based implementation.
package proto

import (
	"encoding/json"
	"time"
)

// Protocol represents the tunnel protocol type.
type Protocol int32

const (
	ProtocolUnknown   Protocol = 0
	ProtocolHTTP      Protocol = 1
	ProtocolHTTPS     Protocol = 2
	ProtocolTCP       Protocol = 3
	ProtocolUDP       Protocol = 4
	ProtocolWebSocket Protocol = 5
	ProtocolGRPC      Protocol = 6
)

func (p Protocol) String() string {
	switch p {
	case ProtocolHTTP:
		return "HTTP"
	case ProtocolHTTPS:
		return "HTTPS"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolWebSocket:
		return "WebSocket"
	case ProtocolGRPC:
		return "gRPC"
	default:
		return "Unknown"
	}
}

// MessageType identifies the type of control message.
type MessageType int32

const (
	MessageTypeUnknown          MessageType = 0
	MessageTypeAuthRequest      MessageType = 1
	MessageTypeAuthResponse     MessageType = 2
	MessageTypeRegisterRequest  MessageType = 3
	MessageTypeRegisterResponse MessageType = 4
	MessageTypePingRequest      MessageType = 5
	MessageTypePingResponse     MessageType = 6
	MessageTypeStreamRequest    MessageType = 7
	MessageTypeStreamResponse   MessageType = 8
	MessageTypeStatsRequest     MessageType = 9
	MessageTypeStatsResponse    MessageType = 10
	MessageTypeCloseRequest     MessageType = 11
	MessageTypeCloseResponse    MessageType = 12
)

// AuthRequest is sent by client to authenticate with the server.
type AuthRequest struct {
	Token        string   `json:"token"`
	Version      string   `json:"version"`
	Subdomain    string   `json:"subdomain,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// AuthResponse is sent by server after authentication.
type AuthResponse struct {
	Success      bool     `json:"success"`
	Error        string   `json:"error,omitempty"`
	Subdomain    string   `json:"subdomain,omitempty"`
	PublicURL    string   `json:"public_url,omitempty"`
	TCPPort      uint32   `json:"tcp_port,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	SessionID    string   `json:"session_id,omitempty"`
}

// RegisterRequest is sent by client to register a tunnel.
type RegisterRequest struct {
	LocalPort uint32   `json:"local_port"`
	Protocol  Protocol `json:"protocol"`
	Subdomain string   `json:"subdomain,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
}

// RegisterResponse is sent by server after tunnel registration.
type RegisterResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	TunnelID  string `json:"tunnel_id,omitempty"`
	PublicURL string `json:"public_url,omitempty"`
	TCPPort   uint32 `json:"tcp_port,omitempty"`
}

// PingRequest is used for keep-alive.
type PingRequest struct {
	PingID    uint64 `json:"ping_id"`
	Timestamp int64  `json:"timestamp"`
}

// PingResponse is the response to a ping.
type PingResponse struct {
	PingID    uint64 `json:"ping_id"`
	Timestamp int64  `json:"timestamp"`
}

// StreamRequest is sent to initiate a new stream.
type StreamRequest struct {
	TunnelID     string        `json:"tunnel_id"`
	RequestID    string        `json:"request_id"`
	RemoteAddr   string        `json:"remote_addr"`
	Protocol     Protocol      `json:"protocol"`
	HTTPMetadata *HTTPMetadata `json:"http_metadata,omitempty"`
}

// HTTPMetadata contains HTTP-specific information.
type HTTPMetadata struct {
	Method        string `json:"method"`
	URI           string `json:"uri"`
	Host          string `json:"host"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int64  `json:"content_length,omitempty"`
}

// StreamResponse is the response to a stream request.
type StreamResponse struct {
	RequestID string `json:"request_id"`
	Accepted  bool   `json:"accepted"`
	Error     string `json:"error,omitempty"`
}

// StatsRequest requests statistics from the server.
type StatsRequest struct {
	SessionID string `json:"session_id,omitempty"`
}

// StatsResponse contains statistics.
type StatsResponse struct {
	ActiveTunnels     uint32 `json:"active_tunnels"`
	ActiveConnections uint32 `json:"active_connections"`
	BytesSent         uint64 `json:"bytes_sent"`
	BytesReceived     uint64 `json:"bytes_received"`
	RequestsHandled   uint64 `json:"requests_handled"`
	UptimeSeconds     uint64 `json:"uptime_seconds"`
}

// CloseRequest is sent to close a tunnel.
type CloseRequest struct {
	TunnelID string `json:"tunnel_id"`
	Reason   string `json:"reason,omitempty"`
}

// CloseResponse acknowledges a close request.
type CloseResponse struct {
	Success bool `json:"success"`
}

// ControlMessage is a wrapper for all control messages.
type ControlMessage struct {
	Type     MessageType `json:"type"`
	Sequence uint64      `json:"sequence"`

	// Payload (only one should be set)
	AuthRequest      *AuthRequest      `json:"auth_request,omitempty"`
	AuthResponse     *AuthResponse     `json:"auth_response,omitempty"`
	RegisterRequest  *RegisterRequest  `json:"register_request,omitempty"`
	RegisterResponse *RegisterResponse `json:"register_response,omitempty"`
	PingRequest      *PingRequest      `json:"ping_request,omitempty"`
	PingResponse     *PingResponse     `json:"ping_response,omitempty"`
	StreamRequest    *StreamRequest    `json:"stream_request,omitempty"`
	StreamResponse   *StreamResponse   `json:"stream_response,omitempty"`
	StatsRequest     *StatsRequest     `json:"stats_request,omitempty"`
	StatsResponse    *StatsResponse    `json:"stats_response,omitempty"`
	CloseRequest     *CloseRequest     `json:"close_request,omitempty"`
	CloseResponse    *CloseResponse    `json:"close_response,omitempty"`
}

// Encode serializes a control message to bytes.
func (m *ControlMessage) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeControlMessage deserializes a control message from bytes.
func DecodeControlMessage(data []byte) (*ControlMessage, error) {
	var m ControlMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Helper functions for creating messages

// NewAuthRequest creates a new auth request message.
func NewAuthRequest(token, version, subdomain string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeAuthRequest,
		AuthRequest: &AuthRequest{
			Token:     token,
			Version:   version,
			Subdomain: subdomain,
		},
	}
}

// NewAuthResponse creates a new auth response message.
func NewAuthResponse(success bool, err string, subdomain, publicURL, sessionID string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeAuthResponse,
		AuthResponse: &AuthResponse{
			Success:   success,
			Error:     err,
			Subdomain: subdomain,
			PublicURL: publicURL,
			SessionID: sessionID,
		},
	}
}

// NewRegisterRequest creates a new register request message.
func NewRegisterRequest(localPort uint32, protocol Protocol, subdomain string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeRegisterRequest,
		RegisterRequest: &RegisterRequest{
			LocalPort: localPort,
			Protocol:  protocol,
			Subdomain: subdomain,
		},
	}
}

// NewRegisterResponse creates a new register response message.
func NewRegisterResponse(success bool, err, tunnelID, publicURL string, tcpPort uint32) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeRegisterResponse,
		RegisterResponse: &RegisterResponse{
			Success:   success,
			Error:     err,
			TunnelID:  tunnelID,
			PublicURL: publicURL,
			TCPPort:   tcpPort,
		},
	}
}

// NewPingRequest creates a new ping request message.
func NewPingRequest(pingID uint64) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypePingRequest,
		PingRequest: &PingRequest{
			PingID:    pingID,
			Timestamp: time.Now().UnixNano(),
		},
	}
}

// NewPingResponse creates a new ping response message.
func NewPingResponse(pingID uint64) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypePingResponse,
		PingResponse: &PingResponse{
			PingID:    pingID,
			Timestamp: time.Now().UnixNano(),
		},
	}
}

// NewStreamRequest creates a new stream request message.
func NewStreamRequest(tunnelID, requestID, remoteAddr string, protocol Protocol) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeStreamRequest,
		StreamRequest: &StreamRequest{
			TunnelID:   tunnelID,
			RequestID:  requestID,
			RemoteAddr: remoteAddr,
			Protocol:   protocol,
		},
	}
}

// NewStreamResponse creates a new stream response message.
func NewStreamResponse(requestID string, accepted bool, err string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeStreamResponse,
		StreamResponse: &StreamResponse{
			RequestID: requestID,
			Accepted:  accepted,
			Error:     err,
		},
	}
}

// NewCloseRequest creates a new close request message.
func NewCloseRequest(tunnelID, reason string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeCloseRequest,
		CloseRequest: &CloseRequest{
			TunnelID: tunnelID,
			Reason:   reason,
		},
	}
}

// NewCloseResponse creates a new close response message.
func NewCloseResponse(success bool) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeCloseResponse,
		CloseResponse: &CloseResponse{
			Success: success,
		},
	}
}
