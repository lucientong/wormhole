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
	MessageTypeP2POfferRequest  MessageType = 13
	MessageTypeP2POfferResponse MessageType = 14
	MessageTypeP2PCandidates    MessageType = 15
	MessageTypeP2PResult        MessageType = 16
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

// P2POfferRequest is sent by a client to initiate a P2P connection.
type P2POfferRequest struct {
	// TunnelID identifies the tunnel wanting P2P.
	TunnelID string `json:"tunnel_id"`
	// NATType is the sender's detected NAT type.
	NATType string `json:"nat_type"`
	// PublicAddr is the sender's public endpoint as discovered by STUN.
	PublicAddr string `json:"public_addr"`
	// LocalAddr is the sender's local endpoint.
	LocalAddr string `json:"local_addr,omitempty"`
}

// P2POfferResponse is the server's response to a P2P offer.
type P2POfferResponse struct {
	// Success indicates whether a peer was found.
	Success bool `json:"success"`
	// Error contains a reason if the offer was rejected.
	Error string `json:"error,omitempty"`
	// PeerAddr is the peer's public endpoint.
	PeerAddr string `json:"peer_addr,omitempty"`
	// PeerNATType is the peer's NAT type.
	PeerNATType string `json:"peer_nat_type,omitempty"`
}

// P2PCandidates carries additional candidate endpoints for hole punching.
type P2PCandidates struct {
	// TunnelID identifies the tunnel.
	TunnelID string `json:"tunnel_id"`
	// Candidates is a list of candidate endpoints.
	Candidates []string `json:"candidates"`
}

// P2PResult reports the outcome of a P2P connection attempt.
type P2PResult struct {
	// TunnelID identifies the tunnel.
	TunnelID string `json:"tunnel_id"`
	// Success indicates whether P2P was established.
	Success bool `json:"success"`
	// PeerAddr is the confirmed peer address (if successful).
	PeerAddr string `json:"peer_addr,omitempty"`
	// Error contains a reason if P2P failed.
	Error string `json:"error,omitempty"`
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
	P2POfferRequest  *P2POfferRequest  `json:"p2p_offer_request,omitempty"`
	P2POfferResponse *P2POfferResponse `json:"p2p_offer_response,omitempty"`
	P2PCandidates    *P2PCandidates    `json:"p2p_candidates,omitempty"`
	P2PResult        *P2PResult        `json:"p2p_result,omitempty"`
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

// NewP2POfferRequest creates a P2P offer request message.
func NewP2POfferRequest(tunnelID, natType, publicAddr, localAddr string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeP2POfferRequest,
		P2POfferRequest: &P2POfferRequest{
			TunnelID:   tunnelID,
			NATType:    natType,
			PublicAddr: publicAddr,
			LocalAddr:  localAddr,
		},
	}
}

// NewP2POfferResponse creates a P2P offer response message.
func NewP2POfferResponse(success bool, err, peerAddr, peerNATType string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeP2POfferResponse,
		P2POfferResponse: &P2POfferResponse{
			Success:     success,
			Error:       err,
			PeerAddr:    peerAddr,
			PeerNATType: peerNATType,
		},
	}
}

// NewP2PCandidates creates a P2P candidates message.
func NewP2PCandidates(tunnelID string, candidates []string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeP2PCandidates,
		P2PCandidates: &P2PCandidates{
			TunnelID:   tunnelID,
			Candidates: candidates,
		},
	}
}

// NewP2PResult creates a P2P result message.
func NewP2PResult(tunnelID string, success bool, peerAddr, err string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeP2PResult,
		P2PResult: &P2PResult{
			TunnelID: tunnelID,
			Success:  success,
			PeerAddr: peerAddr,
			Error:    err,
		},
	}
}
