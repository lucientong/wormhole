// Package proto provides control protocol definitions for Wormhole.
//
// Hand-written structs are the canonical types used throughout the codebase.
// Serialization uses Protocol Buffers (v2) with automatic JSON fallback for
// backward compatibility with older peers.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/lucientong/wormhole/pkg/proto/pb"
	"google.golang.org/protobuf/proto"
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
	LocalPort  uint32   `json:"local_port"`
	Protocol   Protocol `json:"protocol"`
	Subdomain  string   `json:"subdomain,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
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
	// PublicKey is the sender's ECDH X25519 public key (base64-encoded).
	PublicKey string `json:"public_key,omitempty"`
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
	// PeerPublicKey is the peer's ECDH X25519 public key (base64-encoded).
	PeerPublicKey string `json:"peer_public_key,omitempty"`
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

// Encode serializes a control message to protobuf bytes.
func (m *ControlMessage) Encode() ([]byte, error) {
	return proto.Marshal(m.toProtobuf())
}

// EncodeJSON serializes a control message to JSON bytes (for backward compatibility).
func (m *ControlMessage) EncodeJSON() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeControlMessage deserializes a control message from bytes.
// It first tries protobuf decoding; if that fails, it falls back to JSON.
func DecodeControlMessage(data []byte) (*ControlMessage, error) {
	// Try protobuf first.
	pbMsg := &pb.ControlMessage{}
	if err := proto.Unmarshal(data, pbMsg); err == nil {
		// Validate: a successfully parsed protobuf message should have a known
		// type or at least not be empty. We accept type == 0 (UNKNOWN) because
		// protobuf zero-values are valid; the real check is that Unmarshal
		// didn't return an error.
		return fromProtobuf(pbMsg), nil
	}

	// Fallback to JSON for backward compatibility with v1 peers.
	var m ControlMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DecodeControlMessageJSON deserializes a control message from JSON bytes only.
func DecodeControlMessageJSON(data []byte) (*ControlMessage, error) {
	var m ControlMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ---------------------------------------------------------------------------
// Length-prefixed framing for mixed streams (control message + raw data).
//
// Wire format: [4-byte big-endian length][protobuf payload]
// This allows the reader to know exactly where the control message ends
// so that subsequent raw data (e.g. HTTP request) can be read correctly.
// ---------------------------------------------------------------------------

// maxControlMessageSize limits the size of a single control message (1 MB).
const maxControlMessageSize = 1 << 20

// WriteControlMessage writes a length-prefixed control message to w.
func WriteControlMessage(w io.Writer, m *ControlMessage) error {
	data, err := m.Encode()
	if err != nil {
		return fmt.Errorf("encode control message: %w", err)
	}
	// Write 4-byte big-endian length header.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write length header: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// ReadControlMessage reads a length-prefixed control message from r.
func ReadControlMessage(r io.Reader) (*ControlMessage, error) {
	// Read 4-byte length header.
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read length header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > maxControlMessageSize {
		return nil, fmt.Errorf("control message too large: %d bytes", length)
	}
	// Read exactly length bytes.
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return DecodeControlMessage(payload)
}

// ---------------------------------------------------------------------------
// Protobuf ↔ Hand-written struct conversion (adapter layer)
// ---------------------------------------------------------------------------

// toProtobuf converts the hand-written ControlMessage to the generated pb type.
func (m *ControlMessage) toProtobuf() *pb.ControlMessage {
	pbMsg := &pb.ControlMessage{
		Type:     pb.MessageType(m.Type),
		Sequence: m.Sequence,
	}
	m.setSessionPayload(pbMsg)
	m.setP2PPayload(pbMsg)
	return pbMsg
}

// setSessionPayload fills session/tunnel-related oneof payload in pbMsg.
func (m *ControlMessage) setSessionPayload(pbMsg *pb.ControlMessage) {
	switch {
	case m.AuthRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_AuthRequest{AuthRequest: authRequestToProto(m.AuthRequest)}
	case m.AuthResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_AuthResponse{AuthResponse: authResponseToProto(m.AuthResponse)}
	case m.RegisterRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_RegisterRequest{RegisterRequest: registerRequestToProto(m.RegisterRequest)}
	case m.RegisterResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_RegisterResponse{RegisterResponse: registerResponseToProto(m.RegisterResponse)}
	case m.PingRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_PingRequest{PingRequest: pingRequestToProto(m.PingRequest)}
	case m.PingResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_PingResponse{PingResponse: pingResponseToProto(m.PingResponse)}
	case m.StreamRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_StreamRequest{StreamRequest: streamRequestToProto(m.StreamRequest)}
	case m.StreamResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_StreamResponse{StreamResponse: streamResponseToProto(m.StreamResponse)}
	case m.StatsRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_StatsRequest{StatsRequest: statsRequestToProto(m.StatsRequest)}
	case m.StatsResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_StatsResponse{StatsResponse: statsResponseToProto(m.StatsResponse)}
	case m.CloseRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_CloseRequest{CloseRequest: closeRequestToProto(m.CloseRequest)}
	case m.CloseResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_CloseResponse{CloseResponse: closeResponseToProto(m.CloseResponse)}
	}
}

// setP2PPayload fills P2P-related oneof payload in pbMsg.
func (m *ControlMessage) setP2PPayload(pbMsg *pb.ControlMessage) {
	switch {
	case m.P2POfferRequest != nil:
		pbMsg.Payload = &pb.ControlMessage_P2POfferRequest{P2POfferRequest: p2pOfferRequestToProto(m.P2POfferRequest)}
	case m.P2POfferResponse != nil:
		pbMsg.Payload = &pb.ControlMessage_P2POfferResponse{P2POfferResponse: p2pOfferResponseToProto(m.P2POfferResponse)}
	case m.P2PCandidates != nil:
		pbMsg.Payload = &pb.ControlMessage_P2PCandidates{P2PCandidates: p2pCandidatesToProto(m.P2PCandidates)}
	case m.P2PResult != nil:
		pbMsg.Payload = &pb.ControlMessage_P2PResult{P2PResult: p2pResultToProto(m.P2PResult)}
	}
}

// fromProtobuf converts the generated pb ControlMessage back to the hand-written type.
func fromProtobuf(pbMsg *pb.ControlMessage) *ControlMessage {
	m := &ControlMessage{
		Type:     MessageType(pbMsg.Type),
		Sequence: pbMsg.Sequence,
	}
	fromProtobufSession(m, pbMsg.Payload)
	fromProtobufP2P(m, pbMsg.Payload)
	return m
}

// fromProtobufSession fills session/tunnel payload fields from a pb oneof value.
func fromProtobufSession(m *ControlMessage, p interface{}) {
	switch v := p.(type) {
	case *pb.ControlMessage_AuthRequest:
		m.AuthRequest = authRequestFromProto(v.AuthRequest)
	case *pb.ControlMessage_AuthResponse:
		m.AuthResponse = authResponseFromProto(v.AuthResponse)
	case *pb.ControlMessage_RegisterRequest:
		m.RegisterRequest = registerRequestFromProto(v.RegisterRequest)
	case *pb.ControlMessage_RegisterResponse:
		m.RegisterResponse = registerResponseFromProto(v.RegisterResponse)
	case *pb.ControlMessage_PingRequest:
		m.PingRequest = pingRequestFromProto(v.PingRequest)
	case *pb.ControlMessage_PingResponse:
		m.PingResponse = pingResponseFromProto(v.PingResponse)
	case *pb.ControlMessage_StreamRequest:
		m.StreamRequest = streamRequestFromProto(v.StreamRequest)
	case *pb.ControlMessage_StreamResponse:
		m.StreamResponse = streamResponseFromProto(v.StreamResponse)
	case *pb.ControlMessage_StatsRequest:
		m.StatsRequest = statsRequestFromProto(v.StatsRequest)
	case *pb.ControlMessage_StatsResponse:
		m.StatsResponse = statsResponseFromProto(v.StatsResponse)
	case *pb.ControlMessage_CloseRequest:
		m.CloseRequest = closeRequestFromProto(v.CloseRequest)
	case *pb.ControlMessage_CloseResponse:
		m.CloseResponse = closeResponseFromProto(v.CloseResponse)
	}
}

// fromProtobufP2P fills P2P payload fields from a pb oneof value.
func fromProtobufP2P(m *ControlMessage, p interface{}) {
	switch v := p.(type) {
	case *pb.ControlMessage_P2POfferRequest:
		m.P2POfferRequest = p2pOfferRequestFromProto(v.P2POfferRequest)
	case *pb.ControlMessage_P2POfferResponse:
		m.P2POfferResponse = p2pOfferResponseFromProto(v.P2POfferResponse)
	case *pb.ControlMessage_P2PCandidates:
		m.P2PCandidates = p2pCandidatesFromProto(v.P2PCandidates)
	case *pb.ControlMessage_P2PResult:
		m.P2PResult = p2pResultFromProto(v.P2PResult)
	}
}

// ---------------------------------------------------------------------------
// Per-message conversion helpers (hand-written → pb)
// ---------------------------------------------------------------------------

func authRequestToProto(a *AuthRequest) *pb.AuthRequest {
	return &pb.AuthRequest{
		Token:        a.Token,
		Version:      a.Version,
		Subdomain:    a.Subdomain,
		Capabilities: a.Capabilities,
	}
}

func authResponseToProto(a *AuthResponse) *pb.AuthResponse {
	return &pb.AuthResponse{
		Success:      a.Success,
		Error:        a.Error,
		Subdomain:    a.Subdomain,
		PublicUrl:    a.PublicURL,
		TcpPort:      a.TCPPort,
		Capabilities: a.Capabilities,
		SessionId:    a.SessionID,
	}
}

func registerRequestToProto(r *RegisterRequest) *pb.RegisterRequest {
	return &pb.RegisterRequest{
		LocalPort:  r.LocalPort,
		Protocol:   pb.Protocol(r.Protocol),
		Subdomain:  r.Subdomain,
		Hostname:   r.Hostname,
		PathPrefix: r.PathPrefix,
	}
}

func registerResponseToProto(r *RegisterResponse) *pb.RegisterResponse {
	return &pb.RegisterResponse{
		Success:   r.Success,
		Error:     r.Error,
		TunnelId:  r.TunnelID,
		PublicUrl: r.PublicURL,
		TcpPort:   r.TCPPort,
	}
}

func pingRequestToProto(p *PingRequest) *pb.PingRequest {
	return &pb.PingRequest{
		PingId:    p.PingID,
		Timestamp: p.Timestamp,
	}
}

func pingResponseToProto(p *PingResponse) *pb.PingResponse {
	return &pb.PingResponse{
		PingId:    p.PingID,
		Timestamp: p.Timestamp,
	}
}

func streamRequestToProto(s *StreamRequest) *pb.StreamRequest {
	pbReq := &pb.StreamRequest{
		TunnelId:   s.TunnelID,
		RequestId:  s.RequestID,
		RemoteAddr: s.RemoteAddr,
		Protocol:   pb.Protocol(s.Protocol),
	}
	if s.HTTPMetadata != nil {
		pbReq.HttpMetadata = &pb.HttpMetadata{
			Method:        s.HTTPMetadata.Method,
			Uri:           s.HTTPMetadata.URI,
			Host:          s.HTTPMetadata.Host,
			ContentType:   s.HTTPMetadata.ContentType,
			ContentLength: s.HTTPMetadata.ContentLength,
		}
	}
	return pbReq
}

func streamResponseToProto(s *StreamResponse) *pb.StreamResponse {
	return &pb.StreamResponse{
		RequestId: s.RequestID,
		Accepted:  s.Accepted,
		Error:     s.Error,
	}
}

func statsRequestToProto(s *StatsRequest) *pb.StatsRequest {
	return &pb.StatsRequest{
		SessionId: s.SessionID,
	}
}

func statsResponseToProto(s *StatsResponse) *pb.StatsResponse {
	return &pb.StatsResponse{
		ActiveTunnels:     s.ActiveTunnels,
		ActiveConnections: s.ActiveConnections,
		BytesSent:         s.BytesSent,
		BytesReceived:     s.BytesReceived,
		RequestsHandled:   s.RequestsHandled,
		UptimeSeconds:     s.UptimeSeconds,
	}
}

func closeRequestToProto(c *CloseRequest) *pb.CloseRequest {
	return &pb.CloseRequest{
		TunnelId: c.TunnelID,
		Reason:   c.Reason,
	}
}

func closeResponseToProto(c *CloseResponse) *pb.CloseResponse {
	return &pb.CloseResponse{
		Success: c.Success,
	}
}

func p2pOfferRequestToProto(p *P2POfferRequest) *pb.P2POfferRequest {
	return &pb.P2POfferRequest{
		TunnelId:   p.TunnelID,
		NatType:    p.NATType,
		PublicAddr: p.PublicAddr,
		LocalAddr:  p.LocalAddr,
		PublicKey:  p.PublicKey,
	}
}

func p2pOfferResponseToProto(p *P2POfferResponse) *pb.P2POfferResponse {
	return &pb.P2POfferResponse{
		Success:       p.Success,
		Error:         p.Error,
		PeerAddr:      p.PeerAddr,
		PeerNatType:   p.PeerNATType,
		PeerPublicKey: p.PeerPublicKey,
	}
}

func p2pCandidatesToProto(p *P2PCandidates) *pb.P2PCandidates {
	return &pb.P2PCandidates{
		TunnelId:   p.TunnelID,
		Candidates: p.Candidates,
	}
}

func p2pResultToProto(p *P2PResult) *pb.P2PResult {
	return &pb.P2PResult{
		TunnelId: p.TunnelID,
		Success:  p.Success,
		PeerAddr: p.PeerAddr,
		Error:    p.Error,
	}
}

// ---------------------------------------------------------------------------
// Per-message conversion helpers (pb → hand-written)
// ---------------------------------------------------------------------------

func authRequestFromProto(a *pb.AuthRequest) *AuthRequest {
	if a == nil {
		return nil
	}
	return &AuthRequest{
		Token:        a.Token,
		Version:      a.Version,
		Subdomain:    a.Subdomain,
		Capabilities: a.Capabilities,
	}
}

func authResponseFromProto(a *pb.AuthResponse) *AuthResponse {
	if a == nil {
		return nil
	}
	return &AuthResponse{
		Success:      a.Success,
		Error:        a.Error,
		Subdomain:    a.Subdomain,
		PublicURL:    a.PublicUrl,
		TCPPort:      a.TcpPort,
		Capabilities: a.Capabilities,
		SessionID:    a.SessionId,
	}
}

func registerRequestFromProto(r *pb.RegisterRequest) *RegisterRequest {
	if r == nil {
		return nil
	}
	return &RegisterRequest{
		LocalPort:  r.LocalPort,
		Protocol:   Protocol(r.Protocol),
		Subdomain:  r.Subdomain,
		Hostname:   r.Hostname,
		PathPrefix: r.PathPrefix,
	}
}

func registerResponseFromProto(r *pb.RegisterResponse) *RegisterResponse {
	if r == nil {
		return nil
	}
	return &RegisterResponse{
		Success:   r.Success,
		Error:     r.Error,
		TunnelID:  r.TunnelId,
		PublicURL: r.PublicUrl,
		TCPPort:   r.TcpPort,
	}
}

func pingRequestFromProto(p *pb.PingRequest) *PingRequest {
	if p == nil {
		return nil
	}
	return &PingRequest{
		PingID:    p.PingId,
		Timestamp: p.Timestamp,
	}
}

func pingResponseFromProto(p *pb.PingResponse) *PingResponse {
	if p == nil {
		return nil
	}
	return &PingResponse{
		PingID:    p.PingId,
		Timestamp: p.Timestamp,
	}
}

func streamRequestFromProto(s *pb.StreamRequest) *StreamRequest {
	if s == nil {
		return nil
	}
	req := &StreamRequest{
		TunnelID:   s.TunnelId,
		RequestID:  s.RequestId,
		RemoteAddr: s.RemoteAddr,
		Protocol:   Protocol(s.Protocol),
	}
	if s.HttpMetadata != nil {
		req.HTTPMetadata = &HTTPMetadata{
			Method:        s.HttpMetadata.Method,
			URI:           s.HttpMetadata.Uri,
			Host:          s.HttpMetadata.Host,
			ContentType:   s.HttpMetadata.ContentType,
			ContentLength: s.HttpMetadata.ContentLength,
		}
	}
	return req
}

func streamResponseFromProto(s *pb.StreamResponse) *StreamResponse {
	if s == nil {
		return nil
	}
	return &StreamResponse{
		RequestID: s.RequestId,
		Accepted:  s.Accepted,
		Error:     s.Error,
	}
}

func statsRequestFromProto(s *pb.StatsRequest) *StatsRequest {
	if s == nil {
		return nil
	}
	return &StatsRequest{
		SessionID: s.SessionId,
	}
}

func statsResponseFromProto(s *pb.StatsResponse) *StatsResponse {
	if s == nil {
		return nil
	}
	return &StatsResponse{
		ActiveTunnels:     s.ActiveTunnels,
		ActiveConnections: s.ActiveConnections,
		BytesSent:         s.BytesSent,
		BytesReceived:     s.BytesReceived,
		RequestsHandled:   s.RequestsHandled,
		UptimeSeconds:     s.UptimeSeconds,
	}
}

func closeRequestFromProto(c *pb.CloseRequest) *CloseRequest {
	if c == nil {
		return nil
	}
	return &CloseRequest{
		TunnelID: c.TunnelId,
		Reason:   c.Reason,
	}
}

func closeResponseFromProto(c *pb.CloseResponse) *CloseResponse {
	if c == nil {
		return nil
	}
	return &CloseResponse{
		Success: c.Success,
	}
}

func p2pOfferRequestFromProto(p *pb.P2POfferRequest) *P2POfferRequest {
	if p == nil {
		return nil
	}
	return &P2POfferRequest{
		TunnelID:   p.TunnelId,
		NATType:    p.NatType,
		PublicAddr: p.PublicAddr,
		LocalAddr:  p.LocalAddr,
		PublicKey:  p.PublicKey,
	}
}

func p2pOfferResponseFromProto(p *pb.P2POfferResponse) *P2POfferResponse {
	if p == nil {
		return nil
	}
	return &P2POfferResponse{
		Success:       p.Success,
		Error:         p.Error,
		PeerAddr:      p.PeerAddr,
		PeerNATType:   p.PeerNatType,
		PeerPublicKey: p.PeerPublicKey,
	}
}

func p2pCandidatesFromProto(p *pb.P2PCandidates) *P2PCandidates {
	if p == nil {
		return nil
	}
	return &P2PCandidates{
		TunnelID:   p.TunnelId,
		Candidates: p.Candidates,
	}
}

func p2pResultFromProto(p *pb.P2PResult) *P2PResult {
	if p == nil {
		return nil
	}
	return &P2PResult{
		TunnelID: p.TunnelId,
		Success:  p.Success,
		PeerAddr: p.PeerAddr,
		Error:    p.Error,
	}
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
func NewRegisterRequest(localPort uint32, protocol Protocol, subdomain, hostname, pathPrefix string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeRegisterRequest,
		RegisterRequest: &RegisterRequest{
			LocalPort:  localPort,
			Protocol:   protocol,
			Subdomain:  subdomain,
			Hostname:   hostname,
			PathPrefix: pathPrefix,
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

// NewStatsRequest creates a new stats request message.
func NewStatsRequest(sessionID string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeStatsRequest,
		StatsRequest: &StatsRequest{
			SessionID: sessionID,
		},
	}
}

// NewStatsResponse creates a new stats response message.
func NewStatsResponse(activeTunnels, activeConnections uint32, bytesSent, bytesReceived, requestsHandled, uptimeSeconds uint64) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeStatsResponse,
		StatsResponse: &StatsResponse{
			ActiveTunnels:     activeTunnels,
			ActiveConnections: activeConnections,
			BytesSent:         bytesSent,
			BytesReceived:     bytesReceived,
			RequestsHandled:   requestsHandled,
			UptimeSeconds:     uptimeSeconds,
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
func NewP2POfferRequest(tunnelID, natType, publicAddr, localAddr, publicKey string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeP2POfferRequest,
		P2POfferRequest: &P2POfferRequest{
			TunnelID:   tunnelID,
			NATType:    natType,
			PublicAddr: publicAddr,
			LocalAddr:  localAddr,
			PublicKey:  publicKey,
		},
	}
}

// NewP2POfferResponse creates a P2P offer response message.
func NewP2POfferResponse(success bool, err, peerAddr, peerNATType, peerPublicKey string) *ControlMessage {
	return &ControlMessage{
		Type: MessageTypeP2POfferResponse,
		P2POfferResponse: &P2POfferResponse{
			Success:       success,
			Error:         err,
			PeerAddr:      peerAddr,
			PeerNATType:   peerNATType,
			PeerPublicKey: peerPublicKey,
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
