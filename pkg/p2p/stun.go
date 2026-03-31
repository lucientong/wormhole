package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
)

// STUN protocol constants (RFC 5389).
const (
	stunMagicCookie  = 0x2112A442
	stunHeaderSize   = 20
	stunBindingReq   = 0x0001
	stunBindingResp  = 0x0101
	stunBindingError = 0x0111

	// Attribute types.
	stunAttrMappedAddress    = 0x0001
	stunAttrXORMappedAddress = 0x0020

	// Address families.
	stunIPv4 = 0x01
	stunIPv6 = 0x02
)

// Default STUN servers to use for NAT discovery.
var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
	"stun3.l.google.com:19302",
}

// STUNConfig holds STUN client configuration.
type STUNConfig struct {
	// Servers is a list of STUN server addresses.
	Servers []string
	// Timeout is the deadline for each STUN request.
	Timeout time.Duration
	// Retries is the number of retry attempts per server.
	Retries int
}

// DefaultSTUNConfig returns sensible defaults for STUN discovery.
func DefaultSTUNConfig() STUNConfig {
	return STUNConfig{
		Servers: defaultSTUNServers,
		Timeout: 3 * time.Second,
		Retries: 2,
	}
}

// STUNClient performs STUN binding requests to discover the public endpoint.
type STUNClient struct {
	config STUNConfig
}

// NewSTUNClient creates a new STUN client.
func NewSTUNClient(config STUNConfig) *STUNClient {
	if len(config.Servers) == 0 {
		config.Servers = defaultSTUNServers
	}
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}
	if config.Retries == 0 {
		config.Retries = 2
	}
	return &STUNClient{config: config}
}

// Discover performs NAT discovery by querying STUN servers.
// It returns the detected NAT type and public endpoint.
func (s *STUNClient) Discover(ctx context.Context) (*NATInfo, error) {
	if len(s.config.Servers) < 2 {
		return nil, fmt.Errorf("at least 2 STUN servers required for NAT detection")
	}

	// Phase 1: Binding request to first server.
	addr1, localAddr1, err := s.bindingRequest(ctx, s.config.Servers[0])
	if err != nil {
		return nil, fmt.Errorf("STUN binding to %s: %w", s.config.Servers[0], err)
	}

	log.Debug().
		Str("server", s.config.Servers[0]).
		Str("public", addr1.String()).
		Str("local", localAddr1.String()).
		Msg("STUN binding result 1")

	// Phase 2: Binding request to second server (from same local port).
	addr2, _, err := s.bindingRequestFromPort(ctx, s.config.Servers[1], localAddr1.Port)
	if err != nil {
		// Second server failed — we still know the public address from server 1.
		log.Debug().Err(err).Str("server", s.config.Servers[1]).Msg("Second STUN server failed")
		return &NATInfo{
			Type:       NATUnknown,
			PublicAddr: *addr1,
			LocalAddr:  *localAddr1,
		}, nil
	}

	log.Debug().
		Str("server", s.config.Servers[1]).
		Str("public", addr2.String()).
		Msg("STUN binding result 2")

	// Classify NAT type based on results.
	natType := classifyNAT(localAddr1, addr1, addr2)

	return &NATInfo{
		Type:       natType,
		PublicAddr: *addr1,
		LocalAddr:  *localAddr1,
	}, nil
}

// DiscoverEndpoint performs a simple STUN binding request to get the public endpoint.
// This is faster than full Discover() and sufficient when NAT type is not needed.
func (s *STUNClient) DiscoverEndpoint(ctx context.Context) (*Endpoint, error) {
	for _, server := range s.config.Servers {
		addr, _, err := s.bindingRequest(ctx, server)
		if err != nil {
			log.Debug().Err(err).Str("server", server).Msg("STUN server failed, trying next")
			continue
		}
		return addr, nil
	}
	return nil, fmt.Errorf("all STUN servers failed")
}

// bindingRequest sends a STUN binding request and returns the mapped address.
func (s *STUNClient) bindingRequest(ctx context.Context, server string) (*Endpoint, *Endpoint, error) {
	// Resolve STUN server address.
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve %s: %w", server, err)
	}

	// Create UDP connection.
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	local := &Endpoint{IP: localAddr.IP.String(), Port: localAddr.Port}

	mapped, err := s.doBinding(ctx, conn, serverAddr)
	if err != nil {
		return nil, nil, err
	}

	return mapped, local, nil
}

// bindingRequestFromPort sends a STUN binding request from a specific local port.
func (s *STUNClient) bindingRequestFromPort(ctx context.Context, server string, localPort int) (*Endpoint, *Endpoint, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve %s: %w", server, err)
	}

	listenAddr := net.JoinHostPort("", fmt.Sprintf("%d", localPort))
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp4", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen udp on port %d: %w", localPort, err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	local := &Endpoint{IP: localAddr.IP.String(), Port: localAddr.Port}

	mapped, err := s.doBinding(ctx, conn, serverAddr)
	if err != nil {
		return nil, nil, err
	}

	return mapped, local, nil
}

// doBinding performs the actual STUN binding request with retries.
func (s *STUNClient) doBinding(ctx context.Context, conn net.PacketConn, server *net.UDPAddr) (*Endpoint, error) {
	txID := newTransactionID()
	req := buildBindingRequest(txID)

	for attempt := 0; attempt <= s.config.Retries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Set deadline.
		deadline := time.Now().Add(s.config.Timeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}

		// Send request.
		if _, err := conn.WriteTo(req, server); err != nil {
			continue
		}

		// Read response.
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		// Parse response.
		mapped, parseErr := parseBindingResponse(buf[:n], txID)
		if parseErr != nil {
			continue
		}

		return mapped, nil
	}

	return nil, fmt.Errorf("STUN binding failed after %d attempts", s.config.Retries+1)
}

// classifyNAT determines the NAT type based on two STUN binding results.
func classifyNAT(local, mapped1, mapped2 *Endpoint) NATType {
	// If local == mapped, we have a public IP (no NAT).
	if local.Port == mapped1.Port && isPublicIP(local.IP) {
		return NATNone
	}

	// If both servers see the same mapped address → Cone NAT.
	if mapped1.IP == mapped2.IP && mapped1.Port == mapped2.Port {
		// Same external endpoint for different destinations → Full/Restricted Cone.
		// We cannot distinguish between Full Cone, Restricted Cone, and Port Restricted
		// with only two servers (would need controlled port change). Default to
		// Port Restricted as a conservative estimate.
		return NATPortRestricted
	}

	// Different mapped addresses → Symmetric NAT.
	return NATSymmetric
}

// isPublicIP returns true if the IP is a public (non-private) address.
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Check private ranges.
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
	}

	ip = ip.To4()
	if ip == nil {
		return false
	}

	for _, r := range privateRanges {
		if bytesInRange(ip, r.start.To4(), r.end.To4()) {
			return false
		}
	}
	return true
}

// bytesInRange checks if ip is between start and end (inclusive).
func bytesInRange(ip, start, end net.IP) bool {
	for i := 0; i < 4; i++ {
		if ip[i] < start[i] {
			return false
		}
		if ip[i] > end[i] {
			return false
		}
	}
	return true
}

// STUN message building and parsing.

// newTransactionID generates a random 12-byte transaction ID.
func newTransactionID() [12]byte {
	var id [12]byte
	rand.Read(id[:])
	return id
}

// buildBindingRequest creates a STUN Binding Request message.
func buildBindingRequest(txID [12]byte) []byte {
	msg := make([]byte, stunHeaderSize)

	// Message Type: Binding Request (0x0001).
	binary.BigEndian.PutUint16(msg[0:2], stunBindingReq)
	// Message Length: 0 (no attributes).
	binary.BigEndian.PutUint16(msg[2:4], 0)
	// Magic Cookie.
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	// Transaction ID.
	copy(msg[8:20], txID[:])

	return msg
}

// parseBindingResponse parses a STUN Binding Response and extracts the mapped address.
func parseBindingResponse(data []byte, expectedTxID [12]byte) (*Endpoint, error) {
	if len(data) < stunHeaderSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Verify message type.
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType == stunBindingError {
		return nil, fmt.Errorf("STUN binding error response")
	}
	if msgType != stunBindingResp {
		return nil, fmt.Errorf("unexpected message type: 0x%04x", msgType)
	}

	// Verify magic cookie.
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: 0x%08x", cookie)
	}

	// Verify transaction ID.
	var txID [12]byte
	copy(txID[:], data[8:20])
	if txID != expectedTxID {
		return nil, fmt.Errorf("transaction ID mismatch")
	}

	// Parse attributes.
	msgLen := binary.BigEndian.Uint16(data[2:4])
	attrs := data[stunHeaderSize:]
	if int(msgLen) > len(attrs) {
		return nil, fmt.Errorf("truncated message: declared %d, have %d", msgLen, len(attrs))
	}

	return extractMappedAddress(attrs[:msgLen])
}

// extractMappedAddress iterates STUN attributes and returns the first mapped address found.
// It prefers XOR-MAPPED-ADDRESS over MAPPED-ADDRESS.
func extractMappedAddress(attrs []byte) (*Endpoint, error) {
	var mapped *Endpoint
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := binary.BigEndian.Uint16(attrs[2:4])

		if int(attrLen)+4 > len(attrs) {
			break
		}

		attrValue := attrs[4 : 4+attrLen]

		switch attrType {
		case stunAttrXORMappedAddress:
			ep, err := parseXORMappedAddress(attrValue)
			if err == nil {
				return ep, nil // Preferred.
			}
		case stunAttrMappedAddress:
			ep, err := parseMappedAddress(attrValue)
			if err == nil {
				mapped = ep // Fallback.
			}
		}

		// Advance to next attribute (4-byte aligned).
		advance := 4 + int(attrLen)
		if advance%4 != 0 {
			advance += 4 - (advance % 4)
		}
		if advance > len(attrs) {
			break
		}
		attrs = attrs[advance:]
	}

	if mapped != nil {
		return mapped, nil
	}

	return nil, fmt.Errorf("no mapped address in response")
}

// parseXORMappedAddress decodes an XOR-MAPPED-ADDRESS attribute.
func parseXORMappedAddress(data []byte) (*Endpoint, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("XOR-MAPPED-ADDRESS too short")
	}

	family := data[1]
	xorPort := binary.BigEndian.Uint16(data[2:4])
	port := xorPort ^ uint16(stunMagicCookie>>16)

	switch family {
	case stunIPv4:
		if len(data) < 8 {
			return nil, fmt.Errorf("IPv4 address too short")
		}
		xorIP := binary.BigEndian.Uint32(data[4:8])
		ip := xorIP ^ stunMagicCookie
		ipBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ipBytes, ip)
		return &Endpoint{
			IP:   net.IP(ipBytes).String(),
			Port: int(port),
		}, nil
	case stunIPv6:
		return nil, fmt.Errorf("IPv6 not yet supported")
	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
}

// parseMappedAddress decodes a MAPPED-ADDRESS attribute.
func parseMappedAddress(data []byte) (*Endpoint, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("MAPPED-ADDRESS too short")
	}

	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])

	switch family {
	case stunIPv4:
		ip := net.IP(data[4:8])
		return &Endpoint{
			IP:   ip.String(),
			Port: int(port),
		}, nil
	case stunIPv6:
		return nil, fmt.Errorf("IPv6 not yet supported")
	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
}
