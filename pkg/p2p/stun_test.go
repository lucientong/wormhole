package p2p

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNATType_String(t *testing.T) {
	tests := []struct {
		nat  NATType
		want string
	}{
		{NATUnknown, "Unknown"},
		{NATNone, "None (Public IP)"},
		{NATFullCone, "Full Cone"},
		{NATRestrictedCone, "Restricted Cone"},
		{NATPortRestricted, "Port Restricted Cone"},
		{NATSymmetric, "Symmetric"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.nat.String())
	}
}

func TestNATType_IsTraversable(t *testing.T) {
	assert.True(t, NATNone.IsTraversable())
	assert.True(t, NATFullCone.IsTraversable())
	assert.True(t, NATRestrictedCone.IsTraversable())
	assert.True(t, NATPortRestricted.IsTraversable())
	assert.False(t, NATSymmetric.IsTraversable())
	assert.False(t, NATUnknown.IsTraversable())
}

func TestEndpoint_String(t *testing.T) {
	ep := Endpoint{IP: "1.2.3.4", Port: 5678}
	assert.Equal(t, "1.2.3.4:5678", ep.String())
}

func TestEndpoint_String_IPv6(t *testing.T) {
	ep := Endpoint{IP: "2001:db8::1", Port: 443}
	assert.Equal(t, "[2001:db8::1]:443", ep.String())

	ep2 := Endpoint{IP: "::1", Port: 8080}
	assert.Equal(t, "[::1]:8080", ep2.String())
}

func TestBuildAndParseBindingRequest(t *testing.T) {
	txID := newTransactionID()
	req := buildBindingRequest(txID)

	assert.Len(t, req, stunHeaderSize)

	// Verify message type.
	msgType := binary.BigEndian.Uint16(req[0:2])
	assert.Equal(t, uint16(stunBindingReq), msgType)

	// Verify message length.
	msgLen := binary.BigEndian.Uint16(req[2:4])
	assert.Equal(t, uint16(0), msgLen)

	// Verify magic cookie.
	cookie := binary.BigEndian.Uint32(req[4:8])
	assert.Equal(t, uint32(stunMagicCookie), cookie)

	// Verify transaction ID.
	var parsedTxID [12]byte
	copy(parsedTxID[:], req[8:20])
	assert.Equal(t, txID, parsedTxID)
}

func TestParseXORMappedAddress(t *testing.T) {
	// Build a valid XOR-MAPPED-ADDRESS for 192.0.2.1:32853.
	// XOR port: 32853 ^ (0x2112A442 >> 16) = 32853 ^ 0x2112 = 0xA15F
	// XOR IP: 192.0.2.1 ^ 0x2112A442
	ip := net.ParseIP("192.0.2.1").To4()
	port := uint16(32853)

	data := make([]byte, 8)
	data[0] = 0x00     // Reserved.
	data[1] = stunIPv4 // Family.
	xorPort := port ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(data[2:4], xorPort)
	rawIP := binary.BigEndian.Uint32(ip)
	xorIP := rawIP ^ stunMagicCookie
	binary.BigEndian.PutUint32(data[4:8], xorIP)

	ep, err := parseXORMappedAddress(data, [12]byte{})
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", ep.IP)
	assert.Equal(t, 32853, ep.Port)
}

func TestParseMappedAddress(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 0x00     // Reserved.
	data[1] = stunIPv4 // Family.
	binary.BigEndian.PutUint16(data[2:4], 12345)
	copy(data[4:8], net.ParseIP("10.0.0.1").To4())

	ep, err := parseMappedAddress(data)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ep.IP)
	assert.Equal(t, 12345, ep.Port)
}

func TestParseBindingResponse(t *testing.T) {
	txID := newTransactionID()

	// Build a mock STUN binding response with XOR-MAPPED-ADDRESS.
	ip := net.ParseIP("203.0.113.5").To4()
	port := uint16(54321)

	// XOR values.
	xorPort := port ^ uint16(stunMagicCookie>>16)
	xorIP := binary.BigEndian.Uint32(ip) ^ stunMagicCookie

	// Attribute: XOR-MAPPED-ADDRESS.
	attrValue := make([]byte, 8)
	attrValue[0] = 0x00
	attrValue[1] = stunIPv4
	binary.BigEndian.PutUint16(attrValue[2:4], xorPort)
	binary.BigEndian.PutUint32(attrValue[4:8], xorIP)

	// Build full response.
	attrHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(attrHeader[0:2], stunAttrXORMappedAddress)
	binary.BigEndian.PutUint16(attrHeader[2:4], 8)

	attrs := make([]byte, 0, len(attrHeader)+len(attrValue))
	attrs = append(attrs, attrHeader...)
	attrs = append(attrs, attrValue...)

	resp := make([]byte, stunHeaderSize, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])
	resp = append(resp, attrs...)

	ep, err := parseBindingResponse(resp, txID)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.5", ep.IP)
	assert.Equal(t, 54321, ep.Port)
}

func TestParseBindingResponse_WrongTxID(t *testing.T) {
	txID := newTransactionID()
	wrongTxID := newTransactionID()

	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], 0)
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], wrongTxID[:])

	_, err := parseBindingResponse(resp, txID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction ID mismatch")
}

func TestParseBindingResponse_ErrorResponse(t *testing.T) {
	txID := newTransactionID()

	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingError)
	binary.BigEndian.PutUint16(resp[2:4], 0)
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	_, err := parseBindingResponse(resp, txID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error response")
}

func TestClassifyNAT(t *testing.T) {
	tests := []struct {
		name    string
		local   Endpoint
		mapped1 Endpoint
		mapped2 Endpoint
		want    NATType
	}{
		{
			name:    "same mapped address from different servers → cone NAT",
			local:   Endpoint{IP: "192.168.1.100", Port: 5000},
			mapped1: Endpoint{IP: "1.2.3.4", Port: 5000},
			mapped2: Endpoint{IP: "1.2.3.4", Port: 5000},
			want:    NATPortRestricted,
		},
		{
			name:    "different mapped addresses → symmetric NAT",
			local:   Endpoint{IP: "192.168.1.100", Port: 5000},
			mapped1: Endpoint{IP: "1.2.3.4", Port: 5000},
			mapped2: Endpoint{IP: "1.2.3.4", Port: 6000},
			want:    NATSymmetric,
		},
		{
			name:    "different mapped IPs → symmetric NAT",
			local:   Endpoint{IP: "192.168.1.100", Port: 5000},
			mapped1: Endpoint{IP: "1.2.3.4", Port: 5000},
			mapped2: Endpoint{IP: "5.6.7.8", Port: 5000},
			want:    NATSymmetric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyNAT(&tt.local, &tt.mapped1, &tt.mapped2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	// IPv4 tests.
	assert.False(t, isPublicIP("10.0.0.1"))
	assert.False(t, isPublicIP("172.16.0.1"))
	assert.False(t, isPublicIP("192.168.1.1"))
	assert.False(t, isPublicIP("127.0.0.1"))
	assert.True(t, isPublicIP("8.8.8.8"))
	assert.True(t, isPublicIP("1.1.1.1"))
	assert.True(t, isPublicIP("203.0.113.5"))
	assert.False(t, isPublicIP("invalid"))

	// IPv6 tests.
	assert.True(t, isPublicIP("2001:db8::1"))
	assert.False(t, isPublicIP("::1"))                // Loopback.
	assert.False(t, isPublicIP("fe80::1"))            // Link-local.
	assert.False(t, isPublicIP("fc00::1"))            // Unique local.
	assert.False(t, isPublicIP("fd12:3456:789a::1"))  // Unique local.
	assert.False(t, isPublicIP("ff02::1"))            // Multicast.
	assert.False(t, isPublicIP("::"))                 // Unspecified.
	assert.True(t, isPublicIP("2400:cb00:2049:1::1")) // Cloudflare IPv6 (public).
}

// --- extractMappedAddress tests ---

func TestExtractMappedAddress_XORPreferred(t *testing.T) {
	// Build attrs with XOR-MAPPED-ADDRESS (should be preferred).
	ip := net.ParseIP("203.0.113.10").To4()
	port := uint16(9999)

	xorPort := port ^ uint16(stunMagicCookie>>16)
	xorIP := binary.BigEndian.Uint32(ip) ^ stunMagicCookie

	xorValue := make([]byte, 8)
	xorValue[1] = stunIPv4
	binary.BigEndian.PutUint16(xorValue[2:4], xorPort)
	binary.BigEndian.PutUint32(xorValue[4:8], xorIP)

	attrs := make([]byte, 0, 4+8)
	// Attribute header: type=XOR-MAPPED-ADDRESS, length=8.
	attrs = append(attrs, 0x00, 0x20, 0x00, 0x08)
	attrs = append(attrs, xorValue...)

	ep, err := extractMappedAddress(attrs, [12]byte{})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.10", ep.IP)
	assert.Equal(t, 9999, ep.Port)
}

func TestExtractMappedAddress_MappedFallback(t *testing.T) {
	// Build attrs with only MAPPED-ADDRESS (no XOR variant).
	mappedValue := make([]byte, 8)
	mappedValue[1] = stunIPv4
	binary.BigEndian.PutUint16(mappedValue[2:4], 8080)
	copy(mappedValue[4:8], net.ParseIP("10.0.0.1").To4())

	attrs := make([]byte, 0, 4+8)
	// Attribute header: type=MAPPED-ADDRESS, length=8.
	attrs = append(attrs, 0x00, 0x01, 0x00, 0x08)
	attrs = append(attrs, mappedValue...)

	ep, err := extractMappedAddress(attrs, [12]byte{})
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ep.IP)
	assert.Equal(t, 8080, ep.Port)
}

func TestExtractMappedAddress_XORPriorityOverMapped(t *testing.T) {
	// Build attrs with MAPPED-ADDRESS first, then XOR-MAPPED-ADDRESS.
	// XOR should be returned because it takes priority.
	mappedValue := make([]byte, 8)
	mappedValue[1] = stunIPv4
	binary.BigEndian.PutUint16(mappedValue[2:4], 1111)
	copy(mappedValue[4:8], net.ParseIP("10.0.0.1").To4())

	ip := net.ParseIP("203.0.113.20").To4()
	xorPort := uint16(2222) ^ uint16(stunMagicCookie>>16)
	xorIP := binary.BigEndian.Uint32(ip) ^ stunMagicCookie

	xorValue := make([]byte, 8)
	xorValue[1] = stunIPv4
	binary.BigEndian.PutUint16(xorValue[2:4], xorPort)
	binary.BigEndian.PutUint32(xorValue[4:8], xorIP)

	attrs := make([]byte, 0, 24)
	// MAPPED-ADDRESS first.
	attrs = append(attrs, 0x00, 0x01, 0x00, 0x08)
	attrs = append(attrs, mappedValue...)
	// XOR-MAPPED-ADDRESS second.
	attrs = append(attrs, 0x00, 0x20, 0x00, 0x08)
	attrs = append(attrs, xorValue...)

	ep, err := extractMappedAddress(attrs, [12]byte{})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.20", ep.IP)
	assert.Equal(t, 2222, ep.Port)
}

func TestExtractMappedAddress_EmptyAttrs(t *testing.T) {
	_, err := extractMappedAddress([]byte{}, [12]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no mapped address")
}

func TestExtractMappedAddress_TruncatedAttribute(t *testing.T) {
	// Attribute header claims 8 bytes but only 2 bytes of value follow.
	attrs := []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}
	_, err := extractMappedAddress(attrs, [12]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no mapped address")
}

func TestExtractMappedAddress_UnknownAttributeSkipped(t *testing.T) {
	// Unknown attribute type (0x9999) followed by valid MAPPED-ADDRESS.
	// The unknown attribute should be skipped.
	unknownValue := []byte{0x01, 0x02, 0x03, 0x04}
	mappedValue := make([]byte, 8)
	mappedValue[1] = stunIPv4
	binary.BigEndian.PutUint16(mappedValue[2:4], 7777)
	copy(mappedValue[4:8], net.ParseIP("8.8.8.8").To4())

	attrs := make([]byte, 0, 20)
	// Unknown attribute: type=0x9999, length=4.
	attrs = append(attrs, 0x99, 0x99, 0x00, 0x04)
	attrs = append(attrs, unknownValue...)
	// MAPPED-ADDRESS.
	attrs = append(attrs, 0x00, 0x01, 0x00, 0x08)
	attrs = append(attrs, mappedValue...)

	ep, err := extractMappedAddress(attrs, [12]byte{})
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8", ep.IP)
	assert.Equal(t, 7777, ep.Port)
}

// --- parseXORMappedAddress error branch tests ---

func TestParseXORMappedAddress_TooShort(t *testing.T) {
	_, err := parseXORMappedAddress([]byte{0x00, 0x01, 0x00}, [12]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseXORMappedAddress_IPv6(t *testing.T) {
	// Build a valid IPv6 XOR-MAPPED-ADDRESS for 2001:db8::1 port 9999.
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	targetIP := net.ParseIP("2001:db8::1")

	// Build XOR key: magic cookie (4 bytes) + txID (12 bytes).
	xorKey := make([]byte, 16)
	binary.BigEndian.PutUint32(xorKey[0:4], stunMagicCookie)
	copy(xorKey[4:16], txID[:])

	// XOR the IP.
	xorIP := make([]byte, 16)
	for i := 0; i < 16; i++ {
		xorIP[i] = targetIP[i] ^ xorKey[i]
	}

	port := uint16(9999)
	xorPort := port ^ uint16(stunMagicCookie>>16)

	data := make([]byte, 20)
	data[0] = 0x00     // Reserved.
	data[1] = stunIPv6 // Family.
	binary.BigEndian.PutUint16(data[2:4], xorPort)
	copy(data[4:20], xorIP)

	ep, err := parseXORMappedAddress(data, txID)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", ep.IP)
	assert.Equal(t, 9999, ep.Port)
}

func TestParseXORMappedAddress_IPv6TooShort(t *testing.T) {
	data := make([]byte, 10) // Less than 20 bytes needed for IPv6.
	data[1] = stunIPv6
	_, err := parseXORMappedAddress(data, [12]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IPv6 address too short")
}

func TestParseXORMappedAddress_UnknownFamily(t *testing.T) {
	data := make([]byte, 8)
	data[1] = 0xFF // Unknown family.
	_, err := parseXORMappedAddress(data, [12]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown address family")
}

// --- parseMappedAddress error branch tests ---

func TestParseMappedAddress_TooShort(t *testing.T) {
	_, err := parseMappedAddress([]byte{0x00, 0x01, 0x00})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseMappedAddress_IPv6(t *testing.T) {
	// Build a valid IPv6 MAPPED-ADDRESS for 2001:db8::1 port 8080.
	targetIP := net.ParseIP("2001:db8::1")
	data := make([]byte, 20)
	data[0] = 0x00     // Reserved.
	data[1] = stunIPv6 // Family.
	binary.BigEndian.PutUint16(data[2:4], 8080)
	copy(data[4:20], targetIP.To16())

	ep, err := parseMappedAddress(data)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", ep.IP)
	assert.Equal(t, 8080, ep.Port)
}

func TestParseMappedAddress_IPv6TooShort(t *testing.T) {
	data := make([]byte, 10) // Less than 20 bytes needed for IPv6.
	data[1] = stunIPv6
	_, err := parseMappedAddress(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IPv6 address too short")
}

func TestParseMappedAddress_UnknownFamily(t *testing.T) {
	data := make([]byte, 8)
	data[1] = 0xFF
	_, err := parseMappedAddress(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown address family")
}

// --- parseBindingResponse additional error branch tests ---

func TestParseBindingResponse_TooShort(t *testing.T) {
	_, err := parseBindingResponse([]byte{0x00}, [12]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseBindingResponse_UnexpectedMessageType(t *testing.T) {
	txID := newTransactionID()
	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:2], 0x0002) // Unknown type.
	binary.BigEndian.PutUint16(resp[2:4], 0)
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	_, err := parseBindingResponse(resp, txID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected message type")
}

func TestParseBindingResponse_InvalidMagicCookie(t *testing.T) {
	txID := newTransactionID()
	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], 0)
	binary.BigEndian.PutUint32(resp[4:8], 0xDEADBEEF) // Wrong cookie.
	copy(resp[8:20], txID[:])

	_, err := parseBindingResponse(resp, txID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic cookie")
}

func TestParseBindingResponse_TruncatedMessage(t *testing.T) {
	txID := newTransactionID()
	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], 100) // Claims 100 bytes of attrs but has 0.
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])

	_, err := parseBindingResponse(resp, txID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated message")
}

func TestParseBindingResponse_NoMappedAddress(t *testing.T) {
	txID := newTransactionID()

	// Response with an unknown attribute (no mapped address).
	attrValue := []byte{0x01, 0x02, 0x03, 0x04}
	attrs := make([]byte, 0, 8)
	attrs = append(attrs, 0x99, 0x99, 0x00, 0x04) // Unknown attr type.
	attrs = append(attrs, attrValue...)

	resp := make([]byte, stunHeaderSize, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], txID[:])
	resp = append(resp, attrs...)

	_, err := parseBindingResponse(resp, txID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no mapped address")
}

// --- classifyNAT additional case: public IP ---

func TestClassifyNAT_PublicIP(t *testing.T) {
	local := Endpoint{IP: "203.0.113.1", Port: 5000}
	mapped1 := Endpoint{IP: "203.0.113.1", Port: 5000}
	mapped2 := Endpoint{IP: "203.0.113.1", Port: 5000}

	got := classifyNAT(&local, &mapped1, &mapped2)
	assert.Equal(t, NATNone, got)
}

// --- NewSTUNClient defaults ---

func TestNewSTUNClient_Defaults(t *testing.T) {
	// All zeros → should use defaults.
	c := NewSTUNClient(STUNConfig{})
	assert.NotNil(t, c)
	assert.NotEmpty(t, c.config.Servers)
	assert.Greater(t, c.config.Timeout, time.Duration(0))
	assert.Greater(t, c.config.Retries, 0)
}

func TestNewSTUNClient_CustomConfig(t *testing.T) {
	cfg := STUNConfig{
		Servers: []string{"stun.example.com:3478"},
		Timeout: 5 * time.Second,
		Retries: 3,
	}
	c := NewSTUNClient(cfg)
	assert.Equal(t, []string{"stun.example.com:3478"}, c.config.Servers)
	assert.Equal(t, 5*time.Second, c.config.Timeout)
	assert.Equal(t, 3, c.config.Retries)
}
