package p2p

import (
	"encoding/binary"
	"net"
	"testing"

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

	ep, err := parseXORMappedAddress(data)
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
	assert.False(t, isPublicIP("10.0.0.1"))
	assert.False(t, isPublicIP("172.16.0.1"))
	assert.False(t, isPublicIP("192.168.1.1"))
	assert.False(t, isPublicIP("127.0.0.1"))
	assert.True(t, isPublicIP("8.8.8.8"))
	assert.True(t, isPublicIP("1.1.1.1"))
	assert.True(t, isPublicIP("203.0.113.5"))
	assert.False(t, isPublicIP("invalid"))
}
