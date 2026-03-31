// Package p2p provides peer-to-peer direct connection capabilities.
//
// The p2p package implements NAT traversal techniques to establish direct
// connections between clients when possible, falling back to server relay
// when P2P fails.
package p2p

import "fmt"

// NATType represents the type of NAT detected.
type NATType int

const (
	// NATUnknown indicates the NAT type could not be determined.
	NATUnknown NATType = iota
	// NATNone indicates no NAT — the host has a public IP.
	NATNone
	// NATFullCone indicates a full cone (one-to-one) NAT.
	NATFullCone
	// NATRestrictedCone indicates a restricted cone NAT.
	NATRestrictedCone
	// NATPortRestricted indicates a port-restricted cone NAT.
	NATPortRestricted
	// NATSymmetric indicates a symmetric NAT (hardest to traverse).
	NATSymmetric
)

// String returns a human-readable NAT type name.
func (n NATType) String() string {
	switch n {
	case NATNone:
		return "None (Public IP)"
	case NATFullCone:
		return "Full Cone"
	case NATRestrictedCone:
		return "Restricted Cone"
	case NATPortRestricted:
		return "Port Restricted Cone"
	case NATSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

// IsTraversable returns whether P2P hole punching is likely to succeed.
func (n NATType) IsTraversable() bool {
	switch n {
	case NATNone, NATFullCone, NATRestrictedCone, NATPortRestricted:
		return true
	default:
		return false
	}
}

// Endpoint represents a network endpoint with IP and port.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// String returns the endpoint as host:port.
func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.IP, e.Port)
}

// NATInfo contains the results of NAT discovery.
type NATInfo struct {
	// Type is the detected NAT type.
	Type NATType `json:"type"`
	// PublicAddr is the public-facing endpoint as seen by the STUN server.
	PublicAddr Endpoint `json:"public_addr"`
	// LocalAddr is the local endpoint used for the STUN request.
	LocalAddr Endpoint `json:"local_addr"`
}
