// Package p2p provides peer-to-peer direct connection capabilities.
//
// The p2p package implements NAT traversal techniques to establish direct
// connections between clients when possible, falling back to server relay
// when P2P fails.
//
// # Features
//
//   - STUN client for NAT type detection and public IP discovery
//   - UDP hole punching for NAT traversal
//   - Symmetric NAT port prediction
//   - Automatic fallback to relay mode
//
// # NAT Types Supported
//
//   - Full Cone NAT: Easiest to traverse
//   - Restricted Cone NAT: Requires initial outbound packet
//   - Port Restricted Cone NAT: Requires matching port
//   - Symmetric NAT: Most difficult, uses port prediction
//
// # Usage
//
//	client := p2p.NewSTUNClient(p2p.Config{
//	    STUNServers: []string{
//	        "stun:stun.l.google.com:19302",
//	        "stun:stun1.l.google.com:19302",
//	    },
//	})
//
//	// Discover NAT type and public endpoint
//	info, err := client.Discover(ctx)
//	if err != nil {
//	    return err
//	}
//
//	// Attempt hole punching
//	conn, err := p2p.HolePunch(ctx, info, peerInfo)
//	if err != nil {
//	    // Fall back to relay
//	    conn, err = relay.Connect(ctx, serverAddr)
//	}
package p2p
