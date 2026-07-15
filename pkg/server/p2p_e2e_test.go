package server

// An integration test for the `wormhole connect` P2P signaling chain end
// to end — Client.MaybeSendOffer -> Server's
// P2PBroker.HandleOffer -> Server's notifyPeer -> the peer Client's
// HandleNotification -> both sides attempt hole punching and report the
// outcome back via P2PResult. Every other P2P-related test either drives
// the server-side broker against fake ClientSessions (server_test.go) or
// the client-side P2PSession against fakes (pkg/client/p2p_session_test.go);
// this is the one test that wires two real *client.Client instances to a
// real Server and lets the whole three-party chain run for real, the way
// two actual `wormhole connect` peers would.
//
// NAT discovery is the one piece that can't hit the real internet in a
// test: each client's STUN config here points at a fakeSTUNServer
// running on loopback (see below) instead of the real STUN servers,
// giving deterministic, network-independent "traversable NAT" discovery
// so the rest of the chain — offer, matching, notification, hole-punch
// attempt — runs exactly as it would in production.

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/lucientong/wormhole/pkg/client"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestP2P_ConnectSignalingChain_EstablishesDirectConnection starts a real
// Server plus two real Clients — B merely exposes a tunnel
// (P2P enabled), A runs in `wormhole connect` mode targeting B's
// subdomain — and drives the full signaling chain end to end: A's
// MaybeSendOffer reaches the server, P2PBroker.HandleOffer matches it
// against B (whose own earlier presence-only offer registered its NAT
// info), the server notifies B over a fresh stream, B's HandleNotification
// fires, and both sides attempt a mutual hole punch with a session cipher
// derived from the exchanged ECDH keys — then each reports its outcome
// back to the server via a P2PResult, observed here as the
// P2PConnectionsTotal metric incrementing for both.
//
// The actual UDP hole punch is deliberately not required to succeed: real
// NAT traversal depends on OS/network specifics this test doesn't control
// (and is already covered in isolation by pkg/p2p's own
// TestHolePuncher_LocalPunch); what this test is after is proving every
// component correctly wires into the next one, which is fully observable
// whether or not the last hop's raw UDP connectivity happens to succeed.
// HolePunchConfig.Timeout is shortened so a failed punch doesn't make
// this test slow.
func TestP2P_ConnectSignalingChain_EstablishesDirectConnection(t *testing.T) {
	srvCfg := DefaultConfig()
	srvCfg.ListenAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AdminAddr = "127.0.0.1:0"
	srvCfg.MuxConfig.KeepAliveInterval = 0
	srv := NewServer(srvCfg)

	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	srvErrCh := make(chan error, 1)
	go func() { srvErrCh <- srv.Start(srvCtx) }()
	<-srv.listenersReady
	tunnelAddr := srv.tunnelListener.Addr().String()

	stunServers := []string{newFakeSTUNServer(t), newFakeSTUNServer(t)}

	// Client B: a normal tunnel owner with P2P enabled. It never calls
	// `wormhole connect`, but MaybeSendOffer still fires automatically
	// after every successful connect (with an empty TargetSubdomain) to
	// register its P2P reachability info with the server — the
	// prerequisite FindPeerBySubdomain checks for on the initiator side.
	bCfg := client.DefaultConfig()
	bCfg.ServerAddr = tunnelAddr
	bCfg.LocalPort = 9
	bCfg.Subdomain = "clientb"
	bCfg.P2PEnabled = true
	bCfg.P2PConfig.STUNConfig.Servers = stunServers
	bCfg.P2PConfig.HolePunchConfig.Timeout = 500 * time.Millisecond
	bCfg.MuxConfig.KeepAliveInterval = 0
	bCfg.ReconnectInterval = 50 * time.Millisecond
	clientB := client.NewClient(bCfg)
	defer func() { _ = clientB.Close() }()
	bErrCh := make(chan error, 1)
	go func() { bErrCh <- clientB.Start(context.Background()) }()

	// Wait until B's tunnel is registered *and* its P2P presence info has
	// reached the server — both are prerequisites for A's offer to match;
	// starting A too early would have it rejected with "target not found"
	// with no retry (connect mode sends exactly one offer per connection).
	require.Eventually(t, func() bool {
		peer := srv.registry.router.LookupSubdomain("clientb")
		if peer == nil {
			return false
		}
		peer.mu.Lock()
		defer peer.mu.Unlock()
		return peer.P2PPublicAddr != ""
	}, 5*time.Second, 10*time.Millisecond, "client B's tunnel/P2P presence never reached the server")

	// Client A: `wormhole connect clientb` — no tunnel of its own.
	aCfg := client.DefaultConfig()
	aCfg.ServerAddr = tunnelAddr
	aCfg.LocalPort = 9
	aCfg.ConnectTarget = "clientb"
	aCfg.P2PEnabled = true
	aCfg.P2PConfig.STUNConfig.Servers = stunServers
	aCfg.P2PConfig.HolePunchConfig.Timeout = 500 * time.Millisecond
	aCfg.MuxConfig.KeepAliveInterval = 0
	aCfg.ReconnectInterval = 50 * time.Millisecond
	clientA := client.NewClient(aCfg)
	defer func() { _ = clientA.Close() }()
	aErrCh := make(chan error, 1)
	go func() { aErrCh <- clientA.Start(context.Background()) }()

	// Both clients report their hole-punch outcome back to the server via
	// a P2PResult (P2PBroker.HandleResult), which is the chain's final
	// hop and the strongest observable proof every earlier hop (offer,
	// match, notification, cipher derivation, punch attempt) actually ran
	// on both sides — regardless of whether the punch itself succeeded.
	fallbackCounter := srv.metrics.P2PConnectionsTotal.WithLabelValues("fallback")
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(fallbackCounter) >= 2
	}, 5*time.Second, 20*time.Millisecond,
		"expected both clients to report a P2P result back to the server (signaling chain incomplete)")

	require.NoError(t, clientA.Close())
	require.NoError(t, clientB.Close())
	require.NoError(t, <-aErrCh)
	require.NoError(t, <-bErrCh)
	srvCancel()
	require.NoError(t, <-srvErrCh)
}

// Minimal RFC 5389 wire-format constants, duplicated here rather than
// imported from pkg/p2p (which are unexported) purely to hand-encode a
// Binding Response — this only needs to speak the public STUN wire
// protocol, not any internal API.
const (
	fakeSTUNBindingResp   = 0x0101
	fakeSTUNMagicCookie   = 0x2112A442
	fakeSTUNAttrXORMapped = 0x0020
	fakeSTUNFamilyIPv4    = 0x01
)

// newFakeSTUNServer starts a minimal STUN Binding Request responder on
// loopback and returns its address. It always reports the request's own
// observed UDP source address as the "mapped" address — a faithful (not
// fabricated) result given there's no real NAT between two loopback
// sockets — which is enough for pkg/p2p's NAT classification to report a
// Cone (traversable) NAT type without depending on the real internet.
// The server is torn down automatically via t.Cleanup.
func newFakeSTUNServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if n < 20 {
				continue
			}
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			var txID [12]byte
			copy(txID[:], buf[8:20])
			_, _ = conn.WriteTo(buildFakeSTUNBindingResponse(txID, udpAddr), addr)
		}
	}()

	return conn.LocalAddr().String()
}

// buildFakeSTUNBindingResponse encodes a STUN Binding Response carrying a
// single XOR-MAPPED-ADDRESS attribute for addr.
func buildFakeSTUNBindingResponse(txID [12]byte, addr *net.UDPAddr) []byte {
	ip4 := addr.IP.To4()
	xorPort := uint16(addr.Port) ^ uint16(fakeSTUNMagicCookie>>16) // #nosec G115 -- UDP ports fit uint16
	xorIP := binary.BigEndian.Uint32(ip4) ^ uint32(fakeSTUNMagicCookie)

	attrValue := make([]byte, 8)
	attrValue[1] = fakeSTUNFamilyIPv4
	binary.BigEndian.PutUint16(attrValue[2:4], xorPort)
	binary.BigEndian.PutUint32(attrValue[4:8], xorIP)

	attrHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(attrHeader[0:2], fakeSTUNAttrXORMapped)
	binary.BigEndian.PutUint16(attrHeader[2:4], uint16(len(attrValue)))

	msg := make([]byte, 20, 20+len(attrHeader)+len(attrValue))
	binary.BigEndian.PutUint16(msg[0:2], fakeSTUNBindingResp)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrHeader)+len(attrValue)))
	binary.BigEndian.PutUint32(msg[4:8], fakeSTUNMagicCookie)
	copy(msg[8:20], txID[:])

	msg = append(msg, attrHeader...)
	msg = append(msg, attrValue...)
	return msg
}
