package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/lucientong/wormhole/pkg/p2p"
	"github.com/lucientong/wormhole/pkg/proto"
	"github.com/lucientong/wormhole/pkg/tunnel"
	"github.com/rs/zerolog/log"
)

// NAT type strings as reported by pkg/p2p NAT detection and carried in
// P2POfferRequest/P2POfferResponse.P2PNATType.
const (
	natTypeSymmetric          = "Symmetric"
	natTypeFullCone           = "Full Cone"
	natTypeRestrictedCone     = "Restricted Cone"
	natTypePortRestrictedCone = "Port Restricted Cone"
)

// P2P offer rejection reasons. errP2PNoTarget is the expected, silent
// outcome for a client that's only exposing a tunnel and never asked to
// reach a peer (TargetSubdomain == "") — the client treats it as a no-op
// rather than a P2P failure worth falling back from (see
// Client.handleP2POfferResponse).
const (
	errP2PNoTarget       = "no target specified"
	errP2PTargetNotFound = "target not found: no client with that subdomain is currently connected"
	// errP2PTargetOnOtherNode is returned instead of errP2PTargetNotFound
	// when the target subdomain is connected, but to a different cluster
	// node: `wormhole connect` P2P signaling is same-node only, since
	// the peer's NAT/address/ECDH info only ever lives in that
	// node's own in-memory ClientSession. The client treats this the
	// same as any other P2P rejection reason and falls back to relay.
	errP2PTargetOnOtherNode = "target is connected to a different cluster node; P2P connect is only supported within the same node — falling back to relay"
	errP2PTargetIsSelf      = "cannot connect to your own tunnel via P2P"
	errP2PNATIncompatible   = "NAT types not compatible"
	errP2PTargetTunnelMeta  = "target tunnel metadata unavailable"
)

// P2PBroker orchestrates `wormhole connect` P2P signaling between two
// connected clients: matching an initiator's offer against a target
// subdomain's owner, checking NAT compatibility, generating port
// prediction candidates for Symmetric+Symmetric pairs, and notifying the
// matched peer so it can attempt the same hole-punch.
//
// Extracted from Server: it depends only on TunnelRegistry
// (to find the peer a `wormhole connect` request targets) plus metrics
// and the audit logger, not the rest of Server's state.
type P2PBroker interface {
	// HandleOffer handles a P2P connection offer from a client, replying
	// on stream with either a peer match or a rejection reason.
	HandleOffer(client *ClientSession, stream *tunnel.Stream, req *proto.P2POfferRequest)
	// HandleResult handles a P2P result notification (success or
	// fallback-to-relay) from a client.
	HandleResult(client *ClientSession, result *proto.P2PResult)
}

// p2pBroker is P2PBroker's concrete, unexported implementation.
type p2pBroker struct {
	registry    TunnelRegistry
	metrics     *Metrics
	auditLogger *auth.AuditLogger
	// serverCtx returns the root lifecycle context to use for the
	// peer-notification stream open. Falls back to
	// context.Background() if nil.
	serverCtx func() context.Context
}

// newP2PBroker constructs a P2PBroker. ctxFn may be nil.
func newP2PBroker(registry TunnelRegistry, metrics *Metrics, auditLogger *auth.AuditLogger, ctxFn func() context.Context) *p2pBroker {
	return &p2pBroker{
		registry:    registry,
		metrics:     metrics,
		auditLogger: auditLogger,
		serverCtx:   ctxFn,
	}
}

func (b *p2pBroker) ctx() context.Context {
	if b.serverCtx != nil {
		return b.serverCtx()
	}
	return context.Background()
}

// HandleOffer handles a P2P connection offer from a client.
//
// It always stores the sender's P2P reachability info (public/local
// address, NAT type, ECDH public key) so it's available if some other
// client later requests a match against one of this client's subdomains.
// A match is only searched for when req.TargetSubdomain is set (i.e. this
// is a `wormhole connect <subdomain>` request) — an empty target is just
// presence registration and gets a quiet errP2PNoTarget response.
func (b *p2pBroker) HandleOffer(client *ClientSession, stream *tunnel.Stream, req *proto.P2POfferRequest) {
	client.mu.Lock()
	client.P2PPublicAddr = req.PublicAddr
	client.P2PNATType = req.NATType
	client.P2PLocalAddr = req.LocalAddr
	client.P2PPublicKey = req.PublicKey
	client.P2PTunnelID = req.TunnelID
	client.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("nat_type", req.NATType).
		Str("public_addr", req.PublicAddr).
		Str("local_addr", req.LocalAddr).
		Bool("has_public_key", req.PublicKey != "").
		Str("target_subdomain", req.TargetSubdomain).
		Msg("P2P offer received")

	if req.TargetSubdomain == "" {
		resp := proto.NewP2POfferResponse(false, errP2PNoTarget, "", "", "", "")
		if err := proto.WriteControlMessage(stream, resp); err != nil {
			log.Error().Err(err).Msg("Failed to write P2P offer response")
		}
		return
	}

	peer, peerTunnelID, findErr := b.registry.FindPeerBySubdomain(req.TargetSubdomain, client)
	if findErr != "" {
		log.Info().Str("client", client.ID).Str("target", req.TargetSubdomain).Str("reason", findErr).
			Msg("P2P connect request could not be matched")
		resp := proto.NewP2POfferResponse(false, findErr, "", "", "", "")
		_ = proto.WriteControlMessage(stream, resp)
		return
	}

	// Check if both NAT types are traversable.
	if !b.isP2PCompatible(req.NATType, peer.P2PNATType) {
		log.Info().
			Str("client_nat", req.NATType).
			Str("peer_nat", peer.P2PNATType).
			Msg("NAT types not compatible for P2P")
		resp := proto.NewP2POfferResponse(false, errP2PNATIncompatible, "", "", "", "")
		_ = proto.WriteControlMessage(stream, resp)
		return
	}

	// Found the target! Return peer info to initiator.
	peer.mu.Lock()
	peerAddr := peer.P2PPublicAddr
	peerNATType := peer.P2PNATType
	peerPublicKey := peer.P2PPublicKey
	peer.mu.Unlock()

	log.Info().
		Str("client", client.ID).
		Str("peer", peer.ID).
		Str("target_subdomain", req.TargetSubdomain).
		Str("peer_addr", peerAddr).
		Str("client_nat", req.NATType).
		Str("peer_nat", peerNATType).
		Bool("has_peer_key", peerPublicKey != "").
		Msg("P2P peer matched")

	// For Symmetric+Symmetric NAT, generate port prediction candidates and
	// send them as a P2PCandidates message before the offer response.
	// Both messages are length-prefixed (proto.WriteControlMessage) so the
	// client can reliably distinguish and decode each one in turn — see
	// Client.sendP2POffer, which now loop-reads framed messages instead of
	// doing a single raw stream.Read().
	bothSymmetric := req.NATType == natTypeSymmetric && peerNATType == natTypeSymmetric
	var initiatorCandidates []string
	if bothSymmetric {
		initiatorCandidates = predictCandidatesForSymmetric(req.PublicAddr, req.NATType, 8)
		peerCandidates := predictCandidatesForSymmetric(peerAddr, peerNATType, 8)

		// Send peer's predicted candidates to the initiating client.
		if len(peerCandidates) > 0 {
			candidatesMsg := proto.NewP2PCandidates(peerTunnelID, peerCandidates)
			if err := proto.WriteControlMessage(stream, candidatesMsg); err != nil {
				log.Error().Err(err).Msg("Failed to write P2P candidates")
			}
		}
		log.Info().
			Str("client", client.ID).
			Str("peer", peer.ID).
			Int("peer_candidates", len(peerCandidates)).
			Int("initiator_candidates", len(initiatorCandidates)).
			Msg("Symmetric+Symmetric NAT: using port prediction for P2P")
	}

	// Send peer info (including ECDH public key) to initiating client.
	resp := proto.NewP2POfferResponse(true, "", peerAddr, peerNATType, peerPublicKey, peerTunnelID)
	if err := proto.WriteControlMessage(stream, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write P2P offer response")
		return
	}

	// Notify the peer about the incoming P2P request (via a new stream).
	go b.notifyPeer(peer, client, initiatorCandidates)
}

// isP2PCompatible checks if two NAT types can establish a P2P connection.
// With port prediction, Symmetric-Symmetric is attempted (lower success rate).
func (b *p2pBroker) isP2PCompatible(natType1, natType2 string) bool {
	// Any combination that includes at least one non-Symmetric NAT is traversable.
	// Symmetric+Symmetric is also attempted using port prediction heuristics.
	return natPriority(natType1) > 0 && natPriority(natType2) > 0
}

// predictCandidatesForSymmetric generates port candidates for the given
// Symmetric NAT address using the port predictor.
// Returns nil if the address is not Symmetric NAT or prediction is not possible.
func predictCandidatesForSymmetric(addr string, natType string, count int) []string {
	if natType != natTypeSymmetric || addr == "" {
		return nil
	}

	host, portStr, err := splitHostPort(addr)
	if err != nil {
		return nil
	}

	port := 0
	if _, scanErr := fmt.Sscanf(portStr, "%d", &port); scanErr != nil || port <= 0 {
		return nil
	}

	pred := p2p.NewPredictor()
	pred.AddSample(port)
	ports := pred.Predict(count)

	candidates := make([]string, 0, len(ports))
	for _, p := range ports {
		candidates = append(candidates, fmt.Sprintf("%s:%d", host, p))
	}
	return candidates
}

// splitHostPort is a thin wrapper around net.SplitHostPort that returns
// ("", "", err) on failure so callers can handle it cleanly.
func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}

// notifyPeer sends a P2P offer notification to the peer client.
// For Symmetric+Symmetric NAT pairs it also sends predicted port candidates
// for the initiator side so the peer can attempt hole punching.
func (b *p2pBroker) notifyPeer(peer *ClientSession, initiator *ClientSession, initiatorCandidates []string) {
	initiator.mu.Lock()
	initiatorAddr := initiator.P2PPublicAddr
	initiatorNATType := initiator.P2PNATType
	initiatorPublicKey := initiator.P2PPublicKey
	initiatorTunnelID := initiator.P2PTunnelID
	initiator.mu.Unlock()

	peer.mu.Lock()
	peerNATType := peer.P2PNATType
	peer.mu.Unlock()

	// Open a stream to the peer to notify them.
	stream, err := peer.Mux.OpenStreamContext(b.ctx())
	if err != nil {
		log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to open stream to notify peer of P2P")
		return
	}
	defer stream.Close()

	if deadlineErr := stream.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
		log.Error().Err(deadlineErr).Msg("Failed to set P2P notification deadline")
		return
	}

	// For Symmetric+Symmetric, send initiator's predicted candidates first.
	// Framed with proto.WriteControlMessage (length-prefixed) to match the
	// client's Client.handleStream, which loop-reads framed control
	// messages off this notification stream.
	if initiatorNATType == natTypeSymmetric && peerNATType == natTypeSymmetric {
		if len(initiatorCandidates) > 0 {
			candidatesMsg := proto.NewP2PCandidates(initiatorTunnelID, initiatorCandidates)
			if err := proto.WriteControlMessage(stream, candidatesMsg); err != nil {
				log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to write P2P candidates to peer")
			} else {
				log.Debug().
					Str("peer", peer.ID).
					Int("candidates", len(initiatorCandidates)).
					Msg("Sent initiator port prediction candidates to peer")
			}
		}
	}

	// Send P2P offer response (as a notification) with the initiator's info and public key.
	// PeerTunnelID is only meaningful for the initiator (addressing outgoing
	// streams to a specific tunnel on the target); the notified side accepts
	// P2P streams generically, so it's left empty here.
	msg := proto.NewP2POfferResponse(true, "", initiatorAddr, initiatorNATType, initiatorPublicKey, "")
	if err := proto.WriteControlMessage(stream, msg); err != nil {
		log.Error().Err(err).Str("peer", peer.ID).Msg("Failed to write P2P notification")
		return
	}

	log.Debug().
		Str("peer", peer.ID).
		Str("initiator_addr", initiatorAddr).
		Bool("has_key", initiatorPublicKey != "").
		Msg("P2P notification sent to peer")
}

// HandleResult handles a P2P result notification from a client.
func (b *p2pBroker) HandleResult(client *ClientSession, result *proto.P2PResult) {
	if result.Success {
		log.Info().
			Str("client", client.ID).
			Str("peer_addr", result.PeerAddr).
			Msg("P2P connection established")
		if b.metrics != nil {
			b.metrics.P2PConnectionsTotal.WithLabelValues("success").Inc()
		}
		if b.auditLogger != nil {
			b.auditLogger.LogP2PEstablished(client.ID, result.PeerAddr)
		}
	} else {
		log.Info().
			Str("client", client.ID).
			Str("error", result.Error).
			Msg("P2P connection failed, using relay")
		if b.metrics != nil {
			b.metrics.P2PConnectionsTotal.WithLabelValues("fallback").Inc()
		}
		if b.auditLogger != nil {
			b.auditLogger.LogP2PFallback(client.ID, result.Error)
		}
	}
}

// natPriority returns a priority score for a NAT type.
// Higher score = more traversal-friendly = preferred peer.
func natPriority(natType string) int {
	switch natType {
	case natTypeFullCone:
		return 4
	case natTypeRestrictedCone:
		return 3
	case natTypePortRestrictedCone:
		return 2
	case natTypeSymmetric:
		return 1
	default:
		return 0
	}
}
