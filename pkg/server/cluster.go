package server

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// defaultHeartbeatInterval is how often a node sends heartbeats to the store.
	defaultHeartbeatInterval = 30 * time.Second

	// defaultEvictInterval is how often the node scans for and evicts dead peers.
	defaultEvictInterval = 60 * time.Second

	// defaultDeadNodeThreshold is the maximum age of a node heartbeat before
	// the node is considered dead and its routes are cleaned up.
	defaultDeadNodeThreshold = 3 * defaultHeartbeatInterval
)

// startClusterHeartbeat starts a background goroutine that:
//   - Periodically calls StateStore.NodeHeartbeat to mark this node as alive.
//   - Periodically evicts routes owned by nodes that have stopped heartbeating.
//
// It stops when ctx is canceled.
func (s *Server) startClusterHeartbeat(ctx context.Context) {
	if s.stateStore == nil {
		return
	}

	s.closeWg.Add(1)
	go func() {
		defer s.closeWg.Done()

		heartbeatTick := time.NewTicker(defaultHeartbeatInterval)
		evictTick := time.NewTicker(defaultEvictInterval)
		defer heartbeatTick.Stop()
		defer evictTick.Stop()

		// Send an immediate first heartbeat.
		s.sendHeartbeat()

		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatTick.C:
				s.sendHeartbeat()
			case <-evictTick.C:
				if err := s.stateStore.EvictDeadNodes(defaultDeadNodeThreshold); err != nil {
					log.Warn().Err(err).Msg("Cluster: evict dead nodes failed")
				}
			}
		}
	}()
}

// sendHeartbeat records this node's heartbeat in the state store.
func (s *Server) sendHeartbeat() {
	if err := s.stateStore.NodeHeartbeat(NodeInfo{
		NodeID:   s.config.ClusterNodeID,
		NodeAddr: s.config.ClusterNodeAddr,
	}); err != nil {
		log.Warn().Err(err).Msg("Cluster: heartbeat failed")
	}
}

// lookupRemoteClient attempts to find a route entry for the given subdomain in
// the cluster state store. Returns nil if the subdomain is not found or if the
// state store is not configured.
func (s *Server) lookupRemoteClient(subdomain string) *RouteEntry {
	if s.stateStore == nil {
		return nil
	}

	entry, err := s.stateStore.LookupBySubdomain(subdomain)
	if err != nil {
		log.Warn().Err(err).Str("subdomain", subdomain).Msg("Cluster: state store lookup failed")
		return nil
	}
	return entry
}

// isLocalNode returns true if the given nodeID is the current node.
func (s *Server) isLocalNode(nodeID string) bool {
	return nodeID == s.config.ClusterNodeID
}

// proxyToNode forwards an HTTP request to the node that owns the route entry.
// It is used for cross-node routing when the target client is connected to a
// different cluster member.
func (s *Server) proxyToNode(nodeAddr string, w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse("http://" + nodeAddr)
	if err != nil {
		log.Error().Err(err).Str("node_addr", nodeAddr).Msg("Cluster: invalid node address for proxying")
		http.Error(w, "cluster routing error", http.StatusBadGateway)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
		log.Error().Err(proxyErr).Str("node_addr", nodeAddr).Msg("Cluster: cross-node proxy error")
		http.Error(rw, "cluster proxy error", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}
