package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// defaultHeartbeatInterval is how often a node sends heartbeats to the store.
	// H1: this is also how often the node refreshes the TTL of every route
	// it currently owns, so a long-lived connection's route never actually
	// expires as long as its owning node keeps heartbeating — the 30s
	// cadence is comfortably inside defaultRouteTTL (5 minutes).
	defaultHeartbeatInterval = 30 * time.Second

	// defaultEvictInterval is how often the node scans for and evicts dead peers.
	defaultEvictInterval = 60 * time.Second

	// defaultDeadNodeThreshold is the maximum age of a node heartbeat before
	// the node is considered dead and its routes are cleaned up.
	defaultDeadNodeThreshold = 3 * defaultHeartbeatInterval

	// clusterSecretHeader carries the shared cluster secret on requests
	// forwarded between nodes by proxyToNode (S1), so a receiving node can
	// tell a genuine peer hop apart from an external caller that happens
	// to reach ClusterNodeAddr directly.
	clusterSecretHeader = "X-Wormhole-Cluster-Secret" // #nosec G101 -- header name, not a credential
)

// startClusterHeartbeat starts a background goroutine that:
//   - Periodically calls StateStore.NodeHeartbeat to mark this node as alive.
//   - Periodically refreshes the TTL of every route this node currently
//     owns (H1), so long-lived connections don't silently fall out of the
//     cluster's routing table after defaultRouteTTL just because nothing
//     re-registered them.
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
		s.refreshClusterRoutes()

		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatTick.C:
				s.sendHeartbeat()
				s.refreshClusterRoutes()
			case <-evictTick.C:
				if err := s.stateStore.EvictDeadNodes(defaultDeadNodeThreshold); err != nil {
					log.Warn().Err(err).Msg("Cluster: evict dead nodes failed")
				}
			}
		}
	}()
}

// sendHeartbeat records this node's heartbeat in the state store, and
// tracks whether the last attempt succeeded (H9) so /health can report
// cluster state-store connectivity instead of staying silent about it.
func (s *Server) sendHeartbeat() {
	err := s.stateStore.NodeHeartbeat(NodeInfo{
		NodeID:   s.config.ClusterNodeID,
		NodeAddr: s.config.ClusterNodeAddr,
	})
	if err != nil {
		log.Warn().Err(err).Msg("Cluster: heartbeat failed")
		s.stateStoreHealthy.Store(false)
		return
	}
	s.stateStoreHealthy.Store(true)
}

// refreshClusterRoutes re-registers every cluster route entry this node's
// currently-connected clients own (H1). RegisterRoute's same-key branch is
// an idempotent TTL refresh, so calling it again on every heartbeat is
// enough to keep a long-lived connection's routes alive indefinitely
// without ever needing a dedicated "just bump the TTL" store method.
func (s *Server) refreshClusterRoutes() {
	if s.stateStore == nil {
		return
	}

	s.clientLock.RLock()
	clients := make([]*ClientSession, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.clientLock.RUnlock()

	for _, c := range clients {
		c.mu.Lock()
		entries := make([]RouteEntry, len(c.clusterRoutes))
		copy(entries, c.clusterRoutes)
		c.mu.Unlock()

		for _, entry := range entries {
			if err := s.stateStore.RegisterRoute(entry); err != nil {
				log.Warn().Err(err).Str("client", c.ID).Str("route", entry.Key()).
					Msg("Cluster: failed to refresh route TTL")
			}
		}
	}
}

// lookupRemoteBySubdomain attempts to find a route entry for the given
// subdomain in the cluster state store. Returns nil if not found or if the
// state store is not configured.
func (s *Server) lookupRemoteBySubdomain(subdomain string) *RouteEntry {
	if s.stateStore == nil || subdomain == "" {
		return nil
	}
	entry, err := s.stateStore.LookupBySubdomain(subdomain)
	if err != nil {
		log.Warn().Err(err).Str("subdomain", subdomain).Msg("Cluster: state store subdomain lookup failed")
		return nil
	}
	return entry
}

// lookupRemoteByHostname is lookupRemoteBySubdomain's counterpart for
// custom hostnames (H3).
func (s *Server) lookupRemoteByHostname(hostname string) *RouteEntry {
	if s.stateStore == nil || hostname == "" {
		return nil
	}
	entry, err := s.stateStore.LookupByHostname(hostname)
	if err != nil {
		log.Warn().Err(err).Str("hostname", hostname).Msg("Cluster: state store hostname lookup failed")
		return nil
	}
	return entry
}

// lookupRemoteByPath is lookupRemoteBySubdomain's counterpart for
// path-prefix routes (H3).
func (s *Server) lookupRemoteByPath(path string) *RouteEntry {
	if s.stateStore == nil {
		return nil
	}
	entry, err := s.stateStore.LookupByPathPrefix(path)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Cluster: state store path lookup failed")
		return nil
	}
	return entry
}

// lookupRemoteRoute resolves host/path to a cluster route entry when no
// locally-registered client matches, mirroring Router.Route's precedence
// (custom hostname > subdomain > path prefix) but consulting the shared
// state store instead of the in-process Router (H3: previously only
// subdomain was ever checked here, so a client's custom hostname or
// path-prefix tunnel was invisible to every node except the one it
// happened to be connected to).
func (s *Server) lookupRemoteRoute(host, path string) *RouteEntry {
	if s.stateStore == nil {
		return nil
	}

	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	hostOnly = strings.ToLower(hostOnly)

	if route := s.lookupRemoteByHostname(hostOnly); route != nil {
		return route
	}
	if route := s.lookupRemoteBySubdomain(extractSubdomain(hostOnly, s.config.Domain)); route != nil {
		return route
	}
	return s.lookupRemoteByPath(path)
}

// isLocalNode returns true if the given nodeID is the current node.
func (s *Server) isLocalNode(nodeID string) bool {
	return nodeID == s.config.ClusterNodeID
}

// proxyToNode forwards an HTTP request to the node that owns the route entry.
// It is used for cross-node routing when the target client is connected to a
// different cluster member. When Config.ClusterSecret is set, the forwarded
// request carries it in clusterSecretHeader (S1) so the receiving node can
// distinguish a genuine peer hop from an external caller that reaches
// ClusterNodeAddr directly.
func (s *Server) proxyToNode(nodeAddr string, w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse("http://" + nodeAddr)
	if err != nil {
		log.Error().Err(err).Str("node_addr", nodeAddr).Msg("Cluster: invalid node address for proxying")
		http.Error(w, "cluster routing error", http.StatusBadGateway)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	if s.config.ClusterSecret != "" {
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Header.Set(clusterSecretHeader, s.config.ClusterSecret)
		}
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
		log.Error().Err(proxyErr).Str("node_addr", nodeAddr).Msg("Cluster: cross-node proxy error")
		http.Error(rw, "cluster proxy error", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

// verifyClusterSecret implements the receiving side of S1: when
// Config.ClusterSecret is configured and an inbound request carries
// clusterSecretHeader, the value must match — a present-but-wrong secret
// means someone is trying to impersonate a cluster peer and the request is
// rejected outright. A request with no such header at all is ordinary
// external traffic and is unaffected (most requests never carry it).
// Returns false (having already written a response) if the request should
// be rejected.
func (s *Server) verifyClusterSecret(w http.ResponseWriter, r *http.Request) bool {
	if s.config.ClusterSecret == "" {
		return true
	}
	got := r.Header.Get(clusterSecretHeader)
	if got == "" {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.config.ClusterSecret)) != 1 {
		log.Warn().Str("remote", r.RemoteAddr).Msg("Cluster: rejected request with invalid cluster secret")
		http.Error(w, "invalid cluster credentials", http.StatusForbidden)
		return false
	}
	return true
}

// stateStoreHealth reports whether the cluster state store is currently
// reachable, for exposure via /health (H9). Returns (configured=false, ...)
// for single-node deployments with no state store at all.
func (s *Server) stateStoreHealth() (configured, healthy bool) {
	if s.stateStore == nil {
		return false, false
	}
	return true, s.stateStoreHealthy.Load()
}
