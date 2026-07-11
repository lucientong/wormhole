package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Cluster heartbeat/eviction tuning (moved here from the former cluster.go
// — see startHeartbeat).
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
)

// TunnelRegistry owns everything about which clients are currently
// connected and which routes (subdomain / custom hostname / path-prefix,
// local and, when clustered, cluster-wide) map inbound requests to them:
// the connected-client directory, the local Router, TCP port allocation
// for TCP-protocol tunnels, and the shared StateStore's heartbeat/eviction
// loop.
//
// Extracted from Server (P3-6 Batch D) so this state has exactly one
// owner — previously it was a set of fields on Server directly mutated
// from server.go, handler.go, admin.go and cluster.go alike, with no
// single place that could be reasoned about (or tested) independently of
// the rest of the server.
type TunnelRegistry interface {
	// Count returns the number of currently connected clients.
	Count() int
	// Get returns the connected client with the given session ID, if any.
	Get(sessionID string) (*ClientSession, bool)
	// Snapshot returns a point-in-time copy of every connected client,
	// safe to iterate without holding any registry lock.
	Snapshot() []*ClientSession

	// RemoveClient unregisters client from the directory and every route
	// (local and cluster) it owns, and releases any TCP ports allocated
	// to its tunnels. It does not touch client.Mux — the caller owns that.
	RemoveClient(client *ClientSession)

	// RegisterTunnel registers a tunnel's extra routing keys (any of
	// subdomain/hostname/pathPrefix that's non-empty) in both the local
	// Router and, if clustered, the shared state store. Returns "" on
	// success, or a human-readable rejection reason on conflict (with
	// everything already registered by this call rolled back).
	RegisterTunnel(client *ClientSession, tunnelID, subdomain, hostname, pathPrefix string) string
	// UnregisterTunnel removes the routes registered by RegisterTunnel.
	UnregisterTunnel(client *ClientSession, tunnelID, subdomain, hostname, pathPrefix string)
	// ReleaseTunnel releases the TCP port (if any) and routes owned by a
	// closed tunnel, undoing RegisterTunnel and the TCP port allocated in
	// AllocatePort.
	ReleaseTunnel(client *ClientSession, removed *TunnelInfo)

	// ResolveLocal returns the client currently serving host/path via the
	// local Router, or nil if none does.
	ResolveLocal(host, path string) *ClientSession
	// ResolveRemote is ResolveLocal's cluster-wide counterpart: it
	// consults the shared state store for a route owned by another node.
	// Always nil for single-node deployments (no state store configured).
	ResolveRemote(host, path string) *RouteEntry
	// IsLocalNode reports whether nodeID is this node's own cluster
	// identity (Config.ClusterNodeID).
	IsLocalNode(nodeID string) bool

	// FindPeerBySubdomain looks up the client session that owns
	// targetSubdomain for a `wormhole connect` P2P request from
	// initiator. Returns a non-empty reason instead of an error when no
	// match can be made, suitable for direct use as a P2POfferResponse
	// error field.
	FindPeerBySubdomain(targetSubdomain string, initiator *ClientSession) (peer *ClientSession, tunnelID, reason string)

	// AllocatePort allocates a TCP port (and starts listening on it) for
	// a TCP-protocol tunnel.
	AllocatePort(ctx context.Context) (port int, ln net.Listener, err error)
	// AllocatedPorts returns the count of currently allocated TCP ports.
	AllocatedPorts() int

	// StartHeartbeat starts the background cluster heartbeat/route-TTL-
	// refresh/dead-node-eviction loop. A no-op for single-node deployments
	// (no state store configured). Stops when ctx is canceled; Close
	// waits for it to fully exit.
	StartHeartbeat(ctx context.Context)
	// StateStoreHealth reports whether the cluster state store is
	// currently reachable, for exposure via /health (H9). Returns
	// (configured=false, ...) for single-node deployments.
	StateStoreHealth() (configured, healthy bool)
	// ActiveRoutes returns the number of routes currently registered in
	// the local Router.
	ActiveRoutes() int

	// Close closes the port allocator and state store, and waits for the
	// heartbeat loop (if any) to exit.
	Close()
}

// tunnelRegistry is the concrete, unexported implementation of
// TunnelRegistry. Server holds this concrete type directly (not just the
// interface) so package-internal callers — including tests — can reach
// implementation-only helpers (e.g. registerClusterRoute) that aren't part
// of the public contract.
type tunnelRegistry struct {
	cfg Config

	router *Router

	clients    map[string]*ClientSession
	clientLock sync.RWMutex

	portAllocator *TCPPortAllocator

	// stateStore is nil for single-node deployments.
	stateStore StateStore
	// stateStoreHealthy tracks whether the most recent heartbeat/route
	// refresh against stateStore succeeded, surfaced via /health (H9).
	stateStoreHealthy atomic.Bool

	// wg tracks the background heartbeat goroutine started by
	// StartHeartbeat, so Close can wait for it to fully exit.
	wg sync.WaitGroup
}

// newTunnelRegistry constructs a TunnelRegistry from server config,
// initializing the local Router, TCP port allocator and (if configured)
// the shared cluster state store.
func newTunnelRegistry(cfg Config) *tunnelRegistry {
	tr := &tunnelRegistry{
		cfg:           cfg,
		clients:       make(map[string]*ClientSession),
		router:        NewRouter(cfg.Domain),
		portAllocator: NewTCPPortAllocator(cfg.TCPPortRangeStart, cfg.TCPPortRangeEnd),
		stateStore:    initStateStore(cfg),
	}
	if tr.stateStore != nil {
		// Optimistic default: assume healthy until the first
		// heartbeat/route refresh (sent moments after Start()) proves
		// otherwise, so /health doesn't report "degraded" for the brief
		// startup window before the cluster heartbeat goroutine gets its
		// first tick in (H9).
		tr.stateStoreHealthy.Store(true)
	}
	return tr
}

func (tr *tunnelRegistry) Count() int {
	tr.clientLock.RLock()
	defer tr.clientLock.RUnlock()
	return len(tr.clients)
}

func (tr *tunnelRegistry) Get(sessionID string) (*ClientSession, bool) {
	tr.clientLock.RLock()
	defer tr.clientLock.RUnlock()
	c, ok := tr.clients[sessionID]
	return c, ok
}

func (tr *tunnelRegistry) Snapshot() []*ClientSession {
	tr.clientLock.RLock()
	defer tr.clientLock.RUnlock()
	out := make([]*ClientSession, 0, len(tr.clients))
	for _, c := range tr.clients {
		out = append(out, c)
	}
	return out
}

// addClient inserts client into the directory. Unlike RemoveClient, this
// isn't part of the public interface: registerClientRoute (Server's
// audit-logging wrapper around this registry) is the only caller, since
// route registration and directory insertion must happen atomically from
// the caller's perspective (a client that fails route registration must
// never appear in the directory at all).
func (tr *tunnelRegistry) addClient(client *ClientSession) {
	tr.clientLock.Lock()
	tr.clients[client.ID] = client
	tr.clientLock.Unlock()
}

// registerClientRoute reserves client.Subdomain in the local Router and,
// if clustered, the shared state store, then adds client to the
// directory. It returns (false, reason) if the subdomain is already
// claimed by another client (locally or cluster-wide), in which case the
// caller must reject the connection rather than let it proceed silently
// unrouted (F6/H6/S3).
func (tr *tunnelRegistry) registerClientRoute(client *ClientSession) (ok bool, reason string) {
	subdomain, sessionID := client.Subdomain, client.ID

	// H10: Router.RegisterSubdomain (below) already reclaims a
	// subdomain locally when its current owner's mux has died but
	// hasn't been cleaned up yet — e.g. a client reconnecting faster
	// than the old session's death was detected. Proactively evict that
	// stale owner's cluster-side entry too, so the reclaim isn't
	// immediately undone by RegisterRoute finding the old (still
	// TTL-live) entry and reporting a conflict against the new
	// connection's own former self.
	if existing := tr.router.LookupSubdomain(subdomain); existing != nil && isStaleOwner(existing, client) && tr.stateStore != nil {
		if err := tr.stateStore.UnregisterRoute(existing.ID); err != nil {
			log.Warn().Err(err).Str("client", existing.ID).Msg("Cluster: failed to evict stale route before reclaim")
		}
	}

	if err := tr.router.RegisterSubdomain(subdomain, client); err != nil {
		log.Error().Err(err).Str("subdomain", subdomain).Str("session_id", sessionID).
			Msg("Subdomain registration conflict — rejecting connection")
		return false, fmt.Sprintf("subdomain %q already in use", subdomain)
	}

	// H6/S3: RegisterRoute atomically reserves the subdomain cluster-wide
	// (Redis SETNX) instead of last-writer-wins; a genuine conflict with a
	// live owner on another node must reject the connection too, for the
	// same reason as the local check above. RouteID defaults to
	// sessionID/ClientID, matching this connection's primary route.
	if regOK, err := tr.registerClusterRoute(client, RouteEntry{ClientID: sessionID, Subdomain: subdomain}); !regOK {
		log.Error().Err(err).Str("subdomain", subdomain).Str("session_id", sessionID).
			Msg("Cluster: subdomain already claimed by another node — rejecting connection")
		tr.router.UnregisterSubdomain(subdomain)
		return false, fmt.Sprintf("subdomain %q already claimed cluster-wide", subdomain)
	}

	tr.addClient(client)
	return true, ""
}

// registerClusterRoute reserves entry in the shared state store (a no-op,
// always-true success when running single-node) and, on success, appends
// it to client.clusterRoutes so the heartbeat loop keeps refreshing its TTL
// (H1). NodeID/NodeAddr are filled in from the registry's own config.
// Returns (false, ErrSubdomainConflict-wrapping err) only for a genuine
// live conflict; a state-store error unrelated to conflict resolution is
// logged and treated as non-fatal (losing cluster visibility temporarily
// is preferable to rejecting every connection whenever Redis hiccups).
func (tr *tunnelRegistry) registerClusterRoute(client *ClientSession, entry RouteEntry) (bool, error) {
	if tr.stateStore == nil {
		return true, nil
	}

	entry.NodeID = tr.cfg.ClusterNodeID
	entry.NodeAddr = tr.cfg.ClusterNodeAddr

	err := tr.stateStore.RegisterRoute(entry)
	if err == nil {
		client.mu.Lock()
		client.clusterRoutes = append(client.clusterRoutes, entry)
		client.mu.Unlock()
		return true, nil
	}
	if !errors.Is(err, ErrSubdomainConflict) {
		log.Warn().Err(err).Str("route", entry.Key()).Msg("Cluster: failed to register route in state store")
		return true, nil
	}
	return false, err
}

// unregisterClusterRoute removes entry from the state store and from
// client.clusterRoutes, undoing registerClusterRoute. Used when an
// individual tunnel (rather than the whole connection) is closed.
func (tr *tunnelRegistry) unregisterClusterRoute(client *ClientSession, routeID string) {
	if tr.stateStore == nil {
		return
	}
	if err := tr.stateStore.UnregisterRouteEntry(routeID); err != nil {
		log.Warn().Err(err).Str("route", routeID).Msg("Cluster: failed to unregister route from state store")
	}
	client.mu.Lock()
	for i, e := range client.clusterRoutes {
		if e.Key() == routeID {
			client.clusterRoutes = append(client.clusterRoutes[:i], client.clusterRoutes[i+1:]...)
			break
		}
	}
	client.mu.Unlock()
}

func (tr *tunnelRegistry) RegisterTunnel(client *ClientSession, tunnelID, subdomain, hostname, pathPrefix string) string {
	if subdomain != "" {
		if err := tr.router.RegisterSubdomain(subdomain, client); err != nil {
			return fmt.Sprintf("subdomain %q already in use", subdomain)
		}
		routeID := tunnelID + ":sub"
		if ok, _ := tr.registerClusterRoute(client, RouteEntry{RouteID: routeID, ClientID: client.ID, Subdomain: subdomain}); !ok {
			tr.router.UnregisterSubdomain(subdomain)
			return fmt.Sprintf("subdomain %q already claimed cluster-wide", subdomain)
		}
	}

	if hostname != "" {
		if err := tr.router.RegisterHostname(hostname, client); err != nil {
			tr.UnregisterTunnel(client, tunnelID, subdomain, "", "")
			return fmt.Sprintf("hostname %q already in use", hostname)
		}
		routeID := tunnelID + ":host"
		if ok, _ := tr.registerClusterRoute(client, RouteEntry{RouteID: routeID, ClientID: client.ID, Hostname: hostname}); !ok {
			tr.router.UnregisterHostname(hostname)
			tr.UnregisterTunnel(client, tunnelID, subdomain, "", "")
			return fmt.Sprintf("hostname %q already claimed cluster-wide", hostname)
		}
	}

	if pathPrefix != "" {
		if err := tr.router.RegisterPath(pathPrefix, client); err != nil {
			tr.UnregisterTunnel(client, tunnelID, subdomain, hostname, "")
			return fmt.Sprintf("path prefix %q already in use", pathPrefix)
		}
		routeID := tunnelID + ":path"
		if ok, _ := tr.registerClusterRoute(client, RouteEntry{RouteID: routeID, ClientID: client.ID, PathPrefix: pathPrefix}); !ok {
			tr.router.UnregisterPath(pathPrefix)
			tr.UnregisterTunnel(client, tunnelID, subdomain, hostname, "")
			return fmt.Sprintf("path prefix %q already claimed cluster-wide", pathPrefix)
		}
	}

	return ""
}

func (tr *tunnelRegistry) UnregisterTunnel(client *ClientSession, tunnelID, subdomain, hostname, pathPrefix string) {
	if subdomain != "" {
		tr.router.UnregisterSubdomain(subdomain)
		tr.unregisterClusterRoute(client, tunnelID+":sub")
	}
	if hostname != "" {
		tr.router.UnregisterHostname(hostname)
		tr.unregisterClusterRoute(client, tunnelID+":host")
	}
	if pathPrefix != "" {
		tr.router.UnregisterPath(pathPrefix)
		tr.unregisterClusterRoute(client, tunnelID+":path")
	}
}

func (tr *tunnelRegistry) ReleaseTunnel(client *ClientSession, removed *TunnelInfo) {
	if removed.TCPPort > 0 {
		tr.portAllocator.Release(int(removed.TCPPort))
	}

	extraSubdomain := ""
	if removed.Subdomain != "" && removed.Subdomain != client.Subdomain {
		extraSubdomain = removed.Subdomain
	}
	tr.UnregisterTunnel(client, removed.ID, extraSubdomain, removed.Hostname, removed.PathPrefix)
}

func (tr *tunnelRegistry) RemoveClient(client *ClientSession) {
	tr.clientLock.Lock()
	delete(tr.clients, client.ID)
	tr.clientLock.Unlock()

	tr.router.Unregister(client)

	if tr.stateStore != nil {
		if err := tr.stateStore.UnregisterRoute(client.ID); err != nil {
			log.Warn().Err(err).Str("client", client.ID).Msg("Cluster: failed to unregister route from state store")
		}
	}

	client.mu.Lock()
	for _, t := range client.Tunnels {
		if t.TCPPort > 0 {
			tr.portAllocator.Release(int(t.TCPPort))
		}
	}
	client.mu.Unlock()
}

func (tr *tunnelRegistry) ResolveLocal(host, path string) *ClientSession {
	return tr.router.Route(host, path)
}

// lookupRemoteBySubdomain attempts to find a route entry for the given
// subdomain in the cluster state store. Returns nil if not found or if the
// state store is not configured.
func (tr *tunnelRegistry) lookupRemoteBySubdomain(subdomain string) *RouteEntry {
	if tr.stateStore == nil || subdomain == "" {
		return nil
	}
	entry, err := tr.stateStore.LookupBySubdomain(subdomain)
	if err != nil {
		log.Warn().Err(err).Str("subdomain", subdomain).Msg("Cluster: state store subdomain lookup failed")
		return nil
	}
	return entry
}

// lookupRemoteByHostname is lookupRemoteBySubdomain's counterpart for
// custom hostnames (H3).
func (tr *tunnelRegistry) lookupRemoteByHostname(hostname string) *RouteEntry {
	if tr.stateStore == nil || hostname == "" {
		return nil
	}
	entry, err := tr.stateStore.LookupByHostname(hostname)
	if err != nil {
		log.Warn().Err(err).Str("hostname", hostname).Msg("Cluster: state store hostname lookup failed")
		return nil
	}
	return entry
}

// lookupRemoteByPath is lookupRemoteBySubdomain's counterpart for
// path-prefix routes (H3).
func (tr *tunnelRegistry) lookupRemoteByPath(path string) *RouteEntry {
	if tr.stateStore == nil {
		return nil
	}
	entry, err := tr.stateStore.LookupByPathPrefix(path)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Cluster: state store path lookup failed")
		return nil
	}
	return entry
}

func (tr *tunnelRegistry) ResolveRemote(host, path string) *RouteEntry {
	if tr.stateStore == nil {
		return nil
	}

	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	hostOnly = strings.ToLower(hostOnly)

	if route := tr.lookupRemoteByHostname(hostOnly); route != nil {
		return route
	}
	if route := tr.lookupRemoteBySubdomain(extractSubdomain(hostOnly, tr.cfg.Domain)); route != nil {
		return route
	}
	return tr.lookupRemoteByPath(path)
}

func (tr *tunnelRegistry) IsLocalNode(nodeID string) bool {
	return nodeID == tr.cfg.ClusterNodeID
}

func (tr *tunnelRegistry) FindPeerBySubdomain(targetSubdomain string, initiator *ClientSession) (peer *ClientSession, tunnelID, reason string) {
	peer = tr.router.LookupSubdomain(targetSubdomain)
	if peer == nil {
		return nil, "", errP2PTargetNotFound
	}
	if peer == initiator {
		return nil, "", errP2PTargetIsSelf
	}

	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.P2PPublicAddr == "" {
		return nil, "", errP2PTargetNotFound
	}
	for _, t := range peer.Tunnels {
		if t.Subdomain == targetSubdomain {
			return peer, t.ID, ""
		}
	}
	return nil, "", errP2PTargetTunnelMeta
}

func (tr *tunnelRegistry) AllocatePort(ctx context.Context) (int, net.Listener, error) {
	return tr.portAllocator.Allocate(ctx)
}

func (tr *tunnelRegistry) AllocatedPorts() int {
	return tr.portAllocator.AllocatedPorts()
}

func (tr *tunnelRegistry) ActiveRoutes() int {
	if tr.router == nil {
		return 0
	}
	return tr.router.ActiveRoutes()
}

// StartHeartbeat starts a background goroutine that:
//   - Periodically calls StateStore.NodeHeartbeat to mark this node as alive.
//   - Periodically refreshes the TTL of every route this node currently
//     owns (H1), so long-lived connections don't silently fall out of the
//     cluster's routing table after defaultRouteTTL just because nothing
//     re-registered them.
//   - Periodically evicts routes owned by nodes that have stopped heartbeating.
//
// It stops when ctx is canceled; Close waits for it to fully exit.
func (tr *tunnelRegistry) StartHeartbeat(ctx context.Context) {
	if tr.stateStore == nil {
		return
	}

	tr.wg.Add(1)
	go func() {
		defer tr.wg.Done()

		heartbeatTick := time.NewTicker(defaultHeartbeatInterval)
		evictTick := time.NewTicker(defaultEvictInterval)
		defer heartbeatTick.Stop()
		defer evictTick.Stop()

		// Send an immediate first heartbeat.
		tr.sendHeartbeat()
		tr.refreshClusterRoutes()

		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatTick.C:
				tr.sendHeartbeat()
				tr.refreshClusterRoutes()
			case <-evictTick.C:
				if err := tr.stateStore.EvictDeadNodes(defaultDeadNodeThreshold); err != nil {
					log.Warn().Err(err).Msg("Cluster: evict dead nodes failed")
				}
			}
		}
	}()
}

// sendHeartbeat records this node's heartbeat in the state store, and
// tracks whether the last attempt succeeded (H9) so /health can report
// cluster state-store connectivity instead of staying silent about it.
func (tr *tunnelRegistry) sendHeartbeat() {
	err := tr.stateStore.NodeHeartbeat(NodeInfo{
		NodeID:   tr.cfg.ClusterNodeID,
		NodeAddr: tr.cfg.ClusterNodeAddr,
	})
	if err != nil {
		log.Warn().Err(err).Msg("Cluster: heartbeat failed")
		tr.stateStoreHealthy.Store(false)
		return
	}
	tr.stateStoreHealthy.Store(true)
}

// refreshClusterRoutes re-registers every cluster route entry this node's
// currently-connected clients own (H1). RegisterRoute's same-key branch is
// an idempotent TTL refresh, so calling it again on every heartbeat is
// enough to keep a long-lived connection's routes alive indefinitely
// without ever needing a dedicated "just bump the TTL" store method.
func (tr *tunnelRegistry) refreshClusterRoutes() {
	if tr.stateStore == nil {
		return
	}

	clients := tr.Snapshot()

	for _, c := range clients {
		c.mu.Lock()
		entries := make([]RouteEntry, len(c.clusterRoutes))
		copy(entries, c.clusterRoutes)
		c.mu.Unlock()

		for _, entry := range entries {
			if err := tr.stateStore.RegisterRoute(entry); err != nil {
				log.Warn().Err(err).Str("client", c.ID).Str("route", entry.Key()).
					Msg("Cluster: failed to refresh route TTL")
			}
		}
	}
}

func (tr *tunnelRegistry) StateStoreHealth() (configured, healthy bool) {
	if tr.stateStore == nil {
		return false, false
	}
	return true, tr.stateStoreHealthy.Load()
}

func (tr *tunnelRegistry) Close() {
	if tr.portAllocator != nil {
		tr.portAllocator.CloseAll()
	}
	if tr.stateStore != nil {
		_ = tr.stateStore.Close()
	}
	tr.wg.Wait()
}

// extractSubdomain extracts the subdomain from a host string given the base domain.
// For example, extractSubdomain("abc123.example.com", "example.com") → "abc123".
// Returns an empty string if the host is not a subdomain of domain.
func extractSubdomain(host, domain string) string {
	suffix := "." + domain
	if strings.HasSuffix(host, suffix) {
		return strings.TrimSuffix(host, suffix)
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		if strings.HasSuffix(h, suffix) {
			return strings.TrimSuffix(h, suffix)
		}
	}
	return ""
}

// TCPPortAllocator manages TCP port allocation for raw TCP tunnels.
type TCPPortAllocator struct {
	start    int
	end      int
	nextPort int
	used     map[int]net.Listener
	mu       sync.Mutex
}

// NewTCPPortAllocator creates a new port allocator for the given range.
func NewTCPPortAllocator(start, end int) *TCPPortAllocator {
	return &TCPPortAllocator{
		start:    start,
		end:      end,
		nextPort: start,
		used:     make(map[int]net.Listener),
	}
}

// Allocate allocates a TCP port and starts listening on it.
// Returns the port number and the listener.
func (a *TCPPortAllocator) Allocate(ctx context.Context) (int, net.Listener, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Search for an available port.
	checked := 0
	for checked < (a.end - a.start) {
		port := a.nextPort
		a.nextPort++
		if a.nextPort >= a.end {
			a.nextPort = a.start
		}
		checked++

		if _, exists := a.used[port]; exists {
			continue
		}

		// Try to listen on this port.
		lc := net.ListenConfig{}
		ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue // Port in use by OS, try next.
		}

		a.used[port] = ln
		return port, ln, nil
	}

	return 0, nil, fmt.Errorf("no available ports in range %d-%d", a.start, a.end)
}

// Release releases a previously allocated port.
func (a *TCPPortAllocator) Release(port int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ln, exists := a.used[port]; exists {
		_ = ln.Close()
		delete(a.used, port)
	}
}

// CloseAll closes all allocated port listeners.
func (a *TCPPortAllocator) CloseAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for port, ln := range a.used {
		_ = ln.Close()
		delete(a.used, port)
	}
}

// AllocatedPorts returns the count of currently allocated ports.
func (a *TCPPortAllocator) AllocatedPorts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}
