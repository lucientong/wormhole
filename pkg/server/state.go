package server

import (
	"errors"
	"time"
)

// ErrSubdomainConflict is returned by StateStore.RegisterRoute when the
// requested subdomain/hostname/path is already held by a different, still-live
// client. Callers should reject the connection rather than proceed with
// a route the cluster considers ambiguous.
var ErrSubdomainConflict = errors.New("subdomain already registered to another client")

// RouteEntry describes a single routing-key reservation registered in the
// cluster state: exactly one of Subdomain, Hostname, or PathPrefix should be
// set, identifying which of the three routing dimensions this entry claims
// (mirrors the three independent maps in the in-process Router).
//
// A single client can own more than one RouteEntry — e.g. its connect-time
// subdomain plus a custom hostname and/or path prefix registered by an
// individual tunnel. RouteID distinguishes these reservations from each
// other; it defaults to ClientID when empty, which preserves the original
// one-entry-per-client behavior for the primary connect-time subdomain.
type RouteEntry struct {
	// RouteID uniquely identifies this reservation. Defaults to ClientID
	// (via Key()) when left empty, so existing single-entry-per-client
	// callers don't need to set it explicitly.
	RouteID string

	// ClientID is the unique identifier of the owning client session.
	ClientID string

	// TeamName is the team that owns this route, threaded through from
	// the owning ClientSession at registration time. Used to reject a
	// different team from reclaiming a route that looks momentarily
	// stale (e.g. the owner is mid-reconnect) — see isStaleOwner and
	// the "Multi-tenancy" section of docs/architecture.md.
	TeamName string

	// Subdomain is set when this entry reserves a subdomain route.
	Subdomain string

	// Hostname is set when this entry reserves a custom-hostname route.
	Hostname string

	// PathPrefix is set when this entry reserves a path-prefix route.
	PathPrefix string

	// NodeID is the cluster node that owns this client connection.
	NodeID string

	// NodeAddr is the reachable HTTP address of the owning node
	// (used for cross-node proxying).
	NodeAddr string

	// RegisteredAt is when the route was registered.
	RegisteredAt time.Time
}

// Key returns the storage key for this entry: RouteID if set, otherwise
// ClientID (the historical default for the one-entry-per-client case).
func (e RouteEntry) Key() string {
	if e.RouteID != "" {
		return e.RouteID
	}
	return e.ClientID
}

// NodeInfo describes a member of the cluster.
type NodeInfo struct {
	// NodeID is the unique identifier for this node.
	NodeID string

	// NodeAddr is the HTTP address other nodes should proxy to for tunnels
	// owned by this node (e.g. "10.0.0.1:7000").
	NodeAddr string

	// LastHeartbeat is when the node last reported it was alive.
	LastHeartbeat time.Time
}

// StateStore is the shared-state interface for cluster coordination.
// All methods must be safe for concurrent use.
//
// Single-node deployments use MemoryStateStore (no external dependency).
// Multi-node deployments use RedisStateStore.
type StateStore interface {
	// RegisterRoute atomically reserves the routing key set on entry
	// (exactly one of Subdomain/Hostname/PathPrefix). Implementations must
	// return ErrSubdomainConflict (wrapped or not) when the key is already
	// held by a different, still-live route entry, instead of
	// silently overwriting the existing owner. Re-registering the same
	// entry.Key() (e.g. a periodic TTL refresh) must succeed idempotently,
	// as must reclaiming a key whose previous owner has gone stale (its
	// entry already expired/removed).
	RegisterRoute(entry RouteEntry) error

	// UnregisterRoute removes all route entries owned by the given client
	// (across all of its RouteIDs — connect-time subdomain plus any
	// per-tunnel hostname/path entries), used on full client disconnect.
	UnregisterRoute(clientID string) error

	// UnregisterRouteEntry removes a single route reservation by its
	// RouteID (or ClientID, if RouteID was left empty when registering),
	// used when an individual tunnel is closed but the client connection
	// (and its other routes) remain active.
	UnregisterRouteEntry(routeID string) error

	// LookupBySubdomain returns the route entry for the given subdomain.
	// Returns (nil, nil) when no entry is found (not an error condition).
	LookupBySubdomain(subdomain string) (*RouteEntry, error)

	// LookupByHostname returns the route entry for the given custom
	// hostname. Returns (nil, nil) when not found.
	LookupByHostname(hostname string) (*RouteEntry, error)

	// LookupByPathPrefix returns the route entry whose PathPrefix is the
	// longest prefix match of path, mirroring Router.matchPath's
	// local semantics. Returns (nil, nil) when no path route matches.
	LookupByPathPrefix(path string) (*RouteEntry, error)

	// ListRoutes returns all active route entries across the cluster.
	ListRoutes() ([]RouteEntry, error)

	// NodeHeartbeat records that a node is alive.
	NodeHeartbeat(info NodeInfo) error

	// GetNodes returns the list of known cluster nodes and their last heartbeat.
	GetNodes() ([]NodeInfo, error)

	// EvictDeadNodes removes nodes whose heartbeat is older than the given
	// threshold and cleans up their routes.
	EvictDeadNodes(olderThan time.Duration) error

	// Close releases any resources held by the store.
	Close() error
}
