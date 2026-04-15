package server

import (
	"time"
)

// RouteEntry describes a tunnel route registered in the cluster state.
type RouteEntry struct {
	// ClientID is the unique identifier of the client session.
	ClientID string

	// Subdomain is the subdomain assigned to this client.
	Subdomain string

	// NodeID is the cluster node that owns this client connection.
	NodeID string

	// NodeAddr is the reachable HTTP address of the owning node
	// (used for cross-node proxying).
	NodeAddr string

	// RegisteredAt is when the route was registered.
	RegisteredAt time.Time
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
	// RegisterRoute stores a client's route entry on this node.
	RegisterRoute(entry RouteEntry) error

	// UnregisterRoute removes all routes for a given client.
	UnregisterRoute(clientID string) error

	// LookupBySubdomain returns the route entry for the given subdomain.
	// Returns (nil, nil) when no entry is found (not an error condition).
	LookupBySubdomain(subdomain string) (*RouteEntry, error)

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
