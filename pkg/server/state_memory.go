package server

import (
	"sync"
	"time"
)

// MemoryStateStore is a single-node in-memory implementation of StateStore.
// It provides no cross-node coordination; all state is local to the process.
// This is the default backend for single-node deployments.
type MemoryStateStore struct {
	mu     sync.RWMutex
	routes map[string]RouteEntry // clientID → route
	nodes  map[string]NodeInfo   // nodeID  → node
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		routes: make(map[string]RouteEntry),
		nodes:  make(map[string]NodeInfo),
	}
}

func (m *MemoryStateStore) RegisterRoute(entry RouteEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[entry.ClientID] = entry
	return nil
}

func (m *MemoryStateStore) UnregisterRoute(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, clientID)
	return nil
}

func (m *MemoryStateStore) LookupBySubdomain(subdomain string) (*RouteEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, entry := range m.routes {
		if entry.Subdomain == subdomain {
			e := entry
			return &e, nil
		}
	}
	return nil, nil //nolint:nilnil // nil means "not found", which is not an error
}

func (m *MemoryStateStore) ListRoutes() ([]RouteEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RouteEntry, 0, len(m.routes))
	for _, e := range m.routes {
		out = append(out, e)
	}
	return out, nil
}

func (m *MemoryStateStore) NodeHeartbeat(info NodeInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	info.LastHeartbeat = time.Now()
	m.nodes[info.NodeID] = info
	return nil
}

func (m *MemoryStateStore) GetNodes() ([]NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]NodeInfo, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, n)
	}
	return out, nil
}

func (m *MemoryStateStore) EvictDeadNodes(olderThan time.Duration) error {
	threshold := time.Now().Add(-olderThan)

	m.mu.Lock()
	defer m.mu.Unlock()

	var deadNodes []string
	for id, n := range m.nodes {
		if n.LastHeartbeat.Before(threshold) {
			deadNodes = append(deadNodes, id)
		}
	}

	for _, id := range deadNodes {
		delete(m.nodes, id)
		// Remove routes owned by the dead node.
		for clientID, route := range m.routes {
			if route.NodeID == id {
				delete(m.routes, clientID)
			}
		}
	}

	return nil
}

func (m *MemoryStateStore) Close() error { return nil }
