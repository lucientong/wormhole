package server

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// MemoryStateStore is a single-node in-memory implementation of StateStore.
// It provides no cross-node coordination; all state is local to the process.
// This is the default backend for single-node deployments.
type MemoryStateStore struct {
	mu     sync.RWMutex
	routes map[string]RouteEntry // routeID (see RouteEntry.Key()) → route
	nodes  map[string]NodeInfo   // nodeID  → node
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		routes: make(map[string]RouteEntry),
		nodes:  make(map[string]NodeInfo),
	}
}

// conflictsWith reports whether existing (a different route entry) claims
// the same routing key as entry (H3: any of Subdomain/Hostname/PathPrefix,
// compared case-insensitively / prefix-normalized to match Router's
// semantics).
func conflictsWith(entry, existing RouteEntry) bool {
	switch {
	case entry.Subdomain != "":
		return strings.EqualFold(existing.Subdomain, entry.Subdomain)
	case entry.Hostname != "":
		return strings.EqualFold(existing.Hostname, entry.Hostname)
	case entry.PathPrefix != "":
		return normalizePath(existing.PathPrefix) == normalizePath(entry.PathPrefix)
	default:
		return false
	}
}

func (m *MemoryStateStore) RegisterRoute(entry RouteEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := entry.Key()

	// S3/H6/H3: reject when the routing key is already owned by a
	// different route entry instead of silently overwriting it
	// (last-writer-wins).
	for routeID, existing := range m.routes {
		if routeID != key && conflictsWith(entry, existing) {
			return fmt.Errorf("%w: %s", ErrSubdomainConflict, routeDescription(entry))
		}
	}

	entry.RegisteredAt = time.Now()
	m.routes[key] = entry
	return nil
}

// routeDescription returns a human-readable description of which routing
// key an entry claims, for error messages.
func routeDescription(entry RouteEntry) string {
	switch {
	case entry.Subdomain != "":
		return fmt.Sprintf("subdomain %q", entry.Subdomain)
	case entry.Hostname != "":
		return fmt.Sprintf("hostname %q", entry.Hostname)
	case entry.PathPrefix != "":
		return fmt.Sprintf("path prefix %q", entry.PathPrefix)
	default:
		return "route"
	}
}

func (m *MemoryStateStore) UnregisterRoute(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for routeID, entry := range m.routes {
		if entry.ClientID == clientID {
			delete(m.routes, routeID)
		}
	}
	return nil
}

func (m *MemoryStateStore) UnregisterRouteEntry(routeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, routeID)
	return nil
}

func (m *MemoryStateStore) LookupBySubdomain(subdomain string) (*RouteEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, entry := range m.routes {
		if entry.Subdomain != "" && strings.EqualFold(entry.Subdomain, subdomain) {
			e := entry
			return &e, nil
		}
	}
	return nil, nil //nolint:nilnil // nil means "not found", which is not an error
}

func (m *MemoryStateStore) LookupByHostname(hostname string) (*RouteEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, entry := range m.routes {
		if entry.Hostname != "" && strings.EqualFold(entry.Hostname, hostname) {
			e := entry
			return &e, nil
		}
	}
	return nil, nil //nolint:nilnil // nil means "not found", which is not an error
}

func (m *MemoryStateStore) LookupByPathPrefix(path string) (*RouteEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	reqPath := normalizePath(path)
	var best *RouteEntry
	bestLen := 0
	for _, entry := range m.routes {
		if entry.PathPrefix == "" {
			continue
		}
		prefix := normalizePath(entry.PathPrefix)
		if strings.HasPrefix(reqPath, prefix) && len(prefix) > bestLen {
			e := entry
			best = &e
			bestLen = len(prefix)
		}
	}
	return best, nil
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
		// Remove routes owned by the dead node (H8: unify with Redis,
		// which relies on route TTL rather than an explicit sweep, but a
		// dead node's routes should disappear from ListRoutes/lookups
		// immediately rather than lingering until some unrelated TTL).
		for routeID, route := range m.routes {
			if route.NodeID == id {
				delete(m.routes, routeID)
			}
		}
	}

	return nil
}

func (m *MemoryStateStore) Close() error { return nil }
