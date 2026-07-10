package server

import (
	"errors"
	"testing"
	"time"
)

// Tests for MemoryStateStore cover all StateStore operations.

func TestMemoryStateStore_RegisterAndLookup(t *testing.T) {
	s := NewMemoryStateStore()
	defer s.Close()

	entry := RouteEntry{
		ClientID:  "client-1",
		Subdomain: "abc123",
		NodeID:    "node-1",
		NodeAddr:  "10.0.0.1:7002",
	}

	if err := s.RegisterRoute(entry); err != nil {
		t.Fatalf("RegisterRoute: %v", err)
	}

	got, err := s.LookupBySubdomain("abc123")
	if err != nil {
		t.Fatalf("LookupBySubdomain: %v", err)
	}
	if got.ClientID != entry.ClientID {
		t.Errorf("got ClientID %q; want %q", got.ClientID, entry.ClientID)
	}
	if got.NodeAddr != entry.NodeAddr {
		t.Errorf("got NodeAddr %q; want %q", got.NodeAddr, entry.NodeAddr)
	}
}

func TestMemoryStateStore_LookupMissing(t *testing.T) {
	s := NewMemoryStateStore()
	got, err := s.LookupBySubdomain("notfound")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// TestMemoryStateStore_RegisterRoute_SubdomainConflict verifies S3/H6:
// registering the same subdomain from a different clientID is rejected
// with ErrSubdomainConflict instead of silently overwriting the owner.
func TestMemoryStateStore_RegisterRoute_SubdomainConflict(t *testing.T) {
	s := NewMemoryStateStore()

	if err := s.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"}); err != nil {
		t.Fatalf("first RegisterRoute: %v", err)
	}

	err := s.RegisterRoute(RouteEntry{ClientID: "c2", Subdomain: "sub1", NodeID: "n2"})
	if !errors.Is(err, ErrSubdomainConflict) {
		t.Fatalf("expected ErrSubdomainConflict, got %v", err)
	}

	// The original owner must be unaffected by the rejected attempt.
	got, lookupErr := s.LookupBySubdomain("sub1")
	if lookupErr != nil {
		t.Fatalf("LookupBySubdomain: %v", lookupErr)
	}
	if got == nil || got.ClientID != "c1" {
		t.Fatalf("expected sub1 to still be owned by c1, got %+v", got)
	}
}

// TestMemoryStateStore_RegisterRoute_SameClientRefresh verifies that
// re-registering the same (ClientID, Subdomain) pair — e.g. a TTL refresh —
// is idempotent and never treated as a conflict.
func TestMemoryStateStore_RegisterRoute_SameClientRefresh(t *testing.T) {
	s := NewMemoryStateStore()

	entry := RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"}
	if err := s.RegisterRoute(entry); err != nil {
		t.Fatalf("first RegisterRoute: %v", err)
	}
	if err := s.RegisterRoute(entry); err != nil {
		t.Fatalf("refresh RegisterRoute: %v", err)
	}
}

func TestMemoryStateStore_UnregisterRoute(t *testing.T) {
	s := NewMemoryStateStore()

	entry := RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"}
	_ = s.RegisterRoute(entry)

	if err := s.UnregisterRoute("c1"); err != nil {
		t.Fatalf("UnregisterRoute: %v", err)
	}

	got, _ := s.LookupBySubdomain("sub1")
	if got != nil {
		t.Errorf("expected nil after unregister, got %+v", got)
	}
}

func TestMemoryStateStore_ListRoutes(t *testing.T) {
	s := NewMemoryStateStore()

	for i := range 3 {
		_ = s.RegisterRoute(RouteEntry{
			ClientID:  string(rune('a' + i)),
			Subdomain: string(rune('x' + i)),
			NodeID:    "node-1",
		})
	}

	routes, err := s.ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 3 {
		t.Errorf("got %d routes; want 3", len(routes))
	}
}

func TestMemoryStateStore_NodeHeartbeatAndGetNodes(t *testing.T) {
	s := NewMemoryStateStore()

	for _, id := range []string{"n1", "n2"} {
		if err := s.NodeHeartbeat(NodeInfo{NodeID: id, NodeAddr: id + ":7000"}); err != nil {
			t.Fatalf("NodeHeartbeat(%s): %v", id, err)
		}
	}

	nodes, err := s.GetNodes()
	if err != nil {
		t.Fatalf("GetNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("got %d nodes; want 2", len(nodes))
	}
}

func TestMemoryStateStore_EvictDeadNodes(t *testing.T) {
	s := NewMemoryStateStore()

	// Register a node with an artificially old timestamp.
	_ = s.NodeHeartbeat(NodeInfo{NodeID: "dead", NodeAddr: "1.2.3.4:7000"})

	// Manually backdate the heartbeat.
	s.mu.Lock()
	n := s.nodes["dead"]
	n.LastHeartbeat = time.Now().Add(-10 * time.Minute)
	s.nodes["dead"] = n
	s.mu.Unlock()

	// Also register a route owned by the dead node.
	_ = s.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "dead"})

	if err := s.EvictDeadNodes(5 * time.Minute); err != nil {
		t.Fatalf("EvictDeadNodes: %v", err)
	}

	nodes, _ := s.GetNodes()
	for _, n := range nodes {
		if n.NodeID == "dead" {
			t.Error("dead node was not evicted")
		}
	}

	// Routes owned by the dead node should also be removed.
	route, _ := s.LookupBySubdomain("sub1")
	if route != nil {
		t.Error("route owned by dead node was not evicted")
	}
}

// TestMemoryStateStore_MultipleRoutesPerClient verifies H3: a single
// client can own more than one route entry (its connect-time subdomain
// plus a per-tunnel hostname and path prefix), distinguished by RouteID,
// and all three are independently lookupable.
func TestMemoryStateStore_MultipleRoutesPerClient(t *testing.T) {
	s := NewMemoryStateStore()

	if err := s.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"}); err != nil {
		t.Fatalf("register subdomain: %v", err)
	}
	if err := s.RegisterRoute(RouteEntry{RouteID: "t1:host", ClientID: "c1", Hostname: "custom.example.com", NodeID: "n1"}); err != nil {
		t.Fatalf("register hostname: %v", err)
	}
	if err := s.RegisterRoute(RouteEntry{RouteID: "t1:path", ClientID: "c1", PathPrefix: "/api", NodeID: "n1"}); err != nil {
		t.Fatalf("register path: %v", err)
	}

	if got, _ := s.LookupBySubdomain("sub1"); got == nil || got.ClientID != "c1" {
		t.Fatalf("LookupBySubdomain: got %+v", got)
	}
	if got, _ := s.LookupByHostname("custom.example.com"); got == nil || got.ClientID != "c1" {
		t.Fatalf("LookupByHostname: got %+v", got)
	}
	if got, _ := s.LookupByPathPrefix("/api/v1/foo"); got == nil || got.ClientID != "c1" {
		t.Fatalf("LookupByPathPrefix: got %+v", got)
	}

	routes, err := s.ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("got %d routes; want 3", len(routes))
	}

	// UnregisterRoute(clientID) must remove ALL of the client's routes.
	if err := s.UnregisterRoute("c1"); err != nil {
		t.Fatalf("UnregisterRoute: %v", err)
	}
	if got, _ := s.LookupBySubdomain("sub1"); got != nil {
		t.Error("subdomain route should be gone")
	}
	if got, _ := s.LookupByHostname("custom.example.com"); got != nil {
		t.Error("hostname route should be gone")
	}
	if got, _ := s.LookupByPathPrefix("/api/v1/foo"); got != nil {
		t.Error("path route should be gone")
	}
}

// TestMemoryStateStore_UnregisterRouteEntry verifies that removing a
// single route by RouteID leaves the client's other routes intact —
// mirroring closing one tunnel without disconnecting the whole client.
func TestMemoryStateStore_UnregisterRouteEntry(t *testing.T) {
	s := NewMemoryStateStore()

	_ = s.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"})
	_ = s.RegisterRoute(RouteEntry{RouteID: "t1:host", ClientID: "c1", Hostname: "custom.example.com", NodeID: "n1"})

	if err := s.UnregisterRouteEntry("t1:host"); err != nil {
		t.Fatalf("UnregisterRouteEntry: %v", err)
	}

	if got, _ := s.LookupByHostname("custom.example.com"); got != nil {
		t.Error("hostname route should be gone")
	}
	if got, _ := s.LookupBySubdomain("sub1"); got == nil {
		t.Error("subdomain route should still be present")
	}
}

// TestMemoryStateStore_HostnameAndPathConflict verifies S3/H6's conflict
// rejection also applies to the new hostname/path routing keys (H3), not
// just subdomains.
func TestMemoryStateStore_HostnameAndPathConflict(t *testing.T) {
	s := NewMemoryStateStore()

	_ = s.RegisterRoute(RouteEntry{RouteID: "t1:host", ClientID: "c1", Hostname: "shared.example.com", NodeID: "n1"})
	err := s.RegisterRoute(RouteEntry{RouteID: "t2:host", ClientID: "c2", Hostname: "shared.example.com", NodeID: "n2"})
	if !errors.Is(err, ErrSubdomainConflict) {
		t.Fatalf("expected ErrSubdomainConflict for hostname conflict, got %v", err)
	}

	_ = s.RegisterRoute(RouteEntry{RouteID: "t1:path", ClientID: "c1", PathPrefix: "/api", NodeID: "n1"})
	err = s.RegisterRoute(RouteEntry{RouteID: "t2:path", ClientID: "c2", PathPrefix: "/api", NodeID: "n2"})
	if !errors.Is(err, ErrSubdomainConflict) {
		t.Fatalf("expected ErrSubdomainConflict for path conflict, got %v", err)
	}
}

// TestMemoryStateStore_LookupByPathPrefix_LongestMatch verifies that
// LookupByPathPrefix picks the longest matching prefix, mirroring
// Router.matchPath's local semantics.
func TestMemoryStateStore_LookupByPathPrefix_LongestMatch(t *testing.T) {
	s := NewMemoryStateStore()

	_ = s.RegisterRoute(RouteEntry{RouteID: "short", ClientID: "c1", PathPrefix: "/api", NodeID: "n1"})
	_ = s.RegisterRoute(RouteEntry{RouteID: "long", ClientID: "c2", PathPrefix: "/api/v2", NodeID: "n1"})

	got, err := s.LookupByPathPrefix("/api/v2/widgets")
	if err != nil {
		t.Fatalf("LookupByPathPrefix: %v", err)
	}
	if got == nil || got.ClientID != "c2" {
		t.Fatalf("expected longest-prefix match to win (c2), got %+v", got)
	}

	got, err = s.LookupByPathPrefix("/api/v1/widgets")
	if err != nil {
		t.Fatalf("LookupByPathPrefix: %v", err)
	}
	if got == nil || got.ClientID != "c1" {
		t.Fatalf("expected fallback to shorter prefix match (c1), got %+v", got)
	}
}
