package server

import (
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
