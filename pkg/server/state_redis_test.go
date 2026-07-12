package server

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRedisStateStore spins up an in-process miniredis server and
// returns a RedisStateStore backed by it, along with the miniredis handle
// so tests can manipulate time/TTLs directly.
func newTestRedisStateStore(t *testing.T) (*RedisStateStore, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return newRedisStateStoreWithClient(client), mr
}

// TestRedisStateStore_RegisterRoute_ReservesFreeSubdomain verifies the
// happy path: reserving a never-before-seen subdomain succeeds and the
// route becomes lookupable.
func TestRedisStateStore_RegisterRoute_ReservesFreeSubdomain(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	err := store.RegisterRoute(RouteEntry{ClientID: "client-a", Subdomain: "free-sub", NodeID: "node-1"})
	require.NoError(t, err)

	entry, err := store.LookupBySubdomain("free-sub")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "client-a", entry.ClientID)
}

// TestRedisStateStore_RegisterRoute_SameClientRefresh verifies that a
// client re-registering its own subdomain (e.g. after a reconnect retry)
// is treated as an idempotent TTL refresh rather than a conflict.
func TestRedisStateStore_RegisterRoute_SameClientRefresh(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "client-a", Subdomain: "mine", NodeID: "node-1"}))
	err := store.RegisterRoute(RouteEntry{ClientID: "client-a", Subdomain: "mine", NodeID: "node-1"})
	require.NoError(t, err)

	entry, err := store.LookupBySubdomain("mine")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "client-a", entry.ClientID)
}

// TestRedisStateStore_RegisterRoute_ConflictWithLiveOwner verifies the core
// atomic-reservation guarantee: when a *different*, still-live client
// already owns the subdomain, RegisterRoute must reject with
// ErrSubdomainConflict instead of silently overwriting the reservation
// (as a naive last-writer-wins implementation would).
func TestRedisStateStore_RegisterRoute_ConflictWithLiveOwner(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "client-a", Subdomain: "contested", NodeID: "node-1"}))

	err := store.RegisterRoute(RouteEntry{ClientID: "client-b", Subdomain: "contested", NodeID: "node-2"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSubdomainConflict)

	// The original owner's reservation must be untouched.
	entry, lookupErr := store.LookupBySubdomain("contested")
	require.NoError(t, lookupErr)
	require.NotNil(t, entry)
	assert.Equal(t, "client-a", entry.ClientID)
}

// TestRedisStateStore_RegisterRoute_ReclaimsStaleReservation verifies that
// a subdomain index entry left behind by a crashed node (whose route entry
// has since expired/been removed, so it's no longer "live") can be
// reclaimed by a new client instead of being stuck forever.
func TestRedisStateStore_RegisterRoute_ReclaimsStaleReservation(t *testing.T) {
	store, mr := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "crashed-client", Subdomain: "stale", NodeID: "node-1"}))

	// Simulate the crashed client's route entry having expired (but the
	// subdomain index key surviving, e.g. due to differing TTLs/timing).
	mr.Del(redisRoutePrefix + "crashed-client")

	err := store.RegisterRoute(RouteEntry{ClientID: "new-client", Subdomain: "stale", NodeID: "node-2"})
	require.NoError(t, err)

	entry, err := store.LookupBySubdomain("stale")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "new-client", entry.ClientID)
}

// TestRedisStateStore_UnregisterRoute_FreesSubdomain verifies that
// unregistering a route also removes its subdomain index entry, so the
// subdomain becomes immediately available for reservation again.
func TestRedisStateStore_UnregisterRoute_FreesSubdomain(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "client-a", Subdomain: "released", NodeID: "node-1"}))
	require.NoError(t, store.UnregisterRoute("client-a"))

	entry, err := store.LookupBySubdomain("released")
	require.NoError(t, err)
	assert.Nil(t, entry)

	// Now a different client can claim it without conflict.
	err = store.RegisterRoute(RouteEntry{ClientID: "client-b", Subdomain: "released", NodeID: "node-2"})
	assert.NoError(t, err)
}

// TestRedisStateStore_ListRoutes verifies aggregation across multiple
// registered routes.
func TestRedisStateStore_ListRoutes(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "s1", NodeID: "n1"}))
	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "c2", Subdomain: "s2", NodeID: "n1"}))

	routes, err := store.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 2)
}

// TestRedisStateStore_NodeHeartbeatAndGetNodes verifies node heartbeat
// storage and retrieval.
func TestRedisStateStore_NodeHeartbeatAndGetNodes(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.NodeHeartbeat(NodeInfo{NodeID: "node-1", NodeAddr: "10.0.0.1:7002"}))

	nodes, err := store.GetNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "node-1", nodes[0].NodeID)
	assert.False(t, nodes[0].LastHeartbeat.IsZero())
}

// TestRedisStateStore_EvictDeadNodes_NoOp verifies the documented no-op
// behavior (Redis TTLs already handle expiry).
func TestRedisStateStore_EvictDeadNodes_NoOp(t *testing.T) {
	store, _ := newTestRedisStateStore(t)
	assert.NoError(t, store.EvictDeadNodes(time.Minute))
}

// TestRedisStateStore_HostnameRoute verifies custom-hostname routes are
// indexed in Redis just like subdomains, so a cluster
// peer can find a client's hostname-based tunnel via LookupByHostname.
func TestRedisStateStore_HostnameRoute(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	err := store.RegisterRoute(RouteEntry{
		RouteID: "tunnel-1:host", ClientID: "client-a", Hostname: "custom.example.com", NodeID: "node-1",
	})
	require.NoError(t, err)

	entry, err := store.LookupByHostname("CUSTOM.example.com") // case-insensitive
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "client-a", entry.ClientID)

	// Not found.
	entry, err = store.LookupByHostname("nope.example.com")
	require.NoError(t, err)
	assert.Nil(t, entry)
}

// TestRedisStateStore_PathPrefixRoute_LongestMatch verifies the
// longest-prefix-match semantics for path routes, mirroring Router.matchPath.
func TestRedisStateStore_PathPrefixRoute_LongestMatch(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{RouteID: "short", ClientID: "c1", PathPrefix: "/api", NodeID: "n1"}))
	require.NoError(t, store.RegisterRoute(RouteEntry{RouteID: "long", ClientID: "c2", PathPrefix: "/api/v2", NodeID: "n1"}))

	entry, err := store.LookupByPathPrefix("/api/v2/widgets")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "c2", entry.ClientID, "longest matching prefix should win")

	entry, err = store.LookupByPathPrefix("/api/v1/widgets")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "c1", entry.ClientID)

	entry, err = store.LookupByPathPrefix("/unrelated")
	require.NoError(t, err)
	assert.Nil(t, entry)
}

// TestRedisStateStore_MultipleRoutesPerClient verifies a single client
// can register a subdomain, a hostname, and a path-prefix route
// simultaneously (distinguished by RouteID), and UnregisterRoute cleans up
// all of them via the wormhole:clientroutes:<clientID> index — without a
// separate call per RouteID and without scanning the whole keyspace.
func TestRedisStateStore_MultipleRoutesPerClient(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"}))
	require.NoError(t, store.RegisterRoute(RouteEntry{RouteID: "t1:host", ClientID: "c1", Hostname: "host1.example.com", NodeID: "n1"}))
	require.NoError(t, store.RegisterRoute(RouteEntry{RouteID: "t1:path", ClientID: "c1", PathPrefix: "/api", NodeID: "n1"}))

	routes, err := store.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 3)

	require.NoError(t, store.UnregisterRoute("c1"))

	entry, _ := store.LookupBySubdomain("sub1")
	assert.Nil(t, entry, "subdomain route should be gone")
	entry, _ = store.LookupByHostname("host1.example.com")
	assert.Nil(t, entry, "hostname route should be gone")
	entry, _ = store.LookupByPathPrefix("/api/x")
	assert.Nil(t, entry, "path route should be gone")

	routes, err = store.ListRoutes()
	require.NoError(t, err)
	assert.Empty(t, routes)
}

// TestRedisStateStore_UnregisterRouteEntry verifies that removing a single
// route by RouteID (e.g. closing one tunnel) leaves the client's other
// routes — including its primary connect-time subdomain — intact.
func TestRedisStateStore_UnregisterRouteEntry(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{ClientID: "c1", Subdomain: "sub1", NodeID: "n1"}))
	require.NoError(t, store.RegisterRoute(RouteEntry{RouteID: "t1:host", ClientID: "c1", Hostname: "host1.example.com", NodeID: "n1"}))

	require.NoError(t, store.UnregisterRouteEntry("t1:host"))

	entry, _ := store.LookupByHostname("host1.example.com")
	assert.Nil(t, entry, "closed tunnel's hostname route should be gone")
	entry, _ = store.LookupBySubdomain("sub1")
	require.NotNil(t, entry, "the connection's primary subdomain route must survive")
	assert.Equal(t, "c1", entry.ClientID)
}

// TestRedisStateStore_HostnameConflict verifies the same conflict rejection
// also applies to hostname routes, not just subdomains.
func TestRedisStateStore_HostnameConflict(t *testing.T) {
	store, _ := newTestRedisStateStore(t)

	require.NoError(t, store.RegisterRoute(RouteEntry{RouteID: "t1:host", ClientID: "c1", Hostname: "shared.example.com", NodeID: "n1"}))

	err := store.RegisterRoute(RouteEntry{RouteID: "t2:host", ClientID: "c2", Hostname: "shared.example.com", NodeID: "n2"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSubdomainConflict)
}

// TestRedisStateStore_RegisterRoute_NoRoutingKeySet verifies that an entry
// with none of Subdomain/Hostname/PathPrefix set is rejected outright
// rather than silently succeeding with an unusable/unindexed reservation.
func TestRedisStateStore_RegisterRoute_NoRoutingKeySet(t *testing.T) {
	store, _ := newTestRedisStateStore(t)
	err := store.RegisterRoute(RouteEntry{ClientID: "c1", NodeID: "n1"})
	assert.Error(t, err)
}

// TestRedisStateStore_UnregisterRouteEntry_Missing verifies that
// unregistering a RouteID that doesn't exist is a harmless no-op, matching
// UnregisterRoute's existing idempotent-cleanup behavior.
func TestRedisStateStore_UnregisterRouteEntry_Missing(t *testing.T) {
	store, _ := newTestRedisStateStore(t)
	assert.NoError(t, store.UnregisterRouteEntry("does-not-exist"))
}
