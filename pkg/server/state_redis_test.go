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
// route becomes lookupable (S3/H6).
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
// S3/H6 guarantee: when a *different*, still-live client already owns the
// subdomain, RegisterRoute must reject with ErrSubdomainConflict instead of
// silently overwriting the reservation (the pre-fix last-writer-wins bug).
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
