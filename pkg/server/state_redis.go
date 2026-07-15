package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisRoutePrefix     = "wormhole:route:"        // wormhole:route:<routeID> → JSON RouteEntry
	redisNodePrefix      = "wormhole:node:"         // wormhole:node:<nodeID> → JSON NodeInfo
	redisSubdomainIdx    = "wormhole:sub:"          // wormhole:sub:<subdomain> → routeID
	redisHostnameIdx     = "wormhole:host:"         // wormhole:host:<hostname> → routeID
	redisPathIdx         = "wormhole:path:"         // wormhole:path:<normalized path> → routeID
	redisClientRoutesIdx = "wormhole:clientroutes:" // wormhole:clientroutes:<clientID> → SET of routeIDs

	// defaultRouteTTL is how long a route persists after its last refresh.
	// The owning node re-registers (refreshes) every live route on each
	// heartbeat tick (see Server.refreshClusterRoutes), which runs far
	// more often than this TTL, so a route only actually expires when its
	// owning node has stopped heartbeating entirely.
	defaultRouteTTL = 5 * time.Minute

	// defaultNodeTTL is how long a node heartbeat is kept.
	defaultNodeTTL = 90 * time.Second

	// redisScanCount is the COUNT hint passed to SCAN, balancing round-trip
	// count against per-call latency. It's a hint only; Redis may return
	// more or fewer keys per call.
	redisScanCount = 200
)

// RedisStateStore implements StateStore using Redis for multi-node coordination.
//
// Key layout:
//
//	wormhole:route:<routeID>        — JSON RouteEntry, TTL = defaultRouteTTL
//	wormhole:sub:<subdomain>        — routeID string, TTL = defaultRouteTTL
//	wormhole:host:<hostname> — routeID string, TTL = defaultRouteTTL
//	wormhole:path:<norm path> — routeID string, TTL = defaultRouteTTL
//	wormhole:clientroutes:<clientID> — SET of routeIDs owned by clientID, TTL = defaultRouteTTL
//	wormhole:node:<nodeID>          — JSON NodeInfo, TTL = defaultNodeTTL
type RedisStateStore struct {
	client *redis.Client
}

// RedisStateStoreConfig configures the Redis state store.
type RedisStateStoreConfig struct {
	// Addr is the Redis server address (host:port).
	Addr string

	// Password is the Redis AUTH password (optional).
	Password string

	// DB is the Redis database number (default 0).
	DB int
}

// NewRedisStateStore creates a Redis-backed state store.
func NewRedisStateStore(cfg RedisStateStoreConfig) (*RedisStateStore, error) {
	if cfg.Addr == "" {
		cfg.Addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return &RedisStateStore{client: client}, nil
}

// newRedisStateStoreWithClient wraps an already-constructed *redis.Client
// (e.g. one pointed at a miniredis instance in tests) without the
// Ping/connect logic in NewRedisStateStore.
func newRedisStateStoreWithClient(client *redis.Client) *RedisStateStore {
	return &RedisStateStore{client: client}
}

// indexKey returns the Redis index key (and, for error messages, a
// human-readable description) for whichever of Subdomain/Hostname/PathPrefix
// is set on entry. Returns ("", "") if none are set.
func indexKey(entry RouteEntry) (key, desc string) {
	switch {
	case entry.Subdomain != "":
		return redisSubdomainIdx + strings.ToLower(entry.Subdomain), fmt.Sprintf("subdomain %q", entry.Subdomain)
	case entry.Hostname != "":
		return redisHostnameIdx + strings.ToLower(entry.Hostname), fmt.Sprintf("hostname %q", entry.Hostname)
	case entry.PathPrefix != "":
		return redisPathIdx + normalizePath(entry.PathPrefix), fmt.Sprintf("path prefix %q", entry.PathPrefix)
	default:
		return "", ""
	}
}

// registerRouteScript atomically reserves entry's routing index key,
// writes its JSON record, and (when ClientID is set) tracks it in the
// client's route-ID set, all as one Redis-side transaction (NH-04).
//
// A previous implementation did this as SETNX(idx) + pipeline SET(route
// data), which left a window — between the two round trips — where the
// index key pointed at a routeID with no backing record yet: a concurrent
// lookup landing in that window would see the route as "not found" even
// though the reservation had technically succeeded, and if the process
// crashed or lost its connection between the two calls, that broken state
// could persist until routeID re-registered (which NH-01's heartbeat
// retry now makes likely, but isn't a substitute for closing the race
// itself). Running the whole thing as one EVAL removes the window
// entirely: a lookup interleaved with a RegisterRoute call now always
// finds a fully-formed reservation or none.
//
// Semantics (identical to the previous multi-round-trip version):
//   - Key free                                → reserve it for entry.Key().
//   - Key already owned by entry.Key()         → idempotent TTL refresh.
//   - Key owned by a route whose record has expired/gone (crashed
//     without UnregisterRoute) → reclaim it.
//   - Key owned by another *live* route entry  → "CONFLICT:<routeID>".
const registerRouteScript = `
local idxKey = KEYS[1]
local routeKey = KEYS[2]
local clientRoutesKey = KEYS[3]
local routeID = ARGV[1]
local data = ARGV[2]
local ttl = ARGV[3]
local routePrefix = ARGV[4]

local existing = redis.call("GET", idxKey)
if existing ~= false and existing ~= routeID then
  local ownerAlive = redis.call("EXISTS", routePrefix .. existing)
  if ownerAlive == 1 then
    return "CONFLICT:" .. existing
  end
end

redis.call("SET", idxKey, routeID, "EX", ttl)
redis.call("SET", routeKey, data, "EX", ttl)
if clientRoutesKey ~= "" then
  redis.call("SADD", clientRoutesKey, routeID)
  redis.call("EXPIRE", clientRoutesKey, ttl)
end
return "OK"
`

// RegisterRoute atomically reserves entry's routing key (whichever of
// Subdomain/Hostname/PathPrefix is set) via registerRouteScript instead of
// a plain last-writer-wins SET, and instead of the older SETNX-then-
// pipeline sequence that had a brief window between the two calls (see
// registerRouteScript's doc comment).
func (r *RedisStateStore) RegisterRoute(entry RouteEntry) error {
	ctx := context.Background()

	idxKey, desc := indexKey(entry)
	if idxKey == "" {
		return errors.New("route entry has no Subdomain, Hostname, or PathPrefix set")
	}

	entry.RegisteredAt = time.Now()
	routeID := entry.Key()
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal route entry: %w", err)
	}

	routeKey := redisRoutePrefix + routeID
	clientRoutesKey := ""
	if entry.ClientID != "" {
		clientRoutesKey = redisClientRoutesIdx + entry.ClientID
	}

	res, err := r.client.Eval(ctx, registerRouteScript,
		[]string{idxKey, routeKey, clientRoutesKey},
		routeID, data, int(defaultRouteTTL.Seconds()), redisRoutePrefix,
	).Result()
	if err != nil {
		return fmt.Errorf("reserve %s: %w", desc, err)
	}

	result, ok := res.(string)
	if !ok {
		return fmt.Errorf("reserve %s: unexpected script result %v", desc, res)
	}
	if strings.HasPrefix(result, "CONFLICT:") {
		return fmt.Errorf("%w: %s is held by another client", ErrSubdomainConflict, desc)
	}
	return nil
}

// UnregisterRoute removes all route entries owned by clientID, using the
// wormhole:clientroutes:<clientID> set to find them without scanning the
// entire keyspace.
func (r *RedisStateStore) UnregisterRoute(clientID string) error {
	ctx := context.Background()
	clientRoutesKey := redisClientRoutesIdx + clientID

	routeIDs, err := r.client.SMembers(ctx, clientRoutesKey).Result()
	if err != nil {
		return fmt.Errorf("list routes for client %q: %w", clientID, err)
	}

	for _, routeID := range routeIDs {
		if err := r.deleteRouteByID(ctx, routeID); err != nil {
			return err
		}
	}
	return r.client.Del(ctx, clientRoutesKey).Err()
}

// UnregisterRouteEntry removes a single route reservation by its RouteID
// (or ClientID, when RouteID was left empty at registration time).
func (r *RedisStateStore) UnregisterRouteEntry(routeID string) error {
	ctx := context.Background()

	entry, err := r.getRouteEntry(ctx, routeID)
	if err != nil {
		return err
	}
	if entry != nil && entry.ClientID != "" {
		if err := r.client.SRem(ctx, redisClientRoutesIdx+entry.ClientID, routeID).Err(); err != nil {
			return fmt.Errorf("remove route %q from client index: %w", routeID, err)
		}
	}
	return r.deleteRouteByID(ctx, routeID)
}

// deleteRouteByID deletes the route's storage key and its index key
// (whichever of subdomain/hostname/path it held). It's a no-op (not an
// error) if the route entry no longer exists.
func (r *RedisStateStore) deleteRouteByID(ctx context.Context, routeID string) error {
	entry, err := r.getRouteEntry(ctx, routeID)
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}

	pipe := r.client.Pipeline()
	pipe.Del(ctx, redisRoutePrefix+routeID)
	if idxKey, _ := indexKey(*entry); idxKey != "" {
		pipe.Del(ctx, idxKey)
	}
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete route %q: %w", routeID, err)
	}
	return nil
}

// getRouteEntry fetches and unmarshals the route entry stored at routeID,
// or (nil, nil) if it doesn't exist.
func (r *RedisStateStore) getRouteEntry(ctx context.Context, routeID string) (*RouteEntry, error) {
	data, err := r.client.Get(ctx, redisRoutePrefix+routeID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil //nolint:nilnil // not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("get route %q: %w", routeID, err)
	}
	var entry RouteEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("unmarshal route %q: %w", routeID, err)
	}
	return &entry, nil
}

// lookupByIndex resolves an index key to its route entry, or (nil, nil) if
// either the index or the underlying route record is missing (a missing
// route record means a stale index entry that hasn't expired yet — treated
// the same as "not found", not an error).
func (r *RedisStateStore) lookupByIndex(idxKey string) (*RouteEntry, error) {
	ctx := context.Background()

	routeID, err := r.client.Get(ctx, idxKey).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil //nolint:nilnil // not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("lookup index %q: %w", idxKey, err)
	}
	return r.getRouteEntry(ctx, routeID)
}

func (r *RedisStateStore) LookupBySubdomain(subdomain string) (*RouteEntry, error) {
	return r.lookupByIndex(redisSubdomainIdx + strings.ToLower(subdomain))
}

// LookupByHostname looks up a custom-hostname route: hostnames are indexed
// in Redis the same way subdomains are, so cross-node fallback can find a
// client's custom-hostname tunnel regardless of which node it's connected to.
func (r *RedisStateStore) LookupByHostname(hostname string) (*RouteEntry, error) {
	return r.lookupByIndex(redisHostnameIdx + strings.ToLower(hostname))
}

// LookupByPathPrefix handles the path-routing half. Path routes need a
// longest-prefix match rather than an exact key lookup, so this scans the
// (typically small) set of registered path keys instead of doing a single
// GET, mirroring Router.matchPath's local semantics.
func (r *RedisStateStore) LookupByPathPrefix(path string) (*RouteEntry, error) {
	ctx := context.Background()
	reqPath := normalizePath(path)

	keys, err := r.scanKeys(ctx, redisPathIdx+"*")
	if err != nil {
		return nil, fmt.Errorf("scan path routes: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil //nolint:nilnil // not found is not an error
	}

	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("mget path routes: %w", err)
	}

	var bestRouteID string
	bestLen := 0
	for i, key := range keys {
		v, ok := values[i].(string)
		if !ok || v == "" {
			continue
		}
		prefix := strings.TrimPrefix(key, redisPathIdx)
		if strings.HasPrefix(reqPath, prefix) && len(prefix) > bestLen {
			bestRouteID = v
			bestLen = len(prefix)
		}
	}
	if bestRouteID == "" {
		return nil, nil //nolint:nilnil // not found is not an error
	}
	return r.getRouteEntry(ctx, bestRouteID)
}

func (r *RedisStateStore) ListRoutes() ([]RouteEntry, error) {
	raw, err := r.scanJSON(context.Background(), redisRoutePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	out := make([]RouteEntry, 0, len(raw))
	for _, b := range raw {
		var entry RouteEntry
		if json.Unmarshal(b, &entry) == nil {
			out = append(out, entry)
		}
	}
	return out, nil
}

func (r *RedisStateStore) NodeHeartbeat(info NodeInfo) error {
	ctx := context.Background()
	info.LastHeartbeat = time.Now()

	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal node info: %w", err)
	}

	return r.client.Set(ctx, redisNodePrefix+info.NodeID, data, defaultNodeTTL).Err()
}

func (r *RedisStateStore) GetNodes() ([]NodeInfo, error) {
	raw, err := r.scanJSON(context.Background(), redisNodePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("get nodes: %w", err)
	}
	out := make([]NodeInfo, 0, len(raw))
	for _, b := range raw {
		var info NodeInfo
		if json.Unmarshal(b, &info) == nil {
			out = append(out, info)
		}
	}
	return out, nil
}

// scanKeys returns all keys matching keyPattern using SCAN rather than KEYS:
// KEYS blocks the single-threaded Redis event loop for its entire
// O(N) traversal of the whole keyspace, which is a real availability risk
// once the keyspace holds more than a trivial number of entries. SCAN
// iterates in bounded-size cursor batches instead.
func (r *RedisStateStore) scanKeys(ctx context.Context, keyPattern string) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := r.client.Scan(ctx, cursor, keyPattern, redisScanCount).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

// scanJSON fetches all values matching keyPattern from Redis and returns them as
// a slice of raw JSON byte slices, using SCAN + a single MGET per batch of
// keys to minimize round-trips without blocking on KEYS.
func (r *RedisStateStore) scanJSON(ctx context.Context, keyPattern string) ([][]byte, error) {
	keys, err := r.scanKeys(ctx, keyPattern)
	if err != nil {
		return nil, fmt.Errorf("scan keys %q: %w", keyPattern, err)
	}
	if len(keys) == 0 {
		return nil, nil
	}

	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("mget %q: %w", keyPattern, err)
	}

	out := make([][]byte, 0, len(values))
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			continue
		}
		out = append(out, []byte(s))
	}
	return out, nil
}

// EvictDeadNodes is a no-op for Redis because Redis TTL handles expiry
// automatically: a dead node stops refreshing its own routes (see
// Server.refreshClusterRoutes) and its wormhole:node:<id> heartbeat key
// and abandoned route/index keys all expire via their own TTLs without
// needing an explicit sweep.
func (r *RedisStateStore) EvictDeadNodes(_ time.Duration) error {
	return nil
}

func (r *RedisStateStore) Close() error {
	return r.client.Close()
}
