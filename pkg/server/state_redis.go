package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisRoutePrefix  = "wormhole:route:" // wormhole:route:<clientID>
	redisNodePrefix   = "wormhole:node:"  // wormhole:node:<nodeID>
	redisSubdomainIdx = "wormhole:sub:"   // wormhole:sub:<subdomain> → clientID

	// defaultRouteTTL is how long a route persists after its last heartbeat.
	// Clients periodically refresh their route TTL via NodeHeartbeat.
	defaultRouteTTL = 5 * time.Minute

	// defaultNodeTTL is how long a node heartbeat is kept.
	defaultNodeTTL = 90 * time.Second
)

// RedisStateStore implements StateStore using Redis for multi-node coordination.
//
// Key layout:
//
//	wormhole:route:<clientID>  — JSON RouteEntry, TTL = defaultRouteTTL
//	wormhole:sub:<subdomain>   — clientID string, TTL = defaultRouteTTL
//	wormhole:node:<nodeID>     — JSON NodeInfo, TTL = defaultNodeTTL
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

// RegisterRoute atomically reserves entry.Subdomain via SETNX (S3/H6)
// instead of a plain SET, which previously let two nodes racing to
// register the same subdomain silently overwrite each other
// (last-writer-wins). Semantics:
//
//   - Subdomain free                       → reserve it for entry.ClientID.
//   - Subdomain already owned by entry.ClientID → idempotent TTL refresh.
//   - Subdomain owned by another client whose route entry has expired
//     (crashed without calling UnregisterRoute) → reclaim it.
//   - Subdomain owned by another *live* client  → ErrSubdomainConflict.
func (r *RedisStateStore) RegisterRoute(entry RouteEntry) error {
	ctx := context.Background()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal route entry: %w", err)
	}

	subKey := redisSubdomainIdx + entry.Subdomain
	routeKey := redisRoutePrefix + entry.ClientID

	// SetNX is deprecated in favor of Set/SetArgs with an NX condition; a
	// plain "SET key value NX" reports "not set" as a nil reply rather than
	// a Go error, which SetArgs surfaces as the redis.Nil sentinel.
	_, err = r.client.SetArgs(ctx, subKey, entry.ClientID, redis.SetArgs{
		Mode: "NX",
		TTL:  defaultRouteTTL,
	}).Result()
	switch {
	case err == nil:
		// Reserved successfully.
	case errors.Is(err, redis.Nil):
		if resolveErr := r.resolveSubdomainConflict(ctx, subKey, entry); resolveErr != nil {
			return resolveErr
		}
	default:
		return fmt.Errorf("reserve subdomain %q: %w", entry.Subdomain, err)
	}

	if err := r.client.Set(ctx, routeKey, data, defaultRouteTTL).Err(); err != nil {
		return fmt.Errorf("store route entry: %w", err)
	}
	return nil
}

// resolveSubdomainConflict is called when SetNX on the subdomain index key
// found it already occupied. It distinguishes an idempotent refresh by the
// current owner, a stale reservation left by a crashed node, and a genuine
// conflict with another live owner.
func (r *RedisStateStore) resolveSubdomainConflict(ctx context.Context, subKey string, entry RouteEntry) error {
	existingOwner, err := r.client.Get(ctx, subKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("check subdomain owner %q: %w", entry.Subdomain, err)
	}

	if existingOwner == entry.ClientID {
		// Same client re-registering (e.g. retry) — just refresh the TTL.
		if err := r.client.Expire(ctx, subKey, defaultRouteTTL).Err(); err != nil {
			return fmt.Errorf("refresh subdomain ttl %q: %w", entry.Subdomain, err)
		}
		return nil
	}

	if existingOwner != "" {
		ownerAlive, err := r.client.Exists(ctx, redisRoutePrefix+existingOwner).Result()
		if err != nil {
			return fmt.Errorf("check owner liveness %q: %w", entry.Subdomain, err)
		}
		if ownerAlive > 0 {
			return fmt.Errorf("%w: subdomain %q is held by client %q", ErrSubdomainConflict, entry.Subdomain, existingOwner)
		}
	}

	// Stale reservation (owner's route entry already expired/removed, or
	// the key vanished between SetNX and Get) — reclaim it for entry.ClientID.
	if err := r.client.Set(ctx, subKey, entry.ClientID, defaultRouteTTL).Err(); err != nil {
		return fmt.Errorf("reclaim stale subdomain %q: %w", entry.Subdomain, err)
	}
	return nil
}

func (r *RedisStateStore) UnregisterRoute(clientID string) error {
	ctx := context.Background()

	// Look up the subdomain before deleting.
	routeKey := redisRoutePrefix + clientID
	data, err := r.client.Get(ctx, routeKey).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("lookup route for deletion: %w", err)
	}

	var entry RouteEntry
	if len(data) > 0 {
		_ = json.Unmarshal(data, &entry)
	}

	pipe := r.client.Pipeline()
	pipe.Del(ctx, routeKey)
	if entry.Subdomain != "" {
		pipe.Del(ctx, redisSubdomainIdx+entry.Subdomain)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisStateStore) LookupBySubdomain(subdomain string) (*RouteEntry, error) {
	ctx := context.Background()

	clientID, err := r.client.Get(ctx, redisSubdomainIdx+subdomain).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil //nolint:nilnil // nil means "not found", which is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("lookup subdomain index: %w", err)
	}

	data, err := r.client.Get(ctx, redisRoutePrefix+clientID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil //nolint:nilnil // stale subdomain index; not an error
	}
	if err != nil {
		return nil, fmt.Errorf("lookup route entry: %w", err)
	}

	var entry RouteEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("unmarshal route entry: %w", err)
	}
	return &entry, nil
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

// scanJSON fetches all values matching keyPattern from Redis and returns them as
// a slice of raw JSON byte slices.  It uses a pipeline to minimize round-trips.
func (r *RedisStateStore) scanJSON(ctx context.Context, keyPattern string) ([][]byte, error) {
	keys, err := r.client.Keys(ctx, keyPattern).Result()
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
		if v == nil {
			continue
		}
		out = append(out, []byte(v.(string)))
	}
	return out, nil
}

// EvictDeadNodes is a no-op for Redis because Redis TTL handles expiry automatically.
// The Redis TTL on node keys (defaultNodeTTL) ensures stale entries are cleaned up.
func (r *RedisStateStore) EvictDeadNodes(_ time.Duration) error {
	return nil
}

func (r *RedisStateStore) Close() error {
	return r.client.Close()
}
