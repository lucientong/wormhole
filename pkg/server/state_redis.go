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

func (r *RedisStateStore) RegisterRoute(entry RouteEntry) error {
	ctx := context.Background()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal route entry: %w", err)
	}

	pipe := r.client.Pipeline()
	pipe.Set(ctx, redisRoutePrefix+entry.ClientID, data, defaultRouteTTL)
	pipe.Set(ctx, redisSubdomainIdx+entry.Subdomain, entry.ClientID, defaultRouteTTL)
	_, err = pipe.Exec(ctx)
	return err
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
