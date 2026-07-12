package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisAuthTeamPrefix    = "wormhole:auth:team:"    // wormhole:auth:team:<name> → JSON TeamInfo
	redisAuthRevokedPrefix = "wormhole:auth:revoked:" // wormhole:auth:revoked:<tokenID> → expiry unix (0 = permanent)

	// redisAuthScanCount is the COUNT hint passed to SCAN (see RedisStateStore
	// in pkg/server for the same rationale: SCAN iterates in bounded
	// batches instead of blocking the whole keyspace like KEYS would).
	redisAuthScanCount = 200
)

// RedisStore implements Store using Redis, so that team records and the
// token-revocation blacklist are visible to every node in a cluster instead
// of being trapped in one node's local SQLite file or in-memory map.
// Without this, a token revoked (or a team version bumped) on node A stayed
// valid on node B until an operator manually restarted every other node.
type RedisStore struct {
	client *redis.Client
}

// RedisStoreConfig configures the Redis-backed auth store.
type RedisStoreConfig struct {
	// Addr is the Redis server address (host:port).
	Addr string

	// Password is the Redis AUTH password (optional).
	Password string

	// DB is the Redis database number (default 0).
	DB int
}

// NewRedisStore creates a Redis-backed auth store.
func NewRedisStore(cfg RedisStoreConfig) (*RedisStore, error) {
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

	return &RedisStore{client: client}, nil
}

// newRedisStoreWithClient wraps an already-constructed *redis.Client (e.g.
// one pointed at a miniredis instance in tests).
func newRedisStoreWithClient(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

// SaveTeam saves a team to Redis. Team records have no TTL — they persist
// until explicitly deleted, matching SQLiteStore's semantics.
func (s *RedisStore) SaveTeam(team *TeamInfo) error {
	data, err := json.Marshal(team)
	if err != nil {
		return fmt.Errorf("marshal team: %w", err)
	}
	ctx := context.Background()
	if err := s.client.Set(ctx, redisAuthTeamPrefix+team.Name, data, 0).Err(); err != nil {
		return fmt.Errorf("save team %q: %w", team.Name, err)
	}
	return nil
}

// GetTeam retrieves a team from Redis.
func (s *RedisStore) GetTeam(name string) (*TeamInfo, error) {
	ctx := context.Background()
	data, err := s.client.Get(ctx, redisAuthTeamPrefix+name).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get team %q: %w", name, err)
	}
	var team TeamInfo
	if err := json.Unmarshal(data, &team); err != nil {
		return nil, fmt.Errorf("unmarshal team %q: %w", name, err)
	}
	return &team, nil
}

// ListTeams returns all teams from Redis.
func (s *RedisStore) ListTeams() ([]TeamInfo, error) {
	ctx := context.Background()
	values, err := s.scanValues(ctx, redisAuthTeamPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	teams := make([]TeamInfo, 0, len(values))
	for _, v := range values {
		var team TeamInfo
		if json.Unmarshal(v, &team) == nil {
			teams = append(teams, team)
		}
	}
	return teams, nil
}

// DeleteTeam removes a team from Redis.
func (s *RedisStore) DeleteTeam(name string) error {
	ctx := context.Background()
	if err := s.client.Del(ctx, redisAuthTeamPrefix+name).Err(); err != nil {
		return fmt.Errorf("delete team %q: %w", name, err)
	}
	return nil
}

// SaveRevokedToken saves a revoked token to Redis, shared cluster-wide:
// a token revoked on one node is immediately rejected by every other
// node's ValidatePayload, since they all query the same Redis key. When
// expiresAt is non-zero, the key's own Redis TTL is set to match, so the
// blacklist entry disappears automatically once the token itself would
// have expired anyway (mirrors SQLiteStore/MemoryStore's
// CleanupExpiredRevocations semantics without needing a separate sweep).
func (s *RedisStore) SaveRevokedToken(tokenID string, expiresAt time.Time) error {
	ctx := context.Background()
	key := redisAuthRevokedPrefix + tokenID

	var ttl time.Duration
	if !expiresAt.IsZero() {
		ttl = time.Until(expiresAt)
		if ttl <= 0 {
			// Already expired — nothing meaningful to block, but honor the
			// call by writing a very short-lived marker rather than
			// silently no-oping (matches "revoke" being idempotent/always
			// succeeding, same as MemoryStore/SQLiteStore).
			ttl = time.Second
		}
	}

	if err := s.client.Set(ctx, key, expiresAt.Unix(), ttl).Err(); err != nil {
		return fmt.Errorf("save revoked token %q: %w", tokenID, err)
	}
	return nil
}

// IsTokenRevoked checks if a token is revoked.
func (s *RedisStore) IsTokenRevoked(tokenID string) (bool, error) {
	ctx := context.Background()
	n, err := s.client.Exists(ctx, redisAuthRevokedPrefix+tokenID).Result()
	if err != nil {
		return false, fmt.Errorf("check revoked token %q: %w", tokenID, err)
	}
	return n > 0, nil
}

// RemoveRevokedToken removes a token from the revocation list.
func (s *RedisStore) RemoveRevokedToken(tokenID string) error {
	ctx := context.Background()
	if err := s.client.Del(ctx, redisAuthRevokedPrefix+tokenID).Err(); err != nil {
		return fmt.Errorf("remove revoked token %q: %w", tokenID, err)
	}
	return nil
}

// CleanupExpiredRevocations is a no-op for Redis: SaveRevokedToken already
// sets a matching TTL on every non-permanent revocation, so Redis expires
// them on its own without needing an explicit sweep (mirrors
// RedisStateStore.EvictDeadNodes's rationale in pkg/server for the same
// "TTL already handles it" reason; periodic-sweep callers still
// call this uniformly across all Store implementations).
func (s *RedisStore) CleanupExpiredRevocations() (int, error) {
	return 0, nil
}

// CountRevokedTokens returns the number of revoked tokens currently tracked.
func (s *RedisStore) CountRevokedTokens() (int, error) {
	ctx := context.Background()
	keys, err := s.scanKeys(ctx, redisAuthRevokedPrefix+"*")
	if err != nil {
		return 0, fmt.Errorf("count revoked tokens: %w", err)
	}
	return len(keys), nil
}

// Close closes the Redis client connection.
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// scanKeys returns all keys matching keyPattern using SCAN rather than KEYS
// (the same non-blocking-scan rationale applies here too).
func (s *RedisStore) scanKeys(ctx context.Context, keyPattern string) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := s.client.Scan(ctx, cursor, keyPattern, redisAuthScanCount).Result()
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

// scanValues returns the raw values for all keys matching keyPattern.
func (s *RedisStore) scanValues(ctx context.Context, keyPattern string) ([][]byte, error) {
	keys, err := s.scanKeys(ctx, keyPattern)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	raw, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("mget %q: %w", keyPattern, err)
	}
	out := make([][]byte, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, []byte(s))
		}
	}
	return out, nil
}
