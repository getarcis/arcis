package stores

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/getarcis/arcis/core"
)

// RedisClient is a minimal interface for Redis client libraries.
// Compatible with go-redis (v9+), redigo, and similar clients.
// Implementations should return errors for failed operations.
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, expiration time.Duration) error
	Del(ctx context.Context, key string) error
	TTL(ctx context.Context, key string) (time.Duration, error)
}

// RedisStoreOptions configures the Redis rate limit store.
type RedisStoreOptions struct {
	Prefix   string        // Key prefix (default: "arcis:rl:")
	WindowMs int           // Window size in milliseconds (default: 60000)
	Window   time.Duration // Window size as Duration (overrides WindowMs if set)
}

// RedisRateLimitStore implements core.RateLimitStore using Redis.
// It is safe for use across multiple application instances.
type RedisRateLimitStore struct {
	client RedisClient
	prefix string
	window time.Duration
	ctx    context.Context
}

// NewRedisRateLimitStore creates a new Redis-backed rate limit store.
func NewRedisRateLimitStore(client RedisClient, opts *RedisStoreOptions) *RedisRateLimitStore {
	prefix := "arcis:rl:"
	window := 60 * time.Second

	if opts != nil {
		if opts.Prefix != "" {
			prefix = opts.Prefix
		}
		if opts.Window > 0 {
			window = opts.Window
		} else if opts.WindowMs > 0 {
			window = time.Duration(opts.WindowMs) * time.Millisecond
		}
	}

	return &RedisRateLimitStore{
		client: client,
		prefix: prefix,
		window: window,
		ctx:    context.Background(),
	}
}

// Get retrieves a rate limit entry from Redis.
// Returns nil if the key does not exist or on error (fail-open).
func (s *RedisRateLimitStore) Get(key string) *core.RateLimitEntry {
	fullKey := s.prefix + key

	val, err := s.client.Get(s.ctx, fullKey)
	if err != nil {
		return nil
	}

	count, err := strconv.Atoi(val)
	if err != nil {
		return nil
	}

	ttl, err := s.client.TTL(s.ctx, fullKey)
	if err != nil || ttl <= 0 {
		return nil
	}

	return &core.RateLimitEntry{
		Count:     count,
		ResetTime: time.Now().Add(ttl),
	}
}

// Set stores a rate limit entry in Redis with appropriate TTL.
func (s *RedisRateLimitStore) Set(key string, entry *core.RateLimitEntry) {
	fullKey := s.prefix + key

	ttl := time.Until(entry.ResetTime)
	if ttl <= 0 {
		ttl = s.window
	}

	val := strconv.Itoa(entry.Count)
	_ = s.client.Set(s.ctx, fullKey, val, ttl)
}

// Increment atomically increments the counter for a key.
// On first increment, sets TTL to the window duration.
// Returns the new count, or 1 on error (fail-open).
func (s *RedisRateLimitStore) Increment(key string) int {
	fullKey := s.prefix + key

	count, err := s.client.Incr(s.ctx, fullKey)
	if err != nil {
		return 1 // fail-open
	}

	// Set expiry on first increment
	if count == 1 {
		_ = s.client.Expire(s.ctx, fullKey, s.window)
	}

	return int(count)
}

// Cleanup is a no-op for Redis stores — Redis TTL handles key expiration.
func (s *RedisRateLimitStore) Cleanup() {
	// Redis TTL handles cleanup automatically
}

// Reset deletes a rate limit entry from Redis.
func (s *RedisRateLimitStore) Reset(key string) error {
	return s.client.Del(s.ctx, s.prefix+key)
}

// Close is a no-op — the caller manages the Redis client lifecycle.
func (s *RedisRateLimitStore) Close() error {
	return nil
}

// Ping tests the Redis connection by performing a SET/GET round-trip.
func (s *RedisRateLimitStore) Ping() error {
	testKey := s.prefix + "__ping__"
	err := s.client.Set(s.ctx, testKey, "1", time.Second)
	if err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}
	_ = s.client.Del(s.ctx, testKey)
	return nil
}
