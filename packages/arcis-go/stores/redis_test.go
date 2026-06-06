package stores

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/getarcis/arcis/core"
)

// mockRedis implements RedisClient for testing.
type mockRedis struct {
	mu   sync.Mutex
	data map[string]string
	ttls map[string]time.Time
	fail bool // simulate Redis errors
}

func newMockRedis() *mockRedis {
	return &mockRedis{
		data: make(map[string]string),
		ttls: make(map[string]time.Time),
	}
}

func (m *mockRedis) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return "", errors.New("redis error")
	}
	val, ok := m.data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	if exp, ok := m.ttls[key]; ok && time.Now().After(exp) {
		delete(m.data, key)
		delete(m.ttls, key)
		return "", errors.New("key expired")
	}
	return val, nil
}

func (m *mockRedis) Set(_ context.Context, key string, value string, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("redis error")
	}
	m.data[key] = value
	if expiration > 0 {
		m.ttls[key] = time.Now().Add(expiration)
	}
	return nil
}

func (m *mockRedis) Incr(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return 0, errors.New("redis error")
	}
	val, ok := m.data[key]
	if !ok {
		m.data[key] = "1"
		return 1, nil
	}
	n := 0
	for _, c := range val {
		n = n*10 + int(c-'0')
	}
	n++
	m.data[key] = itoa(n)
	return int64(n), nil
}

func (m *mockRedis) Expire(_ context.Context, key string, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("redis error")
	}
	m.ttls[key] = time.Now().Add(expiration)
	return nil
}

func (m *mockRedis) Del(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("redis error")
	}
	delete(m.data, key)
	delete(m.ttls, key)
	return nil
}

func (m *mockRedis) TTL(_ context.Context, key string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return 0, errors.New("redis error")
	}
	exp, ok := m.ttls[key]
	if !ok {
		return -1, nil
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		return -1, nil
	}
	return remaining, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func TestNewRedisRateLimitStore_Defaults(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	if store.prefix != "arcis:rl:" {
		t.Errorf("Expected default prefix, got %q", store.prefix)
	}
	if store.window != 60*time.Second {
		t.Errorf("Expected 60s window, got %v", store.window)
	}
}

func TestNewRedisRateLimitStore_CustomOptions(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, &RedisStoreOptions{
		Prefix:   "myapp:",
		WindowMs: 30000,
	})

	if store.prefix != "myapp:" {
		t.Errorf("Expected custom prefix, got %q", store.prefix)
	}
	if store.window != 30*time.Second {
		t.Errorf("Expected 30s window, got %v", store.window)
	}
}

func TestNewRedisRateLimitStore_DurationOverridesMs(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, &RedisStoreOptions{
		WindowMs: 30000,
		Window:   2 * time.Minute,
	})

	if store.window != 2*time.Minute {
		t.Errorf("Duration should override WindowMs, got %v", store.window)
	}
}

func TestRedisStore_Increment_FirstCall(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	count := store.Increment("user1")
	if count != 1 {
		t.Errorf("First increment should be 1, got %d", count)
	}
}

func TestRedisStore_Increment_Multiple(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	store.Increment("user1")
	store.Increment("user1")
	count := store.Increment("user1")

	if count != 3 {
		t.Errorf("Expected count 3, got %d", count)
	}
}

func TestRedisStore_Increment_FailOpen(t *testing.T) {
	mock := newMockRedis()
	mock.fail = true
	store := NewRedisRateLimitStore(mock, nil)

	count := store.Increment("user1")
	if count != 1 {
		t.Errorf("On error should fail-open with count 1, got %d", count)
	}
}

func TestRedisStore_Get_Exists(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	store.Increment("user1")
	store.Increment("user1")
	store.Increment("user1")

	entry := store.Get("user1")
	if entry == nil {
		t.Fatal("Expected non-nil entry")
	}
	if entry.Count != 3 {
		t.Errorf("Expected count 3, got %d", entry.Count)
	}
	if entry.ResetTime.Before(time.Now()) {
		t.Error("ResetTime should be in the future")
	}
}

func TestRedisStore_Get_NotExists(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	entry := store.Get("nonexistent")
	if entry != nil {
		t.Error("Expected nil for non-existent key")
	}
}

func TestRedisStore_Get_FailOpen(t *testing.T) {
	mock := newMockRedis()
	mock.fail = true
	store := NewRedisRateLimitStore(mock, nil)

	entry := store.Get("user1")
	if entry != nil {
		t.Error("Expected nil on error (fail-open)")
	}
}

func TestRedisStore_Set(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	entry := &core.RateLimitEntry{
		Count:     5,
		ResetTime: time.Now().Add(30 * time.Second),
	}
	store.Set("user1", entry)

	got := store.Get("user1")
	if got == nil {
		t.Fatal("Expected non-nil after Set")
	}
	if got.Count != 5 {
		t.Errorf("Expected count 5, got %d", got.Count)
	}
}

func TestRedisStore_Set_ExpiredResetTime(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	// Set with past reset time — should use window as fallback TTL
	entry := &core.RateLimitEntry{
		Count:     5,
		ResetTime: time.Now().Add(-1 * time.Second),
	}
	store.Set("user1", entry)

	got := store.Get("user1")
	if got == nil {
		t.Fatal("Expected non-nil — fallback TTL should keep it alive")
	}
}

func TestRedisStore_Reset(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	store.Increment("user1")
	err := store.Reset("user1")
	if err != nil {
		t.Errorf("Reset failed: %v", err)
	}

	entry := store.Get("user1")
	if entry != nil {
		t.Error("Expected nil after reset")
	}
}

func TestRedisStore_Cleanup_NoOp(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	// Should not panic
	store.Cleanup()
}

func TestRedisStore_Close_NoOp(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	err := store.Close()
	if err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

func TestRedisStore_Ping_Success(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	err := store.Ping()
	if err != nil {
		t.Errorf("Ping should succeed: %v", err)
	}
}

func TestRedisStore_Ping_Failure(t *testing.T) {
	mock := newMockRedis()
	mock.fail = true
	store := NewRedisRateLimitStore(mock, nil)

	err := store.Ping()
	if err == nil {
		t.Error("Ping should fail when Redis is down")
	}
}

func TestRedisStore_ImplementsInterface(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	// Compile-time check
	var _ core.RateLimitStore = store
}

func TestRedisStore_DifferentKeys(t *testing.T) {
	mock := newMockRedis()
	store := NewRedisRateLimitStore(mock, nil)

	store.Increment("user1")
	store.Increment("user1")
	store.Increment("user2")

	e1 := store.Get("user1")
	e2 := store.Get("user2")

	if e1 == nil || e1.Count != 2 {
		t.Errorf("user1 count should be 2, got %v", e1)
	}
	if e2 == nil || e2.Count != 1 {
		t.Errorf("user2 count should be 1, got %v", e2)
	}
}

func TestRedisStore_PrefixIsolation(t *testing.T) {
	mock := newMockRedis()
	store1 := NewRedisRateLimitStore(mock, &RedisStoreOptions{Prefix: "app1:"})
	store2 := NewRedisRateLimitStore(mock, &RedisStoreOptions{Prefix: "app2:"})

	store1.Increment("user1")
	store1.Increment("user1")
	store2.Increment("user1")

	e1 := store1.Get("user1")
	e2 := store2.Get("user1")

	if e1 == nil || e1.Count != 2 {
		t.Errorf("app1:user1 count should be 2, got %v", e1)
	}
	if e2 == nil || e2.Count != 1 {
		t.Errorf("app2:user1 count should be 1, got %v", e2)
	}
}
