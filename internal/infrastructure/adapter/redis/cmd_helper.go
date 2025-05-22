package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// CommandHelper provides helper methods for common Redis operations
type CommandHelper struct {
	client    *redis.Client
	keyPrefix string
}

// NewCommandHelper creates a new command helper
func NewCommandHelper(client *redis.Client, keyPrefix string) *CommandHelper {
	return &CommandHelper{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

// GetFullKey returns a key with the prefix applied
func (h *CommandHelper) GetFullKey(key string) string {
	if h.keyPrefix == "" {
		return key
	}
	return h.keyPrefix + ":" + key
}

// SetJSON sets a JSON value with expiration
func (h *CommandHelper) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return ErrRedisMarshal
	}

	fullKey := h.GetFullKey(key)
	err = h.client.Set(ctx, fullKey, data, expiration).Err()
	return MapError(err)
}

// GetJSON gets a JSON value and unmarshal it into the provided destination
func (h *CommandHelper) GetJSON(ctx context.Context, key string, dest interface{}) error {
	fullKey := h.GetFullKey(key)
	data, err := h.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		return MapError(err)
	}

	if err = json.Unmarshal(data, dest); err != nil {
		return ErrRedisUnmarshal
	}

	return nil
}

// SetWithTTL sets a value with TTL (time to live)
func (h *CommandHelper) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	fullKey := h.GetFullKey(key)
	err := h.client.Set(ctx, fullKey, value, ttl).Err()
	return MapError(err)
}

// SetNX sets a value if the key does not exist (with TTL)
func (h *CommandHelper) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	fullKey := h.GetFullKey(key)
	result, err := h.client.SetNX(ctx, fullKey, value, ttl).Result()
	return result, MapError(err)
}

// GetTTL gets the TTL of a key
func (h *CommandHelper) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	fullKey := h.GetFullKey(key)
	ttl, err := h.client.TTL(ctx, fullKey).Result()
	return ttl, MapError(err)
}

// Increment increments a counter
func (h *CommandHelper) Increment(ctx context.Context, key string) (int64, error) {
	fullKey := h.GetFullKey(key)
	val, err := h.client.Incr(ctx, fullKey).Result()
	return val, MapError(err)
}

// IncrementBy increments a counter by a specific amount
func (h *CommandHelper) IncrementBy(ctx context.Context, key string, value int64) (int64, error) {
	fullKey := h.GetFullKey(key)
	val, err := h.client.IncrBy(ctx, fullKey, value).Result()
	return val, MapError(err)
}

// Delete removes one or more keys
func (h *CommandHelper) Delete(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = h.GetFullKey(key)
	}

	result, err := h.client.Del(ctx, fullKeys...).Result()
	return result, MapError(err)
}
