package redis

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"
	"github.com/redis/go-redis/v9"
)

// RedisKeyValueStore implements the storage.KeyValueStore interface using Redis
type RedisKeyValueStore struct {
	client *redis.Client
}

// NewRedisKeyValueStore creates a new RedisKeyValueStore instance
func NewRedisKeyValueStore(client *redis.Client) storage.KeyValueStore {
	return &RedisKeyValueStore{
		client: client,
	}
}

// Set sets a key-value pair with expiration
func (s *RedisKeyValueStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	err := s.client.Set(ctx, key, value, expiration).Err()
	return MapError(err)
}

// Get gets a value by key
func (s *RedisKeyValueStore) Get(ctx context.Context, key string) (string, error) {
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return "", MapError(err)
	}
	return val, nil
}

// Delete deletes keys
func (s *RedisKeyValueStore) Delete(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	count, err := s.client.Del(ctx, keys...).Result()
	if err != nil {
		return 0, MapError(err)
	}
	return count, nil
}

// Exists checks if keys exist
func (s *RedisKeyValueStore) Exists(ctx context.Context, keys ...string) (bool, error) {
	if len(keys) == 0 {
		return false, nil
	}

	count, err := s.client.Exists(ctx, keys...).Result()
	if err != nil {
		return false, MapError(err)
	}
	return count > 0, nil
}
