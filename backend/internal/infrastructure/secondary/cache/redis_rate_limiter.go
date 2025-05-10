// internal/infrastructure/secondary/cache/redis_rate_limiter.go
package cache

import (
	"context"
	"strconv"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/cache"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements the RateLimiter interface using Redis
type RedisRateLimiter struct {
	client *RedisClient
	logger logger.Logger
	prefix string
}

// NewRedisRateLimiter creates a new instance of RedisRateLimiter
func NewRedisRateLimiter(client *RedisClient, logger logger.Logger) cache.RateLimiter {
	return &RedisRateLimiter{
		client: client,
		logger: logger,
		prefix: "rate_limit:",
	}
}

// formatKey formats the rate limit key with a prefix
func (r *RedisRateLimiter) formatKey(key string) string {
	return r.prefix + key
}

// Allow checks if a request is allowed based on the key, rate and window
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, rate int, window time.Duration) (bool, error) {
	formattedKey := r.formatKey(key)
	redisClient := r.client.GetClient()

	// First, try to increment the counter
	val, err := redisClient.Incr(ctx, formattedKey).Result()
	if err != nil {
		r.logger.Error("Failed to increment rate limit counter",
			model.NewField("key", key),
			model.NewField("error", err.Error()))
		return true, err // Allow the request on error to degrade gracefully
	}

	// If this is the first request, set the expiry time
	if val == 1 {
		redisClient.Expire(ctx, formattedKey, window)
	}

	// Check if the limit has been reached
	allowed := val <= int64(rate)

	r.logger.Debug("Rate limit check",
		model.NewField("key", key),
		model.NewField("current", val),
		model.NewField("limit", rate),
		model.NewField("window", window.String()),
		model.NewField("allowed", allowed))

	return allowed, nil
}

// Reset resets the counter for a specific key
func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	formattedKey := r.formatKey(key)
	redisClient := r.client.GetClient()

	_, err := redisClient.Del(ctx, formattedKey).Result()
	if err != nil {
		r.logger.Error("Failed to reset rate limit counter",
			model.NewField("key", key),
			model.NewField("error", err.Error()))
		return err
	}

	r.logger.Debug("Rate limit counter reset", model.NewField("key", key))
	return nil
}

// GetRemaining returns the number of remaining requests for a specific key
func (r *RedisRateLimiter) GetRemaining(ctx context.Context, key string, rate int) (int, error) {
	formattedKey := r.formatKey(key)
	redisClient := r.client.GetClient()

	// Get the current counter value
	val, err := redisClient.Get(ctx, formattedKey).Result()
	if err != nil {
		if err == redis.Nil {
			// Key doesn't exist, so all requests are available
			return rate, nil
		}

		r.logger.Error("Failed to get rate limit counter",
			model.NewField("key", key),
			model.NewField("error", err.Error()))
		return 0, err
	}

	// Convert the value to an integer
	count, err := strconv.Atoi(val)
	if err != nil {
		r.logger.Error("Failed to parse rate limit counter",
			model.NewField("key", key),
			model.NewField("value", val),
			model.NewField("error", err.Error()))
		return 0, err
	}

	// Calculate remaining requests
	remaining := rate - count
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// GetTTL returns the time-to-live for a specific key
func (r *RedisRateLimiter) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	formattedKey := r.formatKey(key)
	redisClient := r.client.GetClient()

	ttl, err := redisClient.TTL(ctx, formattedKey).Result()
	if err != nil {
		r.logger.Error("Failed to get TTL for key",
			model.NewField("key", key),
			model.NewField("error", err.Error()))
		return 0, err
	}

	if ttl < 0 {
		// Key doesn't exist or has no expiry
		return 0, nil
	}

	r.logger.Debug("TTL retrieved",
		model.NewField("key", key),
		model.NewField("ttl", ttl.String()))

	return ttl, nil
}
