package bootstrap

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	redisAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/redis"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
	"github.com/redis/go-redis/v9"
)

// RateLimiter interface for rate limiting functionality
type RateLimiter interface {
	Allow(ctx context.Context, key string, rate int, window time.Duration) (bool, error)
	GetRemaining(ctx context.Context, key string, rate int) (int, error)
	GetTTL(ctx context.Context, key string) (time.Duration, error)
}

// RedisRateLimiter implements the RateLimiter interface using Redis
type RedisRateLimiter struct {
	client *redis.Client
	logger logger.Logger
}

// Allow implements the RateLimiter.Allow method
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, rate int, window time.Duration) (bool, error) {
	// Create rate limit key with prefix
	rateKey := "rate_limit:" + key

	// Get count of requests
	count, err := r.client.Incr(ctx, rateKey).Result()
	if err != nil {
		return true, err
	}

	// Set expiry if this is a new key
	if count == 1 {
		r.client.Expire(ctx, rateKey, window)
	}

	// Allow if underrate limit
	return count <= int64(rate), nil
}

// GetRemaining implements the RateLimiter.GetRemaining method
func (r *RedisRateLimiter) GetRemaining(ctx context.Context, key string, rate int) (int, error) {
	rateKey := "rate_limit:" + key
	count, err := r.client.Get(ctx, rateKey).Int64()
	if errors.Is(err, redis.Nil) {
		return rate, nil
	}
	if err != nil {
		return 0, err
	}
	remaining := rate - int(count)
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

// GetTTL implements the RateLimiter.GetTTL method
func (r *RedisRateLimiter) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	return r.client.TTL(ctx, key).Result()
}

// SetupRedis initializes and configures the Redis connection
func SetupRedis(ctx context.Context, cfg *config.Config, logger logger.Logger) (*redisAdapter.Manager, *RedisRateLimiter) {
	// Skip Redis setup if not configured
	if cfg.Redis.Host == "" {
		logger.Info("Redis not configured, skipping initialization", nil)
		return nil, nil
	}

	// Convert Redis port string to int
	redisPort, _ := strconv.Atoi(cfg.Redis.Port)

	// Create Redis configuration
	redisConfig := &redisAdapter.Config{
		Host:     cfg.Redis.Host,
		Port:     redisPort,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	// Initialize Redis manager
	redisManager := redisAdapter.NewRedisManager(redisConfig, logger)

	// Connect to Redis
	if err := redisManager.Initialize(ctx); err != nil {
		logger.Warn("Failed to connect to Redis, continuing without it", map[string]any{"error": err.Error()})
		return nil, nil
	}

	logger.Info("Successfully connected to Redis", nil)

	// Create rate limiter if Redis is available
	var rateLimiter *RedisRateLimiter
	if redisManager != nil {
		rateLimiter = &RedisRateLimiter{
			client: redisManager.GetClient(),
			logger: logger,
		}
	}

	return redisManager, rateLimiter
}
