// internal/infrastructure/secondary/cache/factory.go
package cache

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/cache"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/spf13/viper"
)

// Factory provides methods to create rate limiter implementations
type Factory interface {
	// CreateRateLimiter creates a rate limiter implementation
	CreateRateLimiter() cache.RateLimiter

	// Close closes any connections created by the factory
	Close() error
}

// RedisFactory implements Factory with Redis
type RedisFactory struct {
	redisClient *RedisClient
	logger      logger.Logger
}

// NewRedisFactory creates a new Redis factory
func NewRedisFactory(config *viper.Viper, logger logger.Logger) (Factory, error) {
	redisClient, err := NewRedisClient(config, logger)
	if err != nil {
		return nil, err
	}

	return &RedisFactory{
		redisClient: redisClient,
		logger:      logger,
	}, nil
}

// CreateRateLimiter creates a Redis-based rate limiter
func (f *RedisFactory) CreateRateLimiter() cache.RateLimiter {
	return NewRedisRateLimiter(f.redisClient, f.logger)
}

// Close closes Redis connections
func (f *RedisFactory) Close() error {
	return f.redisClient.Close()
}
