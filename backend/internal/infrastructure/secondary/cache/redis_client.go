// internal/infrastructure/secondary/cache/redis_client.go
package cache

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

// RedisConfig holds redis connection configuration
type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

// RedisClient provides a wrapper around the redis client
type RedisClient struct {
	client *redis.Client
	logger logger.Logger
}

// NewRedisClient creates a new Redis client
func NewRedisClient(config *viper.Viper, logger logger.Logger) (*RedisClient, error) {
	redisConfig := RedisConfig{
		Host:     config.GetString("redis.host"),
		Port:     config.GetString("redis.port"),
		Password: config.GetString("redis.password"),
		DB:       config.GetInt("redis.db"),
	}

	logger.Info("Initializing Redis client",
		model.NewField("host", redisConfig.Host),
		model.NewField("port", redisConfig.Port),
		model.NewField("db", redisConfig.DB))

	client := redis.NewClient(&redis.Options{
		Addr:     redisConfig.Host + ":" + redisConfig.Port,
		Password: redisConfig.Password,
		DB:       redisConfig.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		logger.Error("Failed to connect to Redis",
			model.NewField("error", err.Error()))
		return nil, err
	}

	logger.Info("Redis connection established successfully")
	return &RedisClient{
		client: client,
		logger: logger,
	}, nil
}

// Close closes the redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// GetClient returns the underlying redis client
func (r *RedisClient) GetClient() *redis.Client {
	return r.client
}
