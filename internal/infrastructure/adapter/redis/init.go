package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"

	"github.com/redis/go-redis/v9"
)

// Manager handles Redis client lifecycle and provides access to Redis services
type Manager struct {
	client        *redis.Client
	config        *Config
	keyPrefix     string
	keyValueStore storage.KeyValueStore
	logger        *RedisLogger
	cmdHelper     *CommandHelper
}

// NewRedisManager creates a new Redis manager with the provided configuration
func NewRedisManager(config *Config, log logger.Logger) *Manager {
	if config == nil {
		config = DefaultConfig()
	}

	return &Manager{
		config:    config,
		keyPrefix: config.KeyPrefix,
		logger:    NewRedisLogger(log, false), // Default to non-verbose
	}
}

// Initialize connects to Redis and initializes the Redis manager
func (m *Manager) Initialize(ctx context.Context) error {
	client := redis.NewClient(m.config.Options())
	m.client = client

	// Configure Redis logging
	ConfigureRedisLogging(client, m.logger)

	// Test the connection
	err := m.Ping(ctx)
	if err != nil {
		m.logger.LogConnection("Connect", m.config.Address(), err)
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	m.logger.LogConnection("Connect", m.config.Address(), nil)

	// Initialize the key-value store
	m.keyValueStore = NewRedisKeyValueStore(client)

	// Initialize command helper
	m.cmdHelper = NewCommandHelper(client, m.keyPrefix)

	return nil
}

// EnableVerboseLogging enables verbose logging
func (m *Manager) EnableVerboseLogging(enable bool) {
	m.logger.EnableLogging(enable)
	if m.client != nil {
		ConfigureRedisLogging(m.client, m.logger)
	}
}

// SetLogLevel sets the minimum log level
func (m *Manager) SetLogLevel(level logger.LogLevel) {
	m.logger.SetLogLevel(level)
}

// Ping checks the Redis connection
func (m *Manager) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := m.client.Ping(ctx).Result()
	return MapError(err)
}

// Close closes the Redis connection
func (m *Manager) Close() error {
	if m.client != nil {
		m.logger.LogConnection("Disconnect", m.config.Address(), nil)
		return m.client.Close()
	}
	return nil
}

// GetClient returns the Redis client
func (m *Manager) GetClient() *redis.Client {
	return m.client
}

// GetKeyValueStore returns the Redis key-value store
func (m *Manager) GetKeyValueStore() storage.KeyValueStore {
	return m.keyValueStore
}

// GetCommandHelper returns the command helper
func (m *Manager) GetCommandHelper() *CommandHelper {
	return m.cmdHelper
}

// GetFullKey returns a key with the configured prefix
func (m *Manager) GetFullKey(key string) string {
	if m.keyPrefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", m.keyPrefix, key)
}
