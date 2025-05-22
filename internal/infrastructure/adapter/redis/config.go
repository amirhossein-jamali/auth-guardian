package redis

import (
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds Redis connection configuration
type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
	// Connection parameters
	PoolSize           int
	MinIdleConnections int
	ConnectTimeout     time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	// TLS configuration
	UseTLS        bool
	TLSSkipVerify bool
	// Other settings
	KeyPrefix string
}

// DefaultConfig returns a default Redis configuration
func DefaultConfig() *Config {
	return &Config{
		Host:               "localhost",
		Port:               6379,
		Password:           "",
		DB:                 0,
		PoolSize:           10,
		MinIdleConnections: 5,
		ConnectTimeout:     5 * time.Second,
		ReadTimeout:        3 * time.Second,
		WriteTimeout:       3 * time.Second,
		UseTLS:             false,
		TLSSkipVerify:      false,
		KeyPrefix:          "",
	}
}

// Address returns the connection address string
func (c *Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Options converts the config to go-redis Options
func (c *Config) Options() *redis.Options {
	opts := &redis.Options{
		Addr:         c.Address(),
		Password:     c.Password,
		DB:           c.DB,
		PoolSize:     c.PoolSize,
		MinIdleConns: c.MinIdleConnections,
		DialTimeout:  c.ConnectTimeout,
		ReadTimeout:  c.ReadTimeout,
		WriteTimeout: c.WriteTimeout,
	}

	return opts
}
