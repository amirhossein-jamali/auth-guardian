package database

import (
	"fmt"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/spf13/viper"
)

// DatabaseConfig holds configuration for database connections
type DatabaseConfig struct {
	Host               string
	Port               int
	User               string
	Password           string
	Database           string
	SSLMode            string
	MaxConnections     int
	MaxIdleConnections int
	MaxLifetime        time.Duration
	MaxRetries         int
	RetryBackoff       time.Duration
}

// NewDatabaseConfigFromViper creates a database config from viper
func NewDatabaseConfigFromViper(config *viper.Viper, timeProvider time.Provider) *DatabaseConfig {
	// Parse durations using our domain's time provider
	maxLifetime, _ := timeProvider.ParseDuration(config.GetString("db.connection_max_lifetime"))
	retryBackoff, _ := timeProvider.ParseDuration(config.GetString("db.retry_backoff"))

	return &DatabaseConfig{
		Host:               config.GetString("db.host"),
		Port:               config.GetInt("db.port"),
		User:               config.GetString("db.user"),
		Password:           config.GetString("db.password"),
		Database:           config.GetString("db.name"),
		SSLMode:            config.GetString("db.ssl_mode"),
		MaxConnections:     config.GetInt("db.max_connections"),
		MaxIdleConnections: config.GetInt("db.max_idle_connections"),
		MaxLifetime:        maxLifetime,
		MaxRetries:         config.GetInt("db.max_retries"),
		RetryBackoff:       retryBackoff,
	}
}

// BuildDSN builds the database connection string
func (c *DatabaseConfig) BuildDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// BuildLogSafeDSN builds the database connection string with password masked for logging
func (c *DatabaseConfig) BuildLogSafeDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=******** dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Database, c.SSLMode,
	)
}
