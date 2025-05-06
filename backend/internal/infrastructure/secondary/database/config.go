package database

import (
	"fmt"
	"time"

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
func NewDatabaseConfigFromViper(config *viper.Viper) *DatabaseConfig {
	return &DatabaseConfig{
		Host:               config.GetString("db.host"),
		Port:               config.GetInt("db.port"),
		User:               config.GetString("db.user"),
		Password:           config.GetString("db.password"),
		Database:           config.GetString("db.name"),
		SSLMode:            config.GetString("db.ssl_mode"),
		MaxConnections:     config.GetInt("db.max_connections"),
		MaxIdleConnections: config.GetInt("db.max_idle_connections"),
		MaxLifetime:        config.GetDuration("db.connection_max_lifetime"),
		MaxRetries:         config.GetInt("db.max_retries"),
		RetryBackoff:       config.GetDuration("db.retry_backoff"),
	}
}

// BuildDSN builds the database connection string
func (c *DatabaseConfig) BuildDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}
