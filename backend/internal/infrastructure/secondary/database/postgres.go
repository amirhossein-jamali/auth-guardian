package database

import (
	"context"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// PostgresManager implements DBManager for PostgreSQL
type PostgresManager struct {
	db               *gorm.DB
	logger           logger.Logger
	migrationManager MigrationManager
}

// Ensure PostgresManager implements DBManager
var _ DBManager = (*PostgresManager)(nil)

// NewPostgresManager creates a new PostgreSQL database manager
func NewPostgresManager(config *viper.Viper, log logger.Logger) (*PostgresManager, error) {
	dbConfig := NewDatabaseConfigFromViper(config)

	// Log all database configuration values
	log.Info("Database configuration",
		model.NewField("host", dbConfig.Host),
		model.NewField("port", dbConfig.Port),
		model.NewField("user", dbConfig.User),
		model.NewField("database", dbConfig.Database),
		model.NewField("sslMode", dbConfig.SSLMode))

	db, err := connectToPostgres(dbConfig, log)
	if err != nil {
		return nil, err
	}

	migrationManager := NewMigrationManager(db, log)

	return &PostgresManager{
		db:               db,
		logger:           log,
		migrationManager: migrationManager,
	}, nil
}

// GetDB returns the database connection
func (m *PostgresManager) GetDB() *gorm.DB {
	return m.db
}

// GetMigrationManager returns the migration manager
func (m *PostgresManager) GetMigrationManager() MigrationManager {
	return m.migrationManager
}

// Close closes the database connection
func (m *PostgresManager) Close() error {
	sqlDB, err := m.db.DB()
	if err != nil {
		m.logger.Error("Failed to get database instance for closing",
			model.NewField("error", err.Error()))
		return err
	}

	if err := sqlDB.Close(); err != nil {
		m.logger.Error("Error closing database connection",
			model.NewField("error", err.Error()))
		return err
	}

	m.logger.Info("Database connection closed successfully")
	return nil
}

// HealthCheck verifies database connectivity
func (m *PostgresManager) HealthCheck(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	sqlDB, err := m.db.DB()
	if err != nil {
		m.logger.Error("Failed to get database instance for health check",
			model.NewField("error", err.Error()))
		return MapError(err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		m.logger.Error("Failed database health check",
			model.NewField("error", err.Error()))
		return fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}

	m.logger.Debug("Database health check successful")
	return nil
}

// connectToPostgres establishes a connection to PostgreSQL
func connectToPostgres(config *DatabaseConfig, log logger.Logger) (*gorm.DB, error) {
	dsn := config.BuildDSN()

	log.Info("Connecting to PostgreSQL database",
		model.NewField("host", config.Host),
		model.NewField("port", config.Port),
		model.NewField("database", config.Database),
		model.NewField("dsn", dsn))

	// Configure GORM
	gormConfig := &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "auth_", // Use a prefix for all tables
			SingularTable: true,    // Use singular table names
		},
		Logger: newGormLogger(log), // Custom GORM logger adapter
	}

	// Initialize connection with retry logic
	var db *gorm.DB
	var err error
	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3 // Default to 3 retries
	}

	retryBackoff := config.RetryBackoff
	if retryBackoff <= 0 {
		retryBackoff = 2 * time.Second // Default to 2 second backoff
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Warn("Retrying database connection",
				model.NewField("attempt", attempt),
				model.NewField("maxRetries", maxRetries))
			time.Sleep(retryBackoff)
		}

		// Connect to database
		db, err = gorm.Open(postgres.Open(dsn), gormConfig)
		if err == nil {
			break
		}

		log.Error("Failed to connect to database",
			model.NewField("attempt", attempt),
			model.NewField("error", err.Error()))
	}

	if err != nil {
		log.Error("All connection attempts failed",
			model.NewField("maxRetries", maxRetries),
			model.NewField("error", err.Error()))
		return nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		log.Error("Failed to get database connection",
			model.NewField("error", err.Error()))
		return nil, err
	}

	// Set max connections
	if config.MaxConnections > 0 {
		sqlDB.SetMaxOpenConns(config.MaxConnections)
	}

	// Set max idle connections
	if config.MaxIdleConnections > 0 {
		sqlDB.SetMaxIdleConns(config.MaxIdleConnections)
	}

	// Set connection max lifetime
	if config.MaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(config.MaxLifetime)
	}

	// Verify connection
	if err := sqlDB.Ping(); err != nil {
		log.Error("Failed to ping database",
			model.NewField("error", err.Error()))
		return nil, fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}

	log.Info("Successfully connected to PostgreSQL database")
	return db, nil
}
