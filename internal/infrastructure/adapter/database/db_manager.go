package database

import (
	"context"
	"sync"

	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var (
	instance *DBManager
	mu       sync.RWMutex
)

// DBManager handles database operations
type DBManager struct {
	db           *gorm.DB
	logger       logger.Logger
	config       *DatabaseConfig
	timeProvider tport.Provider
}

// NewDBManager creates a new database manager
func NewDBManager(config *DatabaseConfig, log logger.Logger, timeProvider tport.Provider) (*DBManager, error) {
	log.Info("Connecting to database", map[string]any{
		"host":     config.Host,
		"port":     config.Port,
		"database": config.Database,
		"sslMode":  config.SSLMode,
	})

	db, err := connectWithRetry(config, log, timeProvider)
	if err != nil {
		return nil, err
	}

	manager := &DBManager{
		db:           db,
		logger:       log,
		config:       config,
		timeProvider: timeProvider,
	}

	// Store as singleton instance
	mu.Lock()
	instance = manager
	mu.Unlock()

	return manager, nil
}

// GetDBManager returns the singleton instance of DBManager
func GetDBManager() *DBManager {
	mu.RLock()
	defer mu.RUnlock()

	if instance == nil {
		panic("DBManager not initialized. Call NewDBManager first")
	}

	return instance
}

// GetDB returns the database connection
func (m *DBManager) GetDB() *gorm.DB {
	return m.db
}

// Close closes the database connection
func (m *DBManager) Close() error {
	sqlDB, err := m.db.DB()
	if err != nil {
		m.logger.Error("Failed to get database instance for closing", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	sqlDBWrapper := newSQLDatabaseWrapper(sqlDB)
	if err := sqlDBWrapper.Close(); err != nil {
		m.logger.Error("Error closing database connection", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	m.logger.Info("Database connection closed successfully", map[string]any{})
	return nil
}

// HealthCheck verifies database connectivity
func (m *DBManager) HealthCheck(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	sqlDB, err := m.db.DB()
	if err != nil {
		m.logger.Error("Failed to get database instance for health check", map[string]any{
			"error": err.Error(),
		})
		return MapError(err)
	}

	// Create wrapper for the sqlDB
	sqlDBWrapper := newSQLDatabaseWrapper(sqlDB)

	// Simple ping to check connectivity
	if err := sqlDBWrapper.PingContext(ctx); err != nil {
		m.logger.Error("Database health check failed", map[string]any{
			"error": err.Error(),
		})
		return domainError.ErrDatabaseOperation
	}

	m.logger.Debug("Database health check successful", map[string]any{})
	return nil
}

// RunInTransaction executes operations within a transaction
func (m *DBManager) RunInTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	if ctx.Err() != nil {
		m.logger.Warn("Context already canceled before starting transaction", map[string]any{})
		return ctx.Err()
	}

	m.logger.Debug("Starting database transaction", map[string]any{})
	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := fn(tx)
		if err != nil {
			m.logger.Error("Transaction failed, rolling back", map[string]any{
				"error": err.Error(),
			})
			return err
		}
		m.logger.Debug("Transaction successful, committing", map[string]any{})
		return nil
	})

	if err != nil {
		return MapError(err)
	}

	return nil
}

// GetMigrationManager returns a migration manager for this database
func (m *DBManager) GetMigrationManager() *MigrationManager {
	return NewMigrationManager(m.db, m.logger, m.timeProvider)
}

// configureConnectionPool sets up the connection pool parameters
func configureConnectionPool(sqlDB SQLDatabase, config *DatabaseConfig, timeProvider tport.Provider) error {
	if config.MaxConnections > 0 {
		sqlDB.SetMaxOpenConns(config.MaxConnections)
	}
	if config.MaxIdleConnections > 0 {
		sqlDB.SetMaxIdleConns(config.MaxIdleConnections)
	}
	if config.MaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(config.MaxLifetime, timeProvider)
	}

	return sqlDB.Ping()
}

// connectWithRetry establishes a connection to the database with retry logic
func connectWithRetry(config *DatabaseConfig, log logger.Logger, timeProvider tport.Provider) (*gorm.DB, error) {
	dsn := config.BuildDSN()

	// Log the actual DSN (with password masked)
	dsnForLog := config.BuildLogSafeDSN()
	log.Info("Attempting database connection with DSN", map[string]any{
		"dsn": dsnForLog,
	})

	// Configure GORM
	gormConfig := &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "",   // No table prefix by default
			SingularTable: true, // Use singular table names
		},
		Logger: newGormLoggerWithTimeProvider(log, timeProvider),
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
		retryBackoff = 2 * tport.Second // Default to 2 second backoff
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Warn("Retrying database connection", map[string]any{
				"attempt":    attempt,
				"maxRetries": maxRetries,
			})
			timeProvider.Sleep(retryBackoff.Std())
		}

		// Connect to database
		db, err = gorm.Open(postgres.Open(dsn), gormConfig)
		if err == nil {
			break
		}

		log.Error("Failed to connect to database", map[string]any{
			"attempt": attempt,
			"error":   err.Error(),
			"dsn":     dsnForLog,
		})
	}

	if err != nil {
		log.Error("All connection attempts failed", map[string]any{
			"maxRetries": maxRetries,
			"error":      err.Error(),
			"dsn":        dsnForLog,
		})
		return nil, domainError.ErrDatabaseOperation
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		log.Error("Failed to get database connection", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	// Create a wrapper for the sqlDB to avoid direct dependency on time
	sqlDBWrapper := newSQLDatabaseWrapper(sqlDB)

	// Configure the connection pool
	if err := configureConnectionPool(sqlDBWrapper, config, timeProvider); err != nil {
		log.Error("Failed to configure connection pool", map[string]any{
			"error": err.Error(),
		})
		return nil, domainError.ErrDatabaseOperation
	}

	log.Info("Successfully connected to database", map[string]any{})
	return db, nil
}
