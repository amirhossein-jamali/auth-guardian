package database

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/spf13/viper"
)

// Initialize sets up the database connection and prepares it for use
func Initialize(config *viper.Viper, log logger.Logger, timeProvider tport.Provider) (*DBManager, error) {
	// Create database configuration
	dbConfig := NewDatabaseConfigFromViper(config, timeProvider)

	// Create DB manager
	dbManager, err := NewDBManager(dbConfig, log, timeProvider)
	if err != nil {
		log.Error("Failed to create database manager", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	return dbManager, nil
}

// PerformMigrations runs all database migrations
func PerformMigrations(dbManager *DBManager) error {
	migrationManager := dbManager.GetMigrationManager()
	return migrationManager.MigrateAll()
}

// CloseDatabase gracefully closes the database connection
func CloseDatabase(dbManager *DBManager) error {
	return dbManager.Close()
}

// CheckDatabaseHealth verifies database connectivity
func CheckDatabaseHealth(ctx context.Context, dbManager *DBManager) error {
	return dbManager.HealthCheck(ctx)
}
