package bootstrap

import (
	"strconv"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/database"
	timeAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
	"gorm.io/gorm"
)

// SetupDatabase initializes and configures the database connection
func SetupDatabase(cfg *config.Config, appLogger logger.Logger) *gorm.DB {
	// Create time provider for database
	timeProvider := timeAdapter.NewRealTimeProvider()

	// Convert port string to int
	dbPort, _ := strconv.Atoi(cfg.Database.Port)

	// Create database configuration
	dbConfig := &database.DatabaseConfig{
		Host:               cfg.Database.Host,
		Port:               dbPort,
		User:               cfg.Database.Username,
		Password:           cfg.Database.Password,
		Database:           cfg.Database.Database,
		SSLMode:            cfg.Database.SSLMode,
		MaxConnections:     cfg.Database.MaxOpenConns,
		MaxIdleConnections: cfg.Database.MaxIdleConns,
	}

	// Initialize database manager
	dbManager, err := database.NewDBManager(dbConfig, appLogger, timeProvider)
	if err != nil {
		FatalError("Failed to connect to database", err)
	}

	// Get GORM DB instance
	db := dbManager.GetDB()

	// Run database migrations
	migrationManager := database.NewMigrationManager(db, appLogger, timeProvider)
	if err := migrationManager.MigrateAll(); err != nil {
		FatalError("Failed to run database migrations", err)
	}

	return db
}
