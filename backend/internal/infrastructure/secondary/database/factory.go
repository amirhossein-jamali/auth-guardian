package database

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/spf13/viper"
)

// DatabaseFactory creates database-related instances
type DatabaseFactory struct {
	config *viper.Viper
	logger logger.Logger
}

// NewDatabaseFactory creates a new DatabaseFactory
func NewDatabaseFactory(config *viper.Viper, logger logger.Logger) *DatabaseFactory {
	return &DatabaseFactory{
		config: config,
		logger: logger,
	}
}

// CreateDBManager creates a database manager
func (f *DatabaseFactory) CreateDBManager() (DBManager, error) {
	return NewPostgresManager(f.config, f.logger)
}
