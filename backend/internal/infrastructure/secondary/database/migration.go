package database

import (
	"context"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	logField "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	dbModel "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database/model"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

const (
	// CurrentSchemaVersion represents the current database schema version
	CurrentSchemaVersion = "1.0.0"
)

// MigrationManagerImpl implements MigrationManager
type MigrationManagerImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// Ensure MigrationManagerImpl implements MigrationManager
var _ MigrationManager = (*MigrationManagerImpl)(nil)

// NewMigrationManager creates a new MigrationManager
func NewMigrationManager(db *gorm.DB, logger logger.Logger) MigrationManager {
	return &MigrationManagerImpl{
		db:     db,
		logger: logger,
	}
}

// MigrateAll runs migrations for all models
func (m *MigrationManagerImpl) MigrateAll() error {
	m.logger.Info("Running database migrations")

	// First, migrate the MigrationVersion table itself
	if err := m.MigrateModel(&dbModel.MigrationVersion{}); err != nil {
		return err
	}

	// All models to migrate
	models := []interface{}{
		&dbModel.User{},
		// Add future models here
	}

	for _, modelEntity := range models {
		if err := m.MigrateModel(modelEntity); err != nil {
			return err
		}
	}

	// Update the schema version
	ctx := context.Background()
	if err := m.SetVersion(ctx, CurrentSchemaVersion); err != nil {
		m.logger.Error("Failed to update schema version",
			logField.NewField("version", CurrentSchemaVersion),
			logField.NewField("error", err.Error()))
		return err
	}

	m.logger.Info("Database migrations completed successfully",
		logField.NewField("version", CurrentSchemaVersion))
	return nil
}

// MigrateModel runs migration for a single model
func (m *MigrationManagerImpl) MigrateModel(modelEntity interface{}) error {
	// Get table name
	var tableName string
	if tabler, ok := modelEntity.(schema.Tabler); ok {
		tableName = tabler.TableName()
	} else {
		tableName = m.db.NamingStrategy.TableName(modelEntity.(string))
	}

	m.logger.Info("Migrating table", logField.NewField("table", tableName))

	if err := m.db.AutoMigrate(modelEntity); err != nil {
		m.logger.Error("Failed to migrate table",
			logField.NewField("table", tableName),
			logField.NewField("error", err.Error()))
		return err
	}

	m.logger.Info("Successfully migrated table", logField.NewField("table", tableName))
	return nil
}

// GetCurrentVersion gets the current migration version
func (m *MigrationManagerImpl) GetCurrentVersion(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	var version dbModel.MigrationVersion
	result := m.db.WithContext(ctx).Order("id desc").First(&version)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return "", nil // No version found, database might be new
		}
		m.logger.Error("Failed to get current schema version",
			logField.NewField("error", result.Error.Error()))
		return "", MapError(result.Error)
	}

	return version.Version, nil
}

// SetVersion sets a new migration version
func (m *MigrationManagerImpl) SetVersion(ctx context.Context, version string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	currentVersion, err := m.GetCurrentVersion(ctx)
	if err != nil {
		return err
	}

	// If the current version is the same as the new version, no need to update
	if currentVersion == version {
		m.logger.Info("Schema version already up to date",
			logField.NewField("version", version))
		return nil
	}

	// Create a new version record
	versionRecord := dbModel.MigrationVersion{
		Version:   version,
		AppliedAt: time.Now(),
		Notes:     fmt.Sprintf("Migrated from %s to %s", currentVersion, version),
	}

	result := m.db.WithContext(ctx).Create(&versionRecord)
	if result.Error != nil {
		m.logger.Error("Failed to set schema version",
			logField.NewField("version", version),
			logField.NewField("error", result.Error.Error()))
		return MapError(result.Error)
	}

	m.logger.Info("Schema version updated",
		logField.NewField("from", currentVersion),
		logField.NewField("to", version))
	return nil
}

// SeedData adds initial data to the database if needed
func (m *MigrationManagerImpl) SeedData() error {
	m.logger.Info("Running data seeding")

	// Check if users table is empty
	var count int64
	if err := m.db.Model(&dbModel.User{}).Count(&count).Error; err != nil {
		m.logger.Error("Failed to count users", logField.NewField("error", err.Error()))
		return err
	}

	// Only seed data if no users exist
	if count == 0 {
		m.logger.Info("Seeding initial user data")
		// Add initial data here if needed
	} else {
		m.logger.Info("Skipping user data seeding, data already exists")
	}

	m.logger.Info("Data seeding completed successfully")
	return nil
}
