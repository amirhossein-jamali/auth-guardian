package database

import (
	"context"
	"errors"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/model"

	"gorm.io/gorm"
)

const (
	// CurrentSchemaVersion represents the current database schema version
	CurrentSchemaVersion = "1.0.1"
)

// MigrationManager handles database schema migrations
type MigrationManager struct {
	db           *gorm.DB
	logger       logger.Logger
	timeProvider tport.Provider
}

// NewMigrationManager creates a new MigrationManager
func NewMigrationManager(db *gorm.DB, logger logger.Logger, timeProvider tport.Provider) *MigrationManager {
	return &MigrationManager{
		db:           db,
		logger:       logger,
		timeProvider: timeProvider,
	}
}

// MigrateAll runs migrations for all models
func (m *MigrationManager) MigrateAll() error {
	m.logger.Info("Running database migrations", map[string]any{})

	// Create migration version table first
	if err := m.db.AutoMigrate(&model.MigrationVersion{}); err != nil {
		m.logger.Error("Failed to create migration version table", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	// Models to migrate
	models := []interface{}{
		&model.User{},
		&model.AuthSession{},
		// Add any other models here
	}

	// Migrate all models
	for _, modelEntity := range models {
		tableName := ""
		if tabler, ok := modelEntity.(interface{ TableName() string }); ok {
			tableName = tabler.TableName()
		}

		m.logger.Info("Migrating table", map[string]any{
			"table": tableName,
		})

		if err := m.db.AutoMigrate(modelEntity); err != nil {
			m.logger.Error("Failed to migrate table", map[string]any{
				"table": tableName,
				"error": err.Error(),
			})
			return err
		}
	}

	// Fix for refresh_token column - change from varchar(255) to text
	m.logger.Info("Updating refresh_token column type", map[string]any{})
	if err := m.db.Exec("ALTER TABLE auth_sessions ALTER COLUMN refresh_token TYPE TEXT").Error; err != nil {
		m.logger.Warn("Failed to alter refresh_token column type (may already be text)", map[string]any{
			"error": err.Error(),
		})
		// Continue anyway, as this might fail if column is already TEXT
	}

	// Add foreign key constraints
	if err := m.addForeignKeyConstraints(); err != nil {
		return err
	}

	// Update migration version
	if err := m.setVersion(context.Background(), CurrentSchemaVersion); err != nil {
		m.logger.Error("Failed to update schema version", map[string]any{
			"version": CurrentSchemaVersion,
			"error":   err.Error(),
		})
		return err
	}

	m.logger.Info("Database migrations completed successfully", map[string]any{
		"version": CurrentSchemaVersion,
	})
	return nil
}

// addForeignKeyConstraints adds necessary foreign key relationships
func (m *MigrationManager) addForeignKeyConstraints() error {
	m.logger.Info("Adding foreign key constraints", map[string]any{})

	// Direct approach that bypasses the type mismatch error
	err := m.db.Exec(`
		ALTER TABLE auth_sessions 
		DROP CONSTRAINT IF EXISTS fk_auth_sessions_user_id;
		
		ALTER TABLE auth_sessions
		ADD CONSTRAINT fk_auth_sessions_user_id
		FOREIGN KEY (user_id) 
		REFERENCES users(id) 
		ON DELETE CASCADE;
	`).Error

	if err != nil {
		m.logger.Error("Failed to add foreign key constraints", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	return nil
}

// GetCurrentVersion gets the current migration version
func (m *MigrationManager) GetCurrentVersion(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	var version model.MigrationVersion
	result := m.db.WithContext(ctx).Order("applied_at desc").First(&version)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", nil // No version found
		}
		return "", result.Error
	}

	return version.Version, nil
}

// setVersion records a new migration version
func (m *MigrationManager) setVersion(ctx context.Context, version string) error {
	migrationVersion := model.MigrationVersion{
		Version:   version,
		AppliedAt: m.timeProvider.Now(),
	}

	result := m.db.WithContext(ctx).Create(&migrationVersion)
	return result.Error
}
