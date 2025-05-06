package database

import (
	"context"

	"gorm.io/gorm"
)

// DBManager handles database operations
type DBManager interface {
	// GetDB returns the database connection
	GetDB() *gorm.DB

	// RunInTransaction runs a function within a transaction
	RunInTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error

	// Close closes the database connection
	Close() error

	// GetMigrationManager returns the migration manager
	GetMigrationManager() MigrationManager

	// HealthCheck verifies database connectivity
	HealthCheck(ctx context.Context) error
}

// MigrationManager handles database schema migrations
type MigrationManager interface {
	// MigrateAll runs migrations for all models
	MigrateAll() error

	// SeedData adds initial data to the database if needed
	SeedData() error

	// MigrateModel migrates a single model
	MigrateModel(model interface{}) error

	// GetCurrentVersion gets the current migration version
	GetCurrentVersion(ctx context.Context) (string, error)

	// SetVersion sets a new migration version
	SetVersion(ctx context.Context, version string) error
}
