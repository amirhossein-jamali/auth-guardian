package model

import (
	"time"
)

// MigrationVersion tracks database schema migrations
type MigrationVersion struct {
	ID        uint      `gorm:"primaryKey"`
	Version   string    `gorm:"uniqueIndex;not null"`
	AppliedAt time.Time `gorm:"not null"`
	Notes     string
}

// TableName overrides the table name
func (MigrationVersion) TableName() string {
	return "auth_migration_versions"
}
