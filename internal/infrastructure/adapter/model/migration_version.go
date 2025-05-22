package model

import (
	"time"
)

// MigrationVersion represents a database migration version
type MigrationVersion struct {
	ID        uint      `gorm:"primaryKey"`
	Version   string    `gorm:"not null"`
	AppliedAt time.Time `gorm:"not null"`
}

// TableName specifies the table name for the MigrationVersion model
func (MigrationVersion) TableName() string {
	return "migration_versions"
}
