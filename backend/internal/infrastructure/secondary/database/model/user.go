package model

import (
	"time"

	"gorm.io/gorm"
)

// User represents the database schema for users
type User struct {
	ID           string `gorm:"primaryKey;type:uuid"`
	Email        string `gorm:"unique;not null"`
	PasswordHash string `gorm:"not null"`
	FirstName    string
	LastName     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

// TableName overrides the table name
func (User) TableName() string {
	return "auth_users"
}
