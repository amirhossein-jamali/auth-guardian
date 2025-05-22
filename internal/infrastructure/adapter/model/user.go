package model

import (
	"time"
)

// User represents a user in the database
type User struct {
	ID           string `gorm:"primaryKey;type:uuid"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	FirstName    string
	LastName     string
	IsActive     bool      `gorm:"default:true"`
	CreatedAt    time.Time `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}

// TableName specifies the table name for the User model
func (User) TableName() string {
	return "users"
}
