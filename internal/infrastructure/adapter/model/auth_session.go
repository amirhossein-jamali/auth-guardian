package model

import (
	"time"
)

// AuthSession represents the database model for authentication sessions
type AuthSession struct {
	ID             string    `gorm:"primaryKey;type:uuid"`
	UserID         string    `gorm:"type:uuid;index"`
	RefreshToken   string    `gorm:"type:text;uniqueIndex"`
	UserAgent      string    `gorm:"type:varchar(255)"`
	IP             string    `gorm:"type:varchar(45)"`
	ExpiresAt      time.Time `gorm:"index"`
	LastActivityAt time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TableName specifies the table name for the AuthSession model
func (AuthSession) TableName() string {
	return "auth_sessions"
}
