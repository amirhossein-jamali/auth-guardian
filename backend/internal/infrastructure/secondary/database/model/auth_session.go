package model

import (
	"time"

	"gorm.io/gorm"
)

type AuthSession struct {
	ID           string `gorm:"primaryKey;type:uuid"`
	UserID       string `gorm:"type:uuid;index:idx_auth_sessions_user_id"`
	RefreshToken string `gorm:"unique;not null;index:idx_auth_sessions_refresh_token"`
	UserAgent    string
	IP           string
	ExpiresAt    time.Time `gorm:"index:idx_auth_sessions_expires_at"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (AuthSession) TableName() string {
	return "auth_sessions"
}
