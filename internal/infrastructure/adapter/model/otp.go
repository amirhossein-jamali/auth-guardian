package model

import (
	"time"
)

// OTP represents the database model for OTP records
type OTP struct {
	ID           string    `gorm:"column:id;primaryKey;type:uuid;"`
	PhoneNumber  string    `gorm:"column:phone_number;index;not null;"`
	Code         string    `gorm:"column:code;not null;"`
	CreatedAt    time.Time `gorm:"column:created_at;not null;"`
	ExpiresAt    time.Time `gorm:"column:expires_at;not null;"`
	IsUsed       bool      `gorm:"column:is_used;not null;default:false"`
	AttemptCount int       `gorm:"column:attempt_count;not null;default:0"`
} 