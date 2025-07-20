package repository

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
)

// OTPRepository defines the interface for OTP data access
type OTPRepository interface {
	// Create creates a new OTP record
	Create(ctx context.Context, otp *entity.OTP) error
	// GetByPhoneNumber gets the latest active OTP for a phone number
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*entity.OTP, error)
	// Update updates an OTP record
	Update(ctx context.Context, otp *entity.OTP) error
	// Delete deletes an OTP record
	Delete(ctx context.Context, otpID entity.ID) error
	// DeleteExpired deletes all expired OTP records
	DeleteExpired(ctx context.Context) (int, error)
}
