package entity

import (
	"time"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// OTP represents a one-time password entity
type OTP struct {
	ID           ID
	PhoneNumber  string
	Code         string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	IsUsed       bool
	AttemptCount int
}

// NewOTP creates a new OTP instance
func NewOTP(id ID, phoneNumber string, code string, expirySeconds int, timeProvider tport.Provider) *OTP {
	now := timeProvider.Now()
	return &OTP{
		ID:           id,
		PhoneNumber:  phoneNumber,
		Code:         code,
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Duration(expirySeconds) * time.Second),
		IsUsed:       false,
		AttemptCount: 0,
	}
}

// IsExpired checks if the OTP has expired
func (o *OTP) IsExpired(timeProvider tport.Provider) bool {
	return timeProvider.Now().After(o.ExpiresAt)
}

// MarkAsUsed marks OTP as used
func (o *OTP) MarkAsUsed(timeProvider tport.Provider) {
	o.IsUsed = true
	o.ExpiresAt = timeProvider.Now() // Immediately expire the OTP
}

// IncrementAttempt increments the attempt counter
func (o *OTP) IncrementAttempt() {
	o.AttemptCount++
}

// HasExceededMaxAttempts checks if the OTP has exceeded max attempts
func (o *OTP) HasExceededMaxAttempts(maxAttempts int) bool {
	return o.AttemptCount >= maxAttempts
}

// Validate checks if the OTP is valid and can be used
func (o *OTP) Validate(code string, maxAttempts int, timeProvider tport.Provider) bool {
	// Check if the OTP is already used
	if o.IsUsed {
		return false
	}

	// Check if the OTP is expired
	if o.IsExpired(timeProvider) {
		return false
	}

	// Check if attempts exceeded
	if o.HasExceededMaxAttempts(maxAttempts) {
		return false
	}

	// Verify the code
	return o.Code == code
}
