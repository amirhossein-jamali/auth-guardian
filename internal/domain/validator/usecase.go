package validator

import (
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
)

// ValidateEmail validates an email and returns a specific error if invalid
func ValidateEmail(email string) error {
	if !IsValidEmail(email) {
		return domainErr.ErrInvalidEmail
	}
	return nil
}

// ValidatePassword validates a password and returns a specific error if invalid
func ValidatePassword(password string) error {
	if password == "" {
		return domainErr.NewValidationError("password", "password is required")
	}

	if !IsStrongPassword(password) {
		return domainErr.ErrPasswordTooWeak
	}

	return nil
}

// ValidateName validates a name (first or last) and returns a specific error if invalid
func ValidateName(fieldName string, name string) error {
	if name == "" {
		return domainErr.NewValidationError(fieldName, fieldName+" is required")
	}
	return nil
}

// ValidateID validates an ID string and returns a specific error if invalid
func ValidateID(fieldName string, id string) error {
	if !IsValidID(id) {
		return domainErr.NewValidationError(fieldName, fieldName+" is invalid")
	}
	return nil
}

// ValidateRefreshToken validates a refresh token
func ValidateRefreshToken(token string) error {
	if token == "" {
		return domainErr.NewValidationError("refreshToken", "refresh token is required")
	}
	return nil
}

// ValidateExpiresAt validates that an expiration timestamp is valid
func ValidateExpiresAt(expiresAt int64) error {
	if expiresAt <= 0 {
		return domainErr.NewValidationError("expiresAt", "expiration time must be a positive value")
	}
	return nil
}
