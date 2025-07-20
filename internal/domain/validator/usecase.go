package validator

import (
	"regexp"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
)

// ValidateEmail validates an email and returns a specific error if invalid
// Email is now optional (empty email is considered valid)
func ValidateEmail(email string) error {
	// Empty email is now considered valid (optional)
	if email == "" {
		return nil
	}

	if !IsValidEmail(email) {
		return domainErr.ErrInvalidEmail
	}
	return nil
}

// ValidatePhoneNumber validates a phone number and returns a specific error if invalid
func ValidatePhoneNumber(phoneNumber string) error {
	if phoneNumber == "" {
		return domainErr.NewValidationError("phoneNumber", "phone number is required")
	}

	// Basic phone number validation (can be enhanced based on requirements)
	// This pattern allows for various international formats
	phoneRegex := regexp.MustCompile(`^\+?[0-9]{8,15}$`)
	if !phoneRegex.MatchString(phoneNumber) {
		return domainErr.NewValidationError("phoneNumber", "invalid phone number format")
	}

	return nil
}

// ValidatePassword validates a password and returns a specific errors if invalid
func ValidatePassword(password string) error {
	if password == "" {
		return domainErr.NewValidationError("password", "password is required")
	}

	if !IsStrongPassword(password) {
		return domainErr.ErrPasswordTooWeak
	}

	return nil
}

// ValidateName validates a name (first or last) and returns a specific errors if invalid
func ValidateName(fieldName string, name string) error {
	if name == "" {
		return domainErr.NewValidationError(fieldName, fieldName+" is required")
	}
	return nil
}

// ValidateID validates an ID string and returns a specific errors if invalid
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
