package validator

import (
	"unicode"
)

// IsStrongPassword checks if a password meets security requirements:
// - Minimum 8 characters
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one digit
func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasDigit bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		}
	}

	return hasUpper && hasLower && hasDigit
}
