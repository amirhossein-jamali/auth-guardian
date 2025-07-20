package validator

import (
	"regexp"
	"strings"
)

// IsValidEmail checks if an email has valid format
func IsValidEmail(email string) bool {
	// Allow empty email (optional)
	if email == "" {
		return true
	}

	// Trim spaces
	email = strings.TrimSpace(email)

	// Convert to lowercase for consistency
	email = strings.ToLower(email)

	// RFC 5322 compliant email regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// NormalizeEmail normalizes an email address (trims spaces, lowercase)
func NormalizeEmail(email string) string {
	// Return empty string if email is empty
	if email == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email))
}
