package validator

import (
	"regexp"
	"strings"
)

// IsValidID checks if an ID string is valid
// Currently checks basic UUID format
func IsValidID(id string) bool {
	if id == "" {
		return false
	}

	// Trim spaces
	id = strings.TrimSpace(id)

	// Check for UUID format (including with and without hyphens)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$`)
	return uuidRegex.MatchString(strings.ToLower(id))
}
