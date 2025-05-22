package tests

import (
	"testing"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

func TestIsValidID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected bool
	}{
		{"Valid UUID with hyphens", "123e4567-e89b-12d3-a456-426614174000", true},
		{"Valid UUID without hyphens", "123e4567e89b12d3a456426614174000", true},
		{"Valid UUID uppercase", "123E4567-E89B-12D3-A456-426614174000", true},
		{"Valid UUID mixed case", "123e4567-E89b-12d3-A456-426614174000", true},
		{"Valid UUID with spaces", "  123e4567-e89b-12d3-a456-426614174000  ", true},

		{"Empty ID", "", false},
		{"Invalid format (too short)", "123e4567", false},
		{"Invalid format (too long)", "123e4567-e89b-12d3-a456-4266141740001234", false},
		{"Invalid format (non-hex chars)", "123e4567-e89b-12d3-a456-42661417400g", false},
		{"Invalid format (wrong segment lengths)", "123e45-e89b1-12d-a456-426614174000", false},
		{"Invalid format (extra hyphens)", "123e4567--e89b-12d3-a456-426614174000", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validator.IsValidID(test.id)
			if result != test.expected {
				t.Errorf("IsValidID(%q) = %v, expected %v", test.id, result, test.expected)
			}
		})
	}
}
