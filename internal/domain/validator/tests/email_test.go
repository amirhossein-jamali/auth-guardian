package tests

import (
	"testing"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"Valid email", "user@example.com", true},
		{"Valid email with subdomain", "user@sub.example.com", true},
		{"Valid email with numbers", "user123@example.com", true},
		{"Valid email with dot", "first.last@example.com", true},
		{"Valid email with plus", "user+tag@example.com", true},
		{"Valid email with dash", "user-name@example-site.com", true},
		{"Valid email with uppercase", "USER@EXAMPLE.COM", true},
		{"Valid email with mixed case", "UsEr@ExAmPlE.CoM", true},

		{"Empty email", "", false},
		{"Missing @", "userexample.com", false},
		{"Missing domain", "user@", false},
		{"Missing TLD", "user@example", false},
		{"Invalid TLD (too short)", "user@example.c", false},
		{"Space in email", "user @example.com", false},
		{"Multiple @ symbols", "user@example@com", false},
		{"Special chars not allowed", "user*name@example.com", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validator.IsValidEmail(test.email)
			if result != test.expected {
				t.Errorf("IsValidEmail(%q) = %v, expected %v", test.email, result, test.expected)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{"Already normalized", "user@example.com", "user@example.com"},
		{"With spaces", "  user@example.com  ", "user@example.com"},
		{"Uppercase", "USER@EXAMPLE.COM", "user@example.com"},
		{"Mixed case with spaces", "  UsEr@ExAmPlE.CoM  ", "user@example.com"},
		{"Empty string", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validator.NormalizeEmail(test.email)
			if result != test.expected {
				t.Errorf("NormalizeEmail(%q) = %q, expected %q", test.email, result, test.expected)
			}
		})
	}
}
