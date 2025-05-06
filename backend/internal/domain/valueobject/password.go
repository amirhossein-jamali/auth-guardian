package valueobject

import (
	"encoding/json"
	"unicode"

	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
)

// Password represents a validated password
type Password struct {
	value string
}

// NewPassword creates and validates a new Password value object
func NewPassword(password string) (*Password, error) {
	if password == "" {
		return nil, domainError.ErrEmptyPassword
	}

	if len(password) < 8 {
		return nil, domainError.ErrPasswordTooShort
	}

	hasUpper := false
	hasLower := false
	hasDigit := false

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

	if !hasUpper || !hasLower || !hasDigit {
		return nil, domainError.ErrPasswordTooWeak
	}

	// Special character is recommended but not required
	// We can add additional validation rules here if needed

	return &Password{value: password}, nil
}

// Value returns the string representation of the password
func (p *Password) Value() string {
	if p == nil {
		return ""
	}
	return p.value
}

// Equals compares two Password objects for equality
// Note: This method should be used with caution and only in testing scenarios
func (p *Password) Equals(other *Password) bool {
	if p == nil || other == nil {
		return p == other
	}
	return p.value == other.value
}

// String implements the Stringer interface
// Returns masked password for security
func (p *Password) String() string {
	if p == nil || len(p.value) == 0 {
		return ""
	}

	// Return masked password with only the first character visible
	return p.value[:1] + "********"
}

// Strength returns password strength as a value from 1-5
func (p *Password) Strength() int {
	if p == nil {
		return 0
	}

	strength := 0

	// Base strength
	if len(p.value) >= 8 {
		strength++
	}
	if len(p.value) >= 12 {
		strength++
	}

	// Character diversity
	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false

	for _, char := range p.value {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if hasUpper && hasLower {
		strength++
	}
	if hasDigit {
		strength++
	}
	if hasSpecial {
		strength++
	}

	// Cap at 5
	if strength > 5 {
		strength = 5
	}

	return strength
}

// MarshalJSON implements json.Marshaller interface
// Never serialize the actual password
func (p *Password) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte(`null`), nil
	}
	// Return empty JSON string to prevent password leakage
	return []byte(`""`), nil
}

// UnmarshalJSON implements json.Unmarshaler interface
func (p *Password) UnmarshalJSON(data []byte) error {
	var passwordStr string
	err := json.Unmarshal(data, &passwordStr)
	if err != nil {
		return err
	}

	password, err := NewPassword(passwordStr)
	if err != nil {
		return err
	}

	*p = *password
	return nil
}

// ParsePassword creates a Password from a string without error checking
// Use with caution - only when you're sure the password is valid
func ParsePassword(password string) *Password {
	p, _ := NewPassword(password)
	return p
}
