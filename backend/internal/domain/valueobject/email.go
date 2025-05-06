package valueobject

import (
	"encoding/json"
	"regexp"
	"strings"

	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
)

// Email represents a validated email address
type Email struct {
	value string
}

// NewEmail creates and validates a new Email value object
func NewEmail(email string) (*Email, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, domainError.ErrEmptyEmail
	}

	// More comprehensive email validation regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return nil, domainError.ErrInvalidEmail
	}

	return &Email{value: strings.ToLower(email)}, nil
}

// Value returns the string representation of the email
func (e *Email) Value() string {
	return e.value
}

// Equals compares two Email objects for equality
func (e *Email) Equals(other *Email) bool {
	if e == nil || other == nil {
		return e == other
	}
	return e.value == other.value
}

// String implements the Stringer interface
func (e *Email) String() string {
	if e == nil {
		return ""
	}
	return e.value
}

// Domain returns the domain part of the email
func (e *Email) Domain() string {
	if e == nil {
		return ""
	}
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// LocalPart returns the local part of the email (before @)
func (e *Email) LocalPart() string {
	if e == nil {
		return ""
	}
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// MarshalJSON implements json.Marshaller interface
func (e *Email) MarshalJSON() ([]byte, error) {
	if e == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(e.value)
}

// UnmarshalJSON implements json.Unmarshaler interface
func (e *Email) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	email, err := NewEmail(s)
	if err != nil {
		return err
	}

	*e = *email
	return nil
}

// ParseEmail Parse creates an Email from a string without error checking
// Use with caution - only when you're sure the email is valid
func ParseEmail(email string) *Email {
	e, _ := NewEmail(email)
	return e
}
