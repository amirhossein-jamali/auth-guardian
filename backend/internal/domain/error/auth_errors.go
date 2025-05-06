package error

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailAlreadyExists = errors.New("email is already registered")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrInternalServer     = errors.New("internal server error")
)

// NewAuthenticationFailedError creates a specific authentication error with context
func NewAuthenticationFailedError(reason string) error {
	return fmt.Errorf("authentication failed: %s", reason)
}
