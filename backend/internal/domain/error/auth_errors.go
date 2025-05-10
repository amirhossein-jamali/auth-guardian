package error

import (
	"errors"
)

var (
	ErrInvalidCredentials = errors.New("authentication failed: invalid email or password")
	ErrEmailAlreadyExists = errors.New("authentication failed: email is already registered")
	ErrInvalidToken       = errors.New("authentication failed: invalid or expired token")
	ErrInternalServer     = errors.New("authentication failed: internal server error")
	ErrInvalidID          = errors.New("authentication failed: invalid ID format")
	ErrSessionNotFound    = errors.New("authentication failed: session not found")
	ErrSessionExpired     = errors.New("authentication failed: session expired")
)
