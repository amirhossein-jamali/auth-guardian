package error

import (
	"errors"
)

var (
	ErrEmptyEmail       = errors.New("email cannot be empty")
	ErrInvalidEmail     = errors.New("email format is invalid")
	ErrEmptyPassword    = errors.New("password cannot be empty")
	ErrPasswordTooShort = errors.New("password must be at least 8 characters long")
	ErrPasswordTooWeak  = errors.New("password must contain at least one uppercase letter, one lowercase letter, and one digit")
)
