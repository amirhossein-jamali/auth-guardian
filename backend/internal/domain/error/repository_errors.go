package error

import (
	"errors"
)

var (
	// ErrNotFound is returned when a requested record is not found
	ErrNotFound = errors.New("record not found")

	// ErrUserNotFound is returned when a requested user is not found
	ErrUserNotFound = errors.New("user not found")
)
