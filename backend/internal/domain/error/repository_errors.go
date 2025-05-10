package error

import (
	"errors"
)

var (
	ErrNotFound     = errors.New("record not found")
	ErrUserNotFound = errors.New("user not found")
)
