package database

import (
	"errors"
	"fmt"

	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"gorm.io/gorm"
)

var (
	// ErrDatabaseConnection indicates a database connection issue
	ErrDatabaseConnection = errors.New("database connection error")

	// ErrDatabaseQuery indicates a query execution error
	ErrDatabaseQuery = errors.New("database query error")
)

// MapError maps database errors to domain errors
func MapError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return domainError.ErrNotFound

	case errors.Is(err, gorm.ErrDuplicatedKey):
		return domainError.ErrEmailAlreadyExists

	case errors.Is(err, gorm.ErrInvalidTransaction):
		return fmt.Errorf("%w: %v", ErrDatabaseQuery, err)

	case errors.Is(err, gorm.ErrInvalidDB):
		return fmt.Errorf("%w: %v", ErrDatabaseConnection, err)
	}

	// For any other database error, return a wrapped error
	return fmt.Errorf("%w: %v", ErrDatabaseQuery, err)
}
