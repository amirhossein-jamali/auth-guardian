package database

import (
	"errors"
	"strings"

	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"

	"gorm.io/gorm"
)

// EntityType represents the type of entity for errors mapping
type EntityType string

const (
	// EntityTypeUser represents the user entity
	EntityTypeUser EntityType = "user"
	// EntityTypeSession represents the auth session entity
	EntityTypeSession EntityType = "session"
)

// MapError maps database errors to domain errors
func MapError(err error) error {
	if err == nil {
		return nil
	}

	errMsg := strings.ToLower(err.Error())

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return domainError.ErrNotFound
	case strings.Contains(errMsg, "unique") || strings.Contains(errMsg, "duplicate"):
		// Try to determine which constraint was violated
		if strings.Contains(errMsg, "email") {
			return domainError.ErrEmailAlreadyExists
		} else if strings.Contains(errMsg, "phone") || strings.Contains(errMsg, "phone_number") {
			return domainError.NewValidationError("phoneNumber", "phone number already exists")
		} else {
			// Default uniqueness error if we can't determine the exact field
			return domainError.NewValidationError("field", "value already exists")
		}
	case strings.Contains(errMsg, "foreign key"):
		return domainError.ErrInternalServer
	case strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "deadline exceeded"):
		return domainError.ErrTimeout
	default:
		return domainError.ErrDatabaseOperation
	}
}

// MapEntityNotFoundError maps database errors to specific entity not found errors
func MapEntityNotFoundError(err error, entityType EntityType) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		switch entityType {
		case EntityTypeUser:
			return domainError.ErrUserNotFound
		case EntityTypeSession:
			return domainError.ErrSessionNotFound
		default:
			return domainError.ErrNotFound
		}
	}

	return MapError(err)
}

// MapUserNotFoundError maps database errors to user not found errors
func MapUserNotFoundError(err error) error {
	return MapEntityNotFoundError(err, EntityTypeUser)
}

// MapSessionNotFoundError maps database errors to session not found errors
func MapSessionNotFoundError(err error) error {
	return MapEntityNotFoundError(err, EntityTypeSession)
}
