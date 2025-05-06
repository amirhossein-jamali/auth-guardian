package repository

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Create stores a new user in the repository
	Create(ctx context.Context, user *entity.User) error

	// GetByID retrieves a user by their ID
	GetByID(ctx context.Context, id valueobject.ID) (*entity.User, error)

	// GetByEmail retrieves a user by their email address
	GetByEmail(ctx context.Context, email valueobject.Email) (*entity.User, error)

	// Update updates an existing user in the repository
	Update(ctx context.Context, user *entity.User) error

	// Delete removes a user from the repository
	Delete(ctx context.Context, id valueobject.ID) error

	// EmailExists checks if a user with the given email exists
	EmailExists(ctx context.Context, email valueobject.Email) (bool, error)
}
