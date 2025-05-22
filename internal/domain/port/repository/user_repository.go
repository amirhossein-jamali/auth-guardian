package repository

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Create creates a new user
	Create(ctx context.Context, user *entity.User) error
	// GetByID gets a user by ID
	GetByID(ctx context.Context, id entity.ID) (*entity.User, error)
	// GetByEmail gets a user by email
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	// Update updates a user
	Update(ctx context.Context, user *entity.User) error
	// Delete deletes a user
	Delete(ctx context.Context, id entity.ID) error
	// EmailExists checks if an email exists
	EmailExists(ctx context.Context, email string) (bool, error)
	// ExecuteInTransaction executes operations within a transaction
	ExecuteInTransaction(ctx context.Context, fn func(txRepo UserRepository) error) error
}
