package repository

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	repo "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/database"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/model"

	"gorm.io/gorm"
)

// GormUserRepository implements the UserRepository interface using GORM
type GormUserRepository struct {
	db           *gorm.DB
	logger       lport.Logger
	contextUtil  ContextChecker
	timeProvider tport.Provider
}

// NewGormUserRepository creates a new GormUserRepository
func NewGormUserRepository(db *gorm.DB, logger lport.Logger, timeProvider tport.Provider) repo.UserRepository {
	return &GormUserRepository{
		db:           db,
		logger:       logger,
		contextUtil:  &DefaultContextChecker{},
		timeProvider: timeProvider,
	}
}

// toModel converts a domain entity to a database model
func (r *GormUserRepository) toModel(user *entity.User) *model.User {
	return &model.User{
		ID:           user.ID.String(),
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		IsActive:     user.IsActive,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

// toEntity converts a database model to a domain entity
func (r *GormUserRepository) toEntity(dbUser model.User) (*entity.User, error) {
	user := &entity.User{
		ID:           entity.ID(dbUser.ID),
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		FirstName:    dbUser.FirstName,
		LastName:     dbUser.LastName,
		IsActive:     dbUser.IsActive,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
	}
	return user, nil
}

// ExecuteInTransaction executes operations within a transaction
func (r *GormUserRepository) ExecuteInTransaction(ctx context.Context, fn func(txRepo repo.UserRepository) error) error {
	// Check if context is valid
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	// Get the DBManager instance
	dbManager := database.GetDBManager()

	// Use DBManager's transaction mechanism
	return dbManager.RunInTransaction(ctx, func(tx *gorm.DB) error {
		// Create a repository that uses the transaction
		txRepo := &GormUserRepository{
			db:           tx,
			logger:       r.logger,
			contextUtil:  r.contextUtil,
			timeProvider: r.timeProvider,
		}

		// Execute the provided function with the transaction-bound repository
		return fn(txRepo)
	})
}

// Create creates a new user
func (r *GormUserRepository) Create(ctx context.Context, user *entity.User) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	dbUser := r.toModel(user)
	result := r.db.WithContext(ctx).Create(dbUser)

	if result.Error != nil {
		r.logger.Error("Failed to create user", map[string]any{
			"userId": user.ID.String(),
			"error":  result.Error.Error(),
		})
	}

	return database.MapError(result.Error)
}

// GetByID gets a user by ID
func (r *GormUserRepository) GetByID(ctx context.Context, id entity.ID) (*entity.User, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return nil, err
	}

	var dbUser model.User
	result := r.db.WithContext(ctx).
		Where("id = ?", id.String()).
		First(&dbUser)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			r.logger.Debug("User not found", map[string]any{"userId": id.String()})
		} else {
			r.logger.Error("Failed to get user by ID", map[string]any{
				"userId": id.String(),
				"error":  result.Error.Error(),
			})
		}
		return nil, database.MapEntityNotFoundError(result.Error, database.EntityTypeUser)
	}

	return r.toEntity(dbUser)
}

// GetByEmail gets a user by email
func (r *GormUserRepository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return nil, err
	}

	var dbUser model.User
	result := r.db.WithContext(ctx).
		Where("email = ?", email).
		First(&dbUser)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			r.logger.Debug("User not found by email", map[string]any{"email": email})
		} else {
			r.logger.Error("Failed to get user by email", map[string]any{
				"email": email,
				"error": result.Error.Error(),
			})
		}
		return nil, database.MapEntityNotFoundError(result.Error, database.EntityTypeUser)
	}

	return r.toEntity(dbUser)
}

// Update updates a user
func (r *GormUserRepository) Update(ctx context.Context, user *entity.User) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	dbUser := r.toModel(user)
	result := r.db.WithContext(ctx).
		Model(&model.User{}).
		Where("id = ?", user.ID.String()).
		Updates(map[string]interface{}{
			"email":         dbUser.Email,
			"password_hash": dbUser.PasswordHash,
			"first_name":    dbUser.FirstName,
			"last_name":     dbUser.LastName,
			"is_active":     dbUser.IsActive,
			"updated_at":    dbUser.UpdatedAt,
		})

	if result.Error != nil {
		r.logger.Error("Failed to update user", map[string]any{
			"userId": user.ID.String(),
			"error":  result.Error.Error(),
		})
		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("User not found for update", map[string]any{"userId": user.ID.String()})
		return domainError.ErrUserNotFound
	}

	return nil
}

// Delete deletes a user
func (r *GormUserRepository) Delete(ctx context.Context, id entity.ID) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("id = ?", id.String()).
		Delete(&model.User{})

	if result.Error != nil {
		r.logger.Error("Failed to delete user", map[string]any{
			"userId": id.String(),
			"error":  result.Error.Error(),
		})
		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("User not found for deletion", map[string]any{"userId": id.String()})
		return domainError.ErrUserNotFound
	}

	return nil
}

// EmailExists checks if an email exists
func (r *GormUserRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return false, err
	}

	var count int64
	result := r.db.WithContext(ctx).
		Model(&model.User{}).
		Where("email = ?", email).
		Count(&count)

	if result.Error != nil {
		r.logger.Error("Failed to check email existence", map[string]any{
			"email": email,
			"error": result.Error.Error(),
		})
		return false, database.MapError(result.Error)
	}

	return count > 0, nil
}
