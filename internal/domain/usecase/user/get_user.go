package user

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

// GetUserInput represents data needed to get a user
type GetUserInput struct {
	UserID string
}

// GetUserOutput represents the result of getting a user
type GetUserOutput struct {
	User *entity.User
}

// GetUserUseCase handles getting a user by ID
type GetUserUseCase struct {
	userRepo     repository.UserRepository
	logger       logger.Logger
	timeProvider tport.Provider
}

// NewGetUserUseCase creates a new instance of GetUserUseCase
func NewGetUserUseCase(
	userRepo repository.UserRepository,
	logger logger.Logger,
	timeProvider tport.Provider,
) *GetUserUseCase {
	return &GetUserUseCase{
		userRepo:     userRepo,
		logger:       logger,
		timeProvider: timeProvider,
	}
}

// Execute gets a user by ID
func (uc *GetUserUseCase) Execute(ctx context.Context, input GetUserInput) (*GetUserOutput, error) {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Validate user ID
	if err := validator.ValidateID("userID", input.UserID); err != nil {
		return nil, err
	}

	// Get user by ID
	user, err := uc.userRepo.GetByID(ctx, entity.ID(input.UserID))
	if err != nil {
		uc.logger.Error("Failed to get user by ID", map[string]any{
			"userId": input.UserID,
			"error":  err.Error(),
		})
		return nil, err
	}

	if user == nil {
		return nil, domainErr.ErrUserNotFound
	}

	// Log successful retrieval with execution time
	elapsed := uc.timeProvider.Since(startTime)
	uc.logger.Info("User retrieved successfully", map[string]any{
		"userId":  input.UserID,
		"elapsed": elapsed.String(),
	})

	return &GetUserOutput{
		User: user,
	}, nil
}
