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

// UpdateProfileInput represents data needed to update a user profile
type UpdateProfileInput struct {
	UserID    string
	Email     string // Email is optional
	FirstName string
	LastName  string
	IP        string // Added for audit logging
}

// UpdateProfileOutput represents the result of updating a user profile
type UpdateProfileOutput struct {
	User *entity.User
}

// UpdateProfileUseCase handles updating a user profile
type UpdateProfileUseCase struct {
	userRepo     repository.UserRepository
	timeProvider tport.Provider
	logger       logger.Logger
	auditLogger  logger.AuditLogger
}

// NewUpdateProfileUseCase creates a new instance of UpdateProfileUseCase
func NewUpdateProfileUseCase(
	userRepo repository.UserRepository,
	timeProvider tport.Provider,
	logger logger.Logger,
	auditLogger logger.AuditLogger,
) *UpdateProfileUseCase {
	return &UpdateProfileUseCase{
		userRepo:     userRepo,
		timeProvider: timeProvider,
		logger:       logger,
		auditLogger:  auditLogger,
	}
}

// Execute updates a user profile
func (uc *UpdateProfileUseCase) Execute(ctx context.Context, input UpdateProfileInput) (*UpdateProfileOutput, error) {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Validate user ID
	if err := validator.ValidateID("userID", input.UserID); err != nil {
		return nil, err
	}

	// Get user by ID
	user, err := uc.userRepo.GetByID(ctx, entity.ID(input.UserID))
	if err != nil {
		uc.logger.Error("Failed to get user by ID", map[string]interface{}{
			"userId": input.UserID,
			"error":  err.Error(),
		})
		return nil, err
	}

	if user == nil {
		return nil, domainErr.ErrUserNotFound
	}

	// Store original values for audit logging
	originalEmail := user.Email
	changes := make(map[string]interface{})

	// Validate and update email if provided
	if input.Email != "" {
		// Validate new email format
		if err := validator.ValidateEmail(input.Email); err != nil {
			return nil, err
		}

		// Normalize email
		normalizedEmail := validator.NormalizeEmail(input.Email)

		// Only check for duplicates if email is actually changing
		if normalizedEmail != user.Email {
			// Check if new email already exists
			emailExists, err := uc.userRepo.EmailExists(ctx, normalizedEmail)
			if err != nil {
				uc.logger.Error("Failed to check email existence", map[string]interface{}{
					"email": normalizedEmail,
					"error": err.Error(),
				})
				return nil, err
			}

			if emailExists {
				return nil, domainErr.ErrEmailAlreadyExists
			}

			// Update the email
			user.Email = normalizedEmail
			changes["email"] = map[string]string{
				"old": originalEmail,
				"new": normalizedEmail,
			}
		}
	}

	// Update and validate first name if provided
	if input.FirstName != "" {
		if err := validator.ValidateName("firstName", input.FirstName); err != nil {
			return nil, err
		}

		// Track changes for first name
		if input.FirstName != user.FirstName {
			changes["firstName"] = map[string]string{
				"old": user.FirstName,
				"new": input.FirstName,
			}
			// Update first name
			user.FirstName = input.FirstName
		}
	}

	// Update and validate last name if provided
	if input.LastName != "" {
		if err := validator.ValidateName("lastName", input.LastName); err != nil {
			return nil, err
		}

		// Track changes for last name
		if input.LastName != user.LastName {
			changes["lastName"] = map[string]string{
				"old": user.LastName,
				"new": input.LastName,
			}
			// Update last name
			user.LastName = input.LastName
		}
	}

	// Only update if there were actual changes
	if len(changes) > 0 {
		user.UpdatedAt = uc.timeProvider.Now()

		// Save updated user
		err = uc.userRepo.Update(ctx, user)
		if err != nil {
			uc.logger.Error("Failed to update user", map[string]interface{}{
				"userId": input.UserID,
				"error":  err.Error(),
			})
			return nil, err
		}

		// Log security-sensitive changes if audit logger is available
		if uc.auditLogger != nil {
			metadata := map[string]any{
				"userId":  user.ID.String(),
				"changes": changes,
			}

			if input.IP != "" {
				metadata["ip"] = input.IP
			}

			// Log the event but don't fail if audit logging fails
			if err := uc.auditLogger.LogSecurityEvent(ctx, "profile_updated", metadata); err != nil {
				uc.logger.Warn("Failed to log security event", map[string]any{
					"userId": user.ID.String(),
					"error":  err.Error(),
				})
			}
		}

		// Calculate execution time
		elapsed := uc.timeProvider.Since(startTime)
		uc.logger.Info("User profile updated successfully", map[string]interface{}{
			"userId":  input.UserID,
			"elapsed": elapsed.String(),
		})
	}

	return &UpdateProfileOutput{
		User: user,
	}, nil
}
