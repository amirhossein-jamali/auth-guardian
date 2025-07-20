package auth

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/idgenerator"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/password"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

// RegisterInput represents data needed for user registration
type RegisterInput struct {
	Email       string // Now optional
	Password    string
	FirstName   string
	LastName    string
	UserAgent   string
	IP          string
	PhoneNumber string // Required field
	OTPCode     string // Required OTP verification code
	SkipOTPValidation bool // If true, skip OTP validation (used when OTP is already verified)
}

// RegisterOutput represents the result of a successful registration
type RegisterOutput struct {
	User         *entity.User
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

// RegisterUseCase handles user registration
type RegisterUseCase struct {
	userRepo       repository.UserRepository
	otpRepo        repository.OTPRepository
	sessionCreator SessionCreator
	passwordHasher password.Hasher
	tokenService   token.TokenService
	idGenerator    idgenerator.IDGenerator
	timeProvider   tport.Provider
	logger         logger.Logger
	maxOTPAttempts int
}

// SessionCreator defines the interface for creating authentication sessions
type SessionCreator interface {
	CreateSession(ctx context.Context, userID entity.ID, refreshToken string, userAgent, ip string, expiresAt int64) error
}

// NewRegisterUseCase creates a new instance of RegisterUseCase
func NewRegisterUseCase(
	userRepo repository.UserRepository,
	otpRepo repository.OTPRepository,
	sessionCreator SessionCreator,
	passwordHasher password.Hasher,
	tokenService token.TokenService,
	idGenerator idgenerator.IDGenerator,
	timeProvider tport.Provider,
	logger logger.Logger,
	maxOTPAttempts int,
) *RegisterUseCase {
	return &RegisterUseCase{
		userRepo:       userRepo,
		otpRepo:        otpRepo,
		sessionCreator: sessionCreator,
		passwordHasher: passwordHasher,
		tokenService:   tokenService,
		idGenerator:    idGenerator,
		timeProvider:   timeProvider,
		logger:         logger,
		maxOTPAttempts: maxOTPAttempts,
	}
}

// Execute creates a new user account and generates authentication tokens
func (uc *RegisterUseCase) Execute(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Validate phone number (required field)
	if err := validator.ValidatePhoneNumber(input.PhoneNumber); err != nil {
		return nil, err
	}

	// Check if phone number already exists
	phoneExists, err := uc.userRepo.PhoneNumberExists(ctx, input.PhoneNumber)
	if err != nil {
		uc.logger.Error("Failed to check phone number existence", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})
		return nil, err
	}

	if phoneExists {
		return nil, domainErr.NewValidationError("phoneNumber", "phone number already exists")
	}

	// Verify OTP code first
	if !input.SkipOTPValidation {
		otp, err := uc.otpRepo.GetByPhoneNumber(ctx, input.PhoneNumber)
		if err != nil {
			uc.logger.Error("Failed to get OTP record", map[string]any{
				"phoneNumber": input.PhoneNumber,
				"error":       err.Error(),
			})
			return nil, domainErr.ErrInvalidOTP
		}

		// Validate the OTP
		if !otp.Validate(input.OTPCode, uc.maxOTPAttempts, uc.timeProvider) {
			// Increment attempt count
			otp.IncrementAttempt()
			if err := uc.otpRepo.Update(ctx, otp); err != nil {
				uc.logger.Error("Failed to update OTP attempts", map[string]any{
					"phoneNumber": input.PhoneNumber,
					"error":       err.Error(),
				})
			}

			if otp.IsExpired(uc.timeProvider) {
				return nil, domainErr.ErrExpiredOTP
			}

			if otp.IsUsed {
				return nil, domainErr.ErrUsedOTP
			}

			if otp.HasExceededMaxAttempts(uc.maxOTPAttempts) {
				return nil, domainErr.ErrMaxAttemptsExceeded
			}

			// Code doesn't match
			return nil, domainErr.ErrInvalidOTP
		}

		// Mark OTP as used
		otp.MarkAsUsed(uc.timeProvider)
		if err := uc.otpRepo.Update(ctx, otp); err != nil {
			uc.logger.Error("Failed to mark OTP as used", map[string]any{
				"phoneNumber": input.PhoneNumber,
				"error":       err.Error(),
			})
			// Continue anyway as this is not critical
		}
	} else {
		uc.logger.Debug("Skipping OTP validation", map[string]any{
			"phoneNumber": input.PhoneNumber,
		})
	}

	// Validate email (now optional)
	if input.Email != "" {
		if err := validator.ValidateEmail(input.Email); err != nil {
			uc.logger.Error("Email validation failed", map[string]any{
				"email": input.Email,
				"error": err.Error(),
			})
			return nil, err
		}

		// Normalize email before checking if it exists
		normalizedEmail := validator.NormalizeEmail(input.Email)
		uc.logger.Debug("Checking if email exists", map[string]any{
			"original_email": input.Email,
			"normalized_email": normalizedEmail,
		})

		// Check if email already exists
		emailExists, err := uc.userRepo.EmailExists(ctx, normalizedEmail)
		if err != nil {
			uc.logger.Error("Failed to check email existence", map[string]any{
				"email": normalizedEmail,
				"error": err.Error(),
			})
			return nil, err
		}

		if emailExists {
			uc.logger.Info("Email already exists", map[string]any{
				"email": normalizedEmail,
			})
			return nil, domainErr.ErrEmailAlreadyExists
		}
	}

	// Validate password
	if err := validator.ValidatePassword(input.Password); err != nil {
		return nil, err
	}

	// Validate names
	if err := validator.ValidateName("firstName", input.FirstName); err != nil {
		return nil, err
	}

	if err := validator.ValidateName("lastName", input.LastName); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := uc.passwordHasher.HashPassword(input.Password)
	if err != nil {
		uc.logger.Error("Failed to hash password", map[string]any{
			"error": err.Error(),
		})
		return nil, domainErr.ErrInternalServer
	}

	// Create user with generated ID
	userId := entity.ID(uc.idGenerator.GenerateID())
	normalizedEmail := validator.NormalizeEmail(input.Email)
	user := entity.NewUser(
		userId,
		normalizedEmail,
		input.PhoneNumber,
		input.FirstName,
		input.LastName,
		uc.timeProvider,
	)

	// Set the hashed password
	user.SetPassword(hashedPassword, uc.timeProvider)

	// Save user to repository
	if err := uc.userRepo.Create(ctx, user); err != nil {
		uc.logger.Error("Failed to create user", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := uc.tokenService.GenerateTokens(user.ID.String())
	if err != nil {
		uc.logger.Error("Failed to generate tokens", map[string]any{
			"userId": user.ID.String(),
			"error":  err.Error(),
		})
		return nil, domainErr.ErrTokenGenerationFailed
	}

	// Validate expiration time
	if expiresAt <= 0 {
		uc.logger.Error("Invalid expiration time received", map[string]any{
			"userId":    user.ID.String(),
			"expiresAt": expiresAt,
		})
		return nil, domainErr.ErrTokenGenerationFailed
	}

	// Create auth session and log errors if it fails, but continue process
	// Token authentication can work without session record
	if err := uc.sessionCreator.CreateSession(
		ctx,
		user.ID,
		refreshToken,
		input.UserAgent,
		input.IP,
		expiresAt,
	); err != nil {
		uc.logger.Warn("Failed to create session but continuing auth process", map[string]any{
			"userId": user.ID.String(),
			"error":  err.Error(),
		})
	}

	// Log successful registration with execution time
	elapsed := uc.timeProvider.Now().Sub(startTime)
	logData := map[string]any{
		"userId":      user.ID.String(),
		"phoneNumber": input.PhoneNumber,
		"elapsed":     elapsed.String(),
	}

	if input.Email != "" {
		logData["email"] = normalizedEmail
	}

	uc.logger.Info("User registered successfully", logData)

	return &RegisterOutput{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}
