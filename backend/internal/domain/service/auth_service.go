package service

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/crypto"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/identification"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
)

// AuthService handles authentication related business logic
type AuthService struct {
	userRepo       repository.UserRepository
	tokenService   jwt.TokenService
	logger         logger.Logger
	passwordHasher crypto.PasswordHasher
	idGenerator    identification.IDGenerator
	idParser       identification.IDParser
}

// NewAuthService creates a new instance of AuthService
func NewAuthService(
	userRepo repository.UserRepository,
	tokenService jwt.TokenService,
	logger logger.Logger,
	passwordHasher crypto.PasswordHasher,
	idGenerator identification.IDGenerator,
	idParser identification.IDParser,
) *AuthService {
	return &AuthService{
		userRepo:       userRepo,
		tokenService:   tokenService,
		logger:         logger,
		passwordHasher: passwordHasher,
		idGenerator:    idGenerator,
		idParser:       idParser,
	}
}

// RegisterInput represents data needed for user registration
type RegisterInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

// RegisterOutput represents the result of a successful registration
type RegisterOutput struct {
	User      *entity.User
	TokenPair *jwt.TokenPair
}

// Register creates a new user account and generates authentication tokens
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	// Validate email
	email, err := valueobject.NewEmail(input.Email)
	if err != nil {
		return nil, err
	}

	// Check if email already exists
	exists, err := s.userRepo.EmailExists(ctx, *email)
	if err != nil {
		s.logger.Error("Failed to check email existence", model.NewField("email", email.Value()), model.NewField("error", err.Error()))
		return nil, err
	}
	if exists {
		return nil, domainError.ErrEmailAlreadyExists
	}

	// Validate password
	password, err := valueobject.NewPassword(input.Password)
	if err != nil {
		return nil, err
	}

	// Hash password using the password hasher adapter
	hashedPassword, err := s.passwordHasher.HashPassword(password.Value())
	if err != nil {
		s.logger.Error("Failed to hash password", model.NewField("error", err.Error()))
		return nil, domainError.ErrInternalServer
	}

	// Create user entity with ID generator
	user := entity.NewUser(
		func() valueobject.ID { return s.idGenerator.GenerateID() },
		*email,
		input.FirstName,
		input.LastName,
		hashedPassword,
	)

	// Save user to repository
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user", model.NewField("error", err.Error()))
		return nil, err
	}

	// Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user)
	if err != nil {
		s.logger.Error("Failed to generate tokens", model.NewField("userId", user.ID.String()), model.NewField("error", err.Error()))
		return nil, domainError.ErrInternalServer
	}

	s.logger.Info("User registered successfully", model.NewField("userId", user.ID.String()), model.NewField("email", email.Value()))

	return &RegisterOutput{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// LoginInput represents data needed for user login
type LoginInput struct {
	Email    string
	Password string
}

// LoginOutput represents the result of a successful login
type LoginOutput struct {
	User      *entity.User
	TokenPair *jwt.TokenPair
}

// Login authenticates a user and generates new tokens
func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	// Validate email
	email, err := valueobject.NewEmail(input.Email)
	if err != nil {
		return nil, err
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, *email)
	if err != nil {
		s.logger.Warn("Login attempt for non-existent user", model.NewField("email", email.Value()))
		return nil, domainError.ErrInvalidCredentials
	}

	// Verify password using the password hasher adapter
	err = s.passwordHasher.ComparePasswords(user.PasswordHash, input.Password)
	if err != nil {
		s.logger.Warn("Invalid password login attempt", model.NewField("userId", user.ID.String()), model.NewField("email", email.Value()))
		return nil, domainError.ErrInvalidCredentials
	}

	// Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user)
	if err != nil {
		s.logger.Error("Failed to generate tokens", model.NewField("userId", user.ID.String()), model.NewField("error", err.Error()))
		return nil, domainError.ErrInternalServer
	}

	s.logger.Info("User logged in successfully", model.NewField("userId", user.ID.String()), model.NewField("email", email.Value()))

	return &LoginOutput{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// RefreshTokenInput represents data needed for token refresh
type RefreshTokenInput struct {
	RefreshToken string
}

// RefreshTokenOutput represents the result of a successful token refresh
type RefreshTokenOutput struct {
	TokenPair *jwt.TokenPair
}

// RefreshToken generates new token pair using a valid refresh token
func (s *AuthService) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	// Validate refresh token
	claims, err := s.tokenService.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		s.logger.Warn("Invalid refresh token", model.NewField("error", err.Error()))
		return nil, domainError.ErrInvalidToken
	}

	// Check if token is blacklisted
	blacklisted, err := s.tokenService.BlacklistCheck(input.RefreshToken)
	if err != nil {
		s.logger.Error("Error checking token blacklist", model.NewField("error", err.Error()))
		return nil, domainError.ErrInternalServer
	}
	if blacklisted {
		s.logger.Warn("Attempt to use blacklisted token", model.NewField("userId", claims.UserID))
		return nil, domainError.ErrInvalidToken
	}

	// Parse the user ID from claims using the ID parser
	userID, err := s.idParser.ParseID(claims.UserID)
	if err != nil {
		s.logger.Error("Invalid user ID in token", model.NewField("userId", claims.UserID))
		return nil, domainError.ErrInvalidToken
	}

	// Get user by ID using the domain value object.ID directly
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("User from token not found", model.NewField("userId", userID.String()))
		return nil, domainError.ErrInvalidToken
	}

	// Revoke old token
	if err := s.tokenService.RevokeToken(input.RefreshToken); err != nil {
		s.logger.Error("Failed to revoke old token", model.NewField("userId", user.ID.String()), model.NewField("error", err.Error()))
		// Continue execution despite token revocation failure
	}

	// Generate new token pair
	tokenPair, err := s.tokenService.GenerateTokenPair(user)
	if err != nil {
		s.logger.Error("Failed to generate new tokens", model.NewField("userId", user.ID.String()), model.NewField("error", err.Error()))
		return nil, domainError.ErrInternalServer
	}

	s.logger.Info("Token refreshed successfully", model.NewField("userId", user.ID.String()))

	return &RefreshTokenOutput{
		TokenPair: tokenPair,
	}, nil
}

// LogoutInput represents data needed for logout
type LogoutInput struct {
	AccessToken  string
	RefreshToken string
}

// Logout invalidates the user's tokens
func (s *AuthService) Logout(ctx context.Context, input LogoutInput) error {
	// Validate token to get user information for logging
	claims, err := s.tokenService.ValidateAccessToken(input.AccessToken)
	if err == nil {
		s.logger.Info("User logout", model.NewField("userId", claims.UserID))
	}

	// Revoke tokens
	// Even if token validation fails, still try to revoke
	if input.AccessToken != "" {
		if err := s.tokenService.RevokeToken(input.AccessToken); err != nil {
			s.logger.Error("Failed to revoke access token", model.NewField("error", err.Error()))
			// Continue execution despite token revocation failure
		}
	}

	if input.RefreshToken != "" {
		if err := s.tokenService.RevokeToken(input.RefreshToken); err != nil {
			s.logger.Error("Failed to revoke refresh token", model.NewField("error", err.Error()))
			// Continue execution despite token revocation failure
		}
	}

	return nil
}
