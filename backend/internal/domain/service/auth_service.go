package service

import (
	"context"
	"time"

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

// AuthServiceConfig contains configuration parameters for the AuthService
type AuthServiceConfig struct {
	// MaxSessionsPerUser defines the maximum number of active sessions allowed per user
	MaxSessionsPerUser int64 `mapstructure:"max_sessions_per_user"`

	// LegacyTokenSupportEnabled controls whether to fall back to legacy token methods
	// Set this to false once all clients are migrated to session-based auth
	LegacyTokenSupportEnabled bool `mapstructure:"legacy_token_support_enabled"`

	// SessionCleanupTimeout defines the timeout for session cleanup operations
	SessionCleanupTimeout time.Duration `mapstructure:"session_cleanup_timeout"`
}

// DefaultAuthServiceConfig returns the default configuration for AuthService
func DefaultAuthServiceConfig() *AuthServiceConfig {
	return &AuthServiceConfig{
		MaxSessionsPerUser:        5,
		LegacyTokenSupportEnabled: true, // Enable legacy support by default
		SessionCleanupTimeout:     30 * time.Second,
	}
}

// AuthService handles authentication related business logic
type AuthService struct {
	userRepo        repository.UserRepository
	authSessionRepo repository.AuthSessionRepository
	tokenService    jwt.TokenService
	logger          logger.Logger
	passwordHasher  crypto.PasswordHasher
	idGenerator     identification.IDGenerator
	idParser        identification.IDParser
	config          *AuthServiceConfig
}

// NewAuthService creates a new instance of AuthService
func NewAuthService(
	userRepo repository.UserRepository,
	authSessionRepo repository.AuthSessionRepository,
	tokenService jwt.TokenService,
	logger logger.Logger,
	passwordHasher crypto.PasswordHasher,
	idGenerator identification.IDGenerator,
	idParser identification.IDParser,
	config *AuthServiceConfig,
) *AuthService {
	// If config is nil, use default config
	if config == nil {
		config = DefaultAuthServiceConfig()
	}

	return &AuthService{
		userRepo:        userRepo,
		authSessionRepo: authSessionRepo,
		tokenService:    tokenService,
		logger:          logger,
		passwordHasher:  passwordHasher,
		idGenerator:     idGenerator,
		idParser:        idParser,
		config:          config,
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

	// Create auth session for the new user
	if err := s.createAuthSession(ctx, user.ID, tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt); err != nil {
		s.logger.Error("Failed to store refresh token",
			model.NewField("userId", user.ID.String()),
			model.NewField("error", err.Error()))
		// Continue despite error - don't fail registration if session storage fails
	}

	s.logger.Info("User registered successfully", model.NewField("userId", user.ID.String()), model.NewField("email", email.Value()))

	return &RegisterOutput{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// createAuthSession creates a new auth session for the user
func (s *AuthService) createAuthSession(
	ctx context.Context,
	userID valueobject.ID,
	refreshToken string,
	expiresAt time.Time,
) error {
	userAgent, _ := ctx.Value(valueobject.UserAgentContextKey).(string)
	ip, _ := ctx.Value(valueobject.IPContextKey).(string)

	authSession := entity.NewAuthSession(
		func() valueobject.ID { return s.idGenerator.GenerateID() },
		userID,
		refreshToken,
		userAgent,
		ip,
		expiresAt,
	)

	return s.authSessionRepo.Create(ctx, authSession)
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

	// Try to get user agent from context
	userAgent, _ := ctx.Value("user_agent").(string)

	// Try to find and update existing session if user agent is available
	if userAgent != "" {
		if err := s.handleExistingSession(ctx, user, userAgent, tokenPair); err == nil {
			// Successfully updated existing session
			return &LoginOutput{
				User:      user,
				TokenPair: tokenPair,
			}, nil
		}

		// Check session limits before creating a new one
		if err := s.enforceSessionLimits(ctx, user.ID); err != nil {
			s.logger.Error("Error enforcing session limits",
				model.NewField("userId", user.ID.String()),
				model.NewField("error", err.Error()))
			// Continue anyway, this is not fatal
		}
	}

	// Create new auth session
	if err := s.createAuthSession(ctx, user.ID, tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt); err != nil {
		s.logger.Error("Failed to store refresh token",
			model.NewField("userId", user.ID.String()),
			model.NewField("error", err.Error()))
		// Continue anyway - don't fail the login operation just because session storage failed
	}

	s.logger.Info("User logged in successfully", model.NewField("userId", user.ID.String()), model.NewField("email", email.Value()))

	return &LoginOutput{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// handleExistingSession tries to find and update an existing session
// Returns nil if successful, error otherwise
func (s *AuthService) handleExistingSession(
	ctx context.Context,
	user *entity.User,
	userAgent string,
	tokenPair *jwt.TokenPair,
) error {
	existingSession, err := s.authSessionRepo.GetByUserIDAndUserAgent(ctx, user.ID, userAgent)
	if err != nil {
		return err
	}

	// Found existing session, update it instead of creating a new one
	s.logger.Info("Updating existing session for user",
		model.NewField("userId", user.ID.String()),
		model.NewField("sessionId", existingSession.ID.String()))

	existingSession.UpdateToken(tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt)
	return s.authSessionRepo.Update(ctx, existingSession)
}

// enforceSessionLimits checks and enforces the maximum number of sessions per user
func (s *AuthService) enforceSessionLimits(ctx context.Context, userID valueobject.ID) error {
	// Check if user has reached session limit
	sessionCount, err := s.authSessionRepo.CountByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if sessionCount >= s.config.MaxSessionsPerUser {
		s.logger.Info("User reached session limit",
			model.NewField("userId", userID.String()),
			model.NewField("sessionCount", sessionCount),
			model.NewField("maxSessionsPerUser", s.config.MaxSessionsPerUser))

		// TODO: Phase 2.5 - Implement deletion of oldest session when limit is reached
		// For now, we'll just log the issue
	}

	return nil
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
	// Primary approach: Use auth session repository
	authSession, err := s.authSessionRepo.GetByRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		// If session approach fails and legacy support is enabled, try legacy approach
		if s.config.LegacyTokenSupportEnabled &&
			(err == domainError.ErrInvalidToken || err == domainError.ErrSessionNotFound) {
			return s.legacyRefreshToken(ctx, input)
		}
		s.logger.Warn("Error getting auth session by refresh token", model.NewField("error", err.Error()))
		return nil, domainError.ErrInvalidToken
	}

	// Check expiration (belt and suspenders, repository should already filter expired sessions)
	if authSession.IsExpired() {
		s.handleExpiredSession(ctx, authSession)
		return nil, domainError.ErrSessionExpired
	}

	// Get user by ID
	user, err := s.userRepo.GetByID(ctx, authSession.UserID)
	if err != nil {
		s.logger.Error("User from token not found",
			model.NewField("userId", authSession.UserID.String()))
		return nil, domainError.ErrInvalidToken
	}

	// Generate new token pair
	tokenPair, err := s.tokenService.GenerateTokenPair(user)
	if err != nil {
		s.logger.Error("Failed to generate new tokens",
			model.NewField("userId", user.ID.String()),
			model.NewField("error", err.Error()))
		return nil, domainError.ErrInternalServer
	}

	// Update existing session with new token
	authSession.UpdateToken(tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt)
	if err := s.authSessionRepo.Update(ctx, authSession); err != nil {
		s.logger.Error("Failed to update auth session",
			model.NewField("sessionId", authSession.ID.String()),
			model.NewField("error", err.Error()))
		// Continue anyway - the user will get new tokens but the old session won't be updated
	}

	s.logger.Info("Token refreshed successfully",
		model.NewField("userId", user.ID.String()),
		model.NewField("sessionId", authSession.ID.String()))

	return &RefreshTokenOutput{
		TokenPair: tokenPair,
	}, nil
}

// handleExpiredSession handles cleanup of expired sessions
func (s *AuthService) handleExpiredSession(ctx context.Context, session *entity.AuthSession) {
	s.logger.Warn("Attempt to use expired refresh token",
		model.NewField("userId", session.UserID.String()),
		model.NewField("sessionId", session.ID.String()))

	// Clean up expired session
	if err := s.authSessionRepo.DeleteByID(ctx, session.ID); err != nil {
		s.logger.Error("Failed to delete expired session",
			model.NewField("sessionId", session.ID.String()),
			model.NewField("error", err.Error()))
	}
}

// legacyRefreshToken is the original token refresh method used as fallback
// TODO: Phase 3 - Remove this method once all clients are migrated to session-based auth
func (s *AuthService) legacyRefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	s.logger.Info("Using legacy token refresh mechanism")

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

	// Store the refresh token in a new session
	if err := s.createAuthSession(ctx, user.ID, tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt); err != nil {
		s.logger.Error("Failed to store new refresh token session",
			model.NewField("userId", user.ID.String()),
			model.NewField("error", err.Error()))
		// Continue anyway - don't fail the refresh operation just because session storage failed
	}

	s.logger.Info("Token refreshed successfully (legacy method)", model.NewField("userId", user.ID.String()))

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
	// First try to log the user ID for auditing
	claims, err := s.tokenService.ValidateAccessToken(input.AccessToken)
	if err == nil {
		s.logger.Info("User logout", model.NewField("userId", claims.UserID))
	}

	// Primary logout mechanism: Delete the auth session
	success := false

	if input.RefreshToken != "" {
		authSession, err := s.authSessionRepo.GetByRefreshToken(ctx, input.RefreshToken)
		if err == nil {
			// Session found, delete it
			if err := s.authSessionRepo.DeleteByID(ctx, authSession.ID); err != nil {
				s.logger.Error("Failed to delete auth session",
					model.NewField("sessionId", authSession.ID.String()),
					model.NewField("error", err.Error()))
				// Continue with legacy method as fallback
			} else {
				s.logger.Info("Auth session deleted during logout",
					model.NewField("sessionId", authSession.ID.String()))
				success = true
			}
		}
	}

	// If session-based logout failed and legacy support is enabled, use token blacklisting
	if !success && s.config.LegacyTokenSupportEnabled {
		s.logger.Info("Using legacy token revocation mechanism")

		// Revoke access token
		if input.AccessToken != "" {
			if err := s.tokenService.RevokeToken(input.AccessToken); err != nil {
				s.logger.Error("Failed to revoke access token", model.NewField("error", err.Error()))
			}
		}

		// Revoke refresh token
		if input.RefreshToken != "" {
			if err := s.tokenService.RevokeToken(input.RefreshToken); err != nil {
				s.logger.Error("Failed to revoke refresh token", model.NewField("error", err.Error()))
			}
		}
	}

	return nil
}

// LogoutAll logs out the user from all devices
func (s *AuthService) LogoutAll(ctx context.Context, userIDStr string) error {
	userID, err := s.idParser.ParseID(userIDStr)
	if err != nil {
		return domainError.ErrInvalidID
	}

	// Delete all sessions for this user
	if err := s.authSessionRepo.DeleteByUserID(ctx, userID); err != nil {
		s.logger.Error("Failed to logout from all devices",
			model.NewField("userId", userID.String()),
			model.NewField("error", err.Error()))
		return domainError.ErrInternalServer
	}

	// For legacy support, we could consider blacklisting all tokens for this user
	// However, we don't have a direct way to get all tokens for a user
	// So we'll log this as a limitation of the legacy system
	if s.config.LegacyTokenSupportEnabled {
		s.logger.Info("Note: Legacy tokens may still be valid until they expire naturally",
			model.NewField("userId", userID.String()))
	}

	s.logger.Info("User logged out from all devices",
		model.NewField("userId", userID.String()))

	return nil
}

// GetUserByID retrieves a user by their ID string
func (s *AuthService) GetUserByID(ctx context.Context, userIDStr string) (*entity.User, error) {
	userID, err := s.idParser.ParseID(userIDStr)
	if err != nil {
		return nil, domainError.ErrInvalidID
	}
	return s.userRepo.GetByID(ctx, userID)
}

// UpdateUserProfile updates user's profile information
func (s *AuthService) UpdateUserProfile(ctx context.Context, userIDStr string, firstName, lastName string) (*entity.User, error) {
	userID, err := s.idParser.ParseID(userIDStr)
	if err != nil {
		return nil, domainError.ErrInvalidID
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	user.FirstName = firstName
	user.LastName = lastName
	user.UpdatedAt = time.Now()

	err = s.userRepo.Update(ctx, user)
	return user, err
}

// SessionInfo represents simplified session information for display to users
type SessionInfo struct {
	ID         string    `json:"id"`
	UserAgent  string    `json:"user_agent"`
	IP         string    `json:"ip"`
	LastActive time.Time `json:"last_active"`
	CreatedAt  time.Time `json:"created_at"`
	IsCurrent  bool      `json:"is_current"`
}

// GetActiveSessions retrieves all active sessions for a user
func (s *AuthService) GetActiveSessions(ctx context.Context, userIDStr string) ([]SessionInfo, error) {
	// TODO: Phase 2.5 - Implement this method properly with a repository method
	// For now, it's a placeholder implementation

	userID, err := s.idParser.ParseID(userIDStr)
	if err != nil {
		return nil, domainError.ErrInvalidID
	}

	// Log the request
	s.logger.Info("Get active sessions requested", model.NewField("userId", userID.String()))

	// Return an empty slice for now
	return []SessionInfo{}, nil
}

// CleanupExpiredSessions removes all expired sessions from the repository
func (s *AuthService) CleanupExpiredSessions(ctx context.Context) error {
	// Create a context with timeout for cleanup operation
	cleanupCtx, cancel := context.WithTimeout(ctx, s.config.SessionCleanupTimeout)
	defer cancel()

	// Delete expired sessions
	if err := s.authSessionRepo.DeleteExpired(cleanupCtx); err != nil {
		s.logger.Error("Failed to cleanup expired sessions", model.NewField("error", err.Error()))
		return err
	}

	s.logger.Info("Cleaned up expired sessions")
	return nil
}
