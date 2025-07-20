package auth

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/password"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/risk"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

// LoginInput represents data needed for user login
type LoginInput struct {
	Email       string // Optional - user can login with either email or phone
	PhoneNumber string // Optional - user can login with either email or phone
	Password    string
	UserAgent   string
	IP          string
}

// LoginOutput represents the result of a successful login
type LoginOutput struct {
	User         *entity.User
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

// LoginUseCase handles user login
type LoginUseCase struct {
	userRepo        repository.UserRepository
	authSessionRepo repository.AuthSessionRepository
	sessionCreator  SessionCreator
	passwordHasher  password.Hasher
	tokenService    token.TokenService
	timeProvider    tport.Provider
	logger          logger.Logger
	maxSessions     int64
	// New fields
	metricsRecorder metrics.Recorder
	riskEvaluator   risk.Evaluator
	auditLogger     logger.AuditLogger
}

// NewLoginUseCase creates a new instance of LoginUseCase
func NewLoginUseCase(
	userRepo repository.UserRepository,
	authSessionRepo repository.AuthSessionRepository,
	sessionCreator SessionCreator,
	passwordHasher password.Hasher,
	tokenService token.TokenService,
	timeProvider tport.Provider,
	logger logger.Logger,
	maxSessions int64,
	// Optional components
	options ...LoginUseCaseOption,
) *LoginUseCase {
	uc := &LoginUseCase{
		userRepo:        userRepo,
		authSessionRepo: authSessionRepo,
		sessionCreator:  sessionCreator,
		passwordHasher:  passwordHasher,
		tokenService:    tokenService,
		timeProvider:    timeProvider,
		logger:          logger,
		maxSessions:     maxSessions,
	}

	// Apply options
	for _, option := range options {
		option(uc)
	}

	return uc
}

// LoginUseCaseOption defines a login use case option function
type LoginUseCaseOption func(*LoginUseCase)

// WithMetricsRecorder sets the metrics recorder for login use case
func WithMetricsRecorder(metricsRecorder metrics.Recorder) LoginUseCaseOption {
	return func(uc *LoginUseCase) {
		uc.metricsRecorder = metricsRecorder
	}
}

// WithRiskEvaluator sets the risk evaluator for login use case
func WithRiskEvaluator(riskEvaluator risk.Evaluator) LoginUseCaseOption {
	return func(uc *LoginUseCase) {
		uc.riskEvaluator = riskEvaluator
	}
}

// WithAuditLogger sets the audit logger for login use case
func WithAuditLogger(auditLogger logger.AuditLogger) LoginUseCaseOption {
	return func(uc *LoginUseCase) {
		uc.auditLogger = auditLogger
	}
}

// Execute authenticates a user and generates new tokens
func (uc *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Record login attempt metric if metrics recorder is available
	if uc.metricsRecorder != nil {
		uc.metricsRecorder.IncCounter("login_attempts", map[string]string{})
	}

	// Validate that at least one of email or phone number is provided
	if input.Email == "" && input.PhoneNumber == "" {
		return nil, domainErr.NewValidationError("authentication", "either email or phone number must be provided")
	}

	// Validate password (only check if it's not empty for login)
	if input.Password == "" {
		return nil, domainErr.NewValidationError("password", "password is required")
	}

	var user *entity.User
	var err error
	var identifier string // For logging purposes

	// Try to get user by email if provided
	if input.Email != "" {
		// Validate email format
		if err := validator.ValidateEmail(input.Email); err != nil {
			return nil, err
		}

		// Normalize email
		normalizedEmail := validator.NormalizeEmail(input.Email)
		identifier = normalizedEmail

		// Get user by normalized email
		user, err = uc.userRepo.GetByEmail(ctx, normalizedEmail)
		if err != nil && !domainErr.IsNotFound(err) {
			uc.logger.Error("Failed to get user by email", map[string]any{
				"email": normalizedEmail,
				"error": err.Error(),
			})
			return nil, err
		}
	}

	// Try to get user by phone number if email wasn't provided or no user was found with that email
	if user == nil && input.PhoneNumber != "" {
		// Validate phone number format
		if err := validator.ValidatePhoneNumber(input.PhoneNumber); err != nil {
			return nil, err
		}

		identifier = input.PhoneNumber

		// Get user by phone number
		user, err = uc.userRepo.GetByPhoneNumber(ctx, input.PhoneNumber)
		if err != nil && !domainErr.IsNotFound(err) {
			uc.logger.Error("Failed to get user by phone number", map[string]any{
				"phoneNumber": input.PhoneNumber,
				"error":       err.Error(),
			})
			return nil, err
		}
	}

	// If user is still nil, no user was found with provided credentials
	if user == nil {
		uc.logger.Warn("Failed login attempt - user not found", map[string]any{
			"identifier": identifier,
			"ip":         input.IP,
		})

		// Record failed login metric if metrics recorder is available
		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("login_failures", map[string]string{
				"reason": "user_not_found",
			})
		}

		return nil, domainErr.ErrInvalidCredentials
	}

	// Check if user account is active
	if !user.IsActive {
		uc.logger.Warn("Login attempt to inactive account", map[string]any{
			"userId":     user.ID.String(),
			"identifier": identifier,
			"ip":         input.IP,
		})

		// Record failed login metric for inactive account
		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("login_failures", map[string]string{
				"reason": "account_inactive",
			})
		}

		return nil, domainErr.ErrUserDeactivated
	}

	// Verify password
	valid, err := uc.passwordHasher.VerifyPassword(user.PasswordHash, input.Password)
	if err != nil {
		uc.logger.Error("Failed to verify password", map[string]any{
			"userId": user.ID.String(),
			"error":  err.Error(),
		})
		return nil, domainErr.ErrInternalServer
	}

	if !valid {
		uc.logger.Warn("Failed login attempt - invalid password", map[string]any{
			"userId":     user.ID.String(),
			"identifier": identifier,
			"ip":         input.IP,
		})

		// Record failed login metric for invalid password
		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("login_failures", map[string]string{
				"reason": "invalid_password",
			})
		}

		return nil, domainErr.ErrInvalidCredentials
	}

	// Evaluate risk if risk evaluator is available
	if uc.riskEvaluator != nil {
		riskFactors := risk.LoginRiskFactors{
			UserID:    user.ID.String(),
			IP:        input.IP,
			UserAgent: input.UserAgent,
		}

		riskLevel, err := uc.riskEvaluator.EvaluateLoginRisk(ctx, riskFactors)
		if err != nil {
			uc.logger.Warn("Failed to evaluate login risk", map[string]any{
				"userId":    user.ID.String(),
				"ip":        input.IP,
				"error":     err.Error(),
			})
			// Continue despite risk evaluation error
		} else if riskLevel == risk.High || riskLevel == risk.Critical {
			uc.logger.Warn("High risk login rejected", map[string]any{
				"userId":    user.ID.String(),
				"ip":        input.IP,
				"riskLevel": riskLevel.String(),
			})

			// Record failed login due to risk
			if uc.metricsRecorder != nil {
				uc.metricsRecorder.IncCounter("login_failures", map[string]string{
					"reason": "high_risk",
				})
			}

			return nil, domainErr.NewAuthorizationError("user", "login", "login attempt flagged as high risk")
		}
	}

	// Get the number of active sessions for this user
	sessionCount, err := uc.authSessionRepo.CountByUserID(ctx, user.ID)
	if err != nil {
		uc.logger.Error("Failed to count active sessions", map[string]any{
			"userId": user.ID.String(),
			"error":  err.Error(),
		})
		// Continue even with errors - we'll handle max sessions later
	}

	// Check if max sessions reached
	if sessionCount >= uc.maxSessions {
		uc.logger.Warn("Max sessions reached for user", map[string]any{
			"userId":      user.ID.String(),
			"maxSessions": uc.maxSessions,
		})

		// Record max sessions event
		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("login_max_sessions", map[string]string{})
		}

		return nil, domainErr.ErrMaxSessionsReached
	}

	// Generate access and refresh tokens
	accessToken, refreshToken, expiresAt, err := uc.tokenService.GenerateTokens(user.ID.String())
	if err != nil {
		uc.logger.Error("Failed to generate tokens", map[string]any{
			"userId": user.ID.String(),
			"error":  err.Error(),
		})
		return nil, domainErr.ErrTokenGenerationFailed
	}

	// Create auth session
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

	// Log successful login with execution time
	elapsed := uc.timeProvider.Now().Sub(startTime)
	logData := map[string]any{
		"userId":  user.ID.String(),
		"elapsed": elapsed.String(),
		"ip":      input.IP,
	}

	// Add identifier used for login to logs
	logData["loginMethod"] = "email"
	if input.Email != "" {
		logData["email"] = validator.NormalizeEmail(input.Email)
	} else {
		logData["loginMethod"] = "phoneNumber"
		logData["phoneNumber"] = input.PhoneNumber
	}

	uc.logger.Info("User logged in successfully", logData)

	// Record successful login
	if uc.metricsRecorder != nil {
		uc.metricsRecorder.IncCounter("login_success", map[string]string{})
		uc.metricsRecorder.ObserveHistogram("login_latency", float64(elapsed.Milliseconds()), map[string]string{})
	}

	// Record login event with audit logger if available
	if uc.auditLogger != nil {
		metadata := map[string]interface{}{
			"ip":        input.IP,
			"userAgent": input.UserAgent,
		}

		uc.auditLogger.LogSecurityEvent(ctx, "user.login", map[string]any{
			"userId":   user.ID.String(),
			"ip":       input.IP,
			"success":  true,
			"metadata": metadata,
		})
	}

	return &LoginOutput{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}
