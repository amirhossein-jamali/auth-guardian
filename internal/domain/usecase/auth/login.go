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
	Email     string
	Password  string
	UserAgent string
	IP        string
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

	// Validate email
	if err := validator.ValidateEmail(input.Email); err != nil {
		return nil, err
	}

	// Normalize email
	normalizedEmail := validator.NormalizeEmail(input.Email)

	// Validate password (only check if it's not empty for login)
	if input.Password == "" {
		return nil, domainErr.NewValidationError("password", "password is required")
	}

	// Get user by normalized email
	user, err := uc.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		uc.logger.Error("Failed to get user by email", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	if user == nil {
		uc.logger.Warn("Failed login attempt - user not found", map[string]any{
			"email": normalizedEmail,
			"ip":    input.IP,
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
			"userId": user.ID.String(),
			"email":  normalizedEmail,
			"ip":     input.IP,
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
			"error": err.Error(),
		})
		return nil, domainErr.ErrInternalServer
	}

	if !valid {
		uc.logger.Warn("Failed login attempt - invalid password", map[string]any{
			"userId": user.ID.String(),
			"email":  normalizedEmail,
			"ip":     input.IP,
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
			Time:      uc.timeProvider.Now().Unix(),
		}

		riskLevel, err := uc.riskEvaluator.EvaluateLoginRisk(ctx, riskFactors)
		if err != nil {
			// Just log the error and continue, don't fail the login
			uc.logger.Warn("Failed to evaluate login risk", map[string]any{
				"userId": user.ID.String(),
				"error":  err.Error(),
			})
		} else if riskLevel >= risk.High {
			uc.logger.Warn("High risk login detected", map[string]any{
				"userId":    user.ID.String(),
				"ip":        input.IP,
				"riskLevel": riskLevel,
			})

			// Record metric for high risk login
			if uc.metricsRecorder != nil {
				uc.metricsRecorder.IncCounter("high_risk_logins", map[string]string{
					"risk_level": riskLevel.String(),
				})
			}

			// Log security event for high risk login
			if uc.auditLogger != nil {
				_ = uc.auditLogger.LogSecurityEvent(ctx, "high_risk_login", map[string]any{
					"userId":    user.ID.String(),
					"ip":        input.IP,
					"userAgent": input.UserAgent,
					"riskLevel": riskLevel,
				})
			}

			// Here you could implement additional security measures:
			// - Force 2FA verification
			// - Limit session duration
			// - Apply additional restrictions
			// For now, we just log it and continue
		}
	}

	// Ensure session limit and log any errors but continue
	if err := uc.authSessionRepo.EnsureSessionLimit(ctx, user.ID, uc.maxSessions); err != nil {
		uc.logger.Warn("Failed to enforce session limit", map[string]any{
			"userId": user.ID.String(),
			"error":  err.Error(),
		})
		// Continue anyway as this is not critical
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := uc.tokenService.GenerateTokens(user.ID.String())
	if err != nil {
		uc.logger.Error("Failed to generate tokens", map[string]any{
			"error": err.Error(),
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

	// Create auth session and log error if it fails, but continue process
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

	// Log security event for successful login
	if uc.auditLogger != nil {
		_ = uc.auditLogger.LogSecurityEvent(ctx, "user_login", map[string]any{
			"userId":    user.ID.String(),
			"ip":        input.IP,
			"userAgent": input.UserAgent,
		})
	}

	// Record successful login metric
	if uc.metricsRecorder != nil {
		uc.metricsRecorder.IncCounter("login_success", map[string]string{})
		elapsed := uc.timeProvider.Since(startTime)
		uc.metricsRecorder.ObserveHistogram("login_duration_ms", float64(elapsed.Milliseconds()), map[string]string{})
	}

	// Log successful login with execution time
	elapsed := uc.timeProvider.Since(startTime)
	uc.logger.Info("User logged in successfully", map[string]any{
		"userId":  user.ID.String(),
		"email":   normalizedEmail,
		"elapsed": elapsed.String(),
	})

	return &LoginOutput{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}
