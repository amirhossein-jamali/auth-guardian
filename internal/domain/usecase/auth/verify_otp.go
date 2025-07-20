package auth

import (
	"context"
	"strconv"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/idgenerator"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
)

// VerifyOTPInput represents data needed for OTP verification
type VerifyOTPInput struct {
	PhoneNumber string
	Code        string
	UserAgent   string
	IP          string
}

// VerifyOTPOutput represents the result of a successful OTP verification
type VerifyOTPOutput struct {
	User         *entity.User
	IsNewUser    bool
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

// VerifyOTPUseCase handles OTP verification process
type VerifyOTPUseCase struct {
	userRepo        repository.UserRepository
	otpRepo         repository.OTPRepository
	authSessionRepo repository.AuthSessionRepository
	sessionCreator  SessionCreator
	tokenService    token.TokenService
	idGenerator     idgenerator.IDGenerator
	timeProvider    tport.Provider
	logger          logger.Logger
	maxAttempts     int
	// Optional components
	metricsRecorder metrics.Recorder
	auditLogger     logger.AuditLogger
}

// VerifyOTPUseCaseOption defines a verify OTP use case option function
type VerifyOTPUseCaseOption func(*VerifyOTPUseCase)

// WithMetricsRecorderForVerifyOTP sets the metrics recorder for OTP verification use case
func WithMetricsRecorderForVerifyOTP(metricsRecorder metrics.Recorder) VerifyOTPUseCaseOption {
	return func(uc *VerifyOTPUseCase) {
		uc.metricsRecorder = metricsRecorder
	}
}

// WithAuditLoggerForVerifyOTP sets the audit logger for OTP verification use case
func WithAuditLoggerForVerifyOTP(auditLogger logger.AuditLogger) VerifyOTPUseCaseOption {
	return func(uc *VerifyOTPUseCase) {
		uc.auditLogger = auditLogger
	}
}

// NewVerifyOTPUseCase creates a new instance of VerifyOTPUseCase
func NewVerifyOTPUseCase(
	userRepo repository.UserRepository,
	otpRepo repository.OTPRepository,
	authSessionRepo repository.AuthSessionRepository,
	sessionCreator SessionCreator,
	tokenService token.TokenService,
	idGenerator idgenerator.IDGenerator,
	timeProvider tport.Provider,
	logger logger.Logger,
	maxAttempts int,
	options ...VerifyOTPUseCaseOption,
) *VerifyOTPUseCase {
	uc := &VerifyOTPUseCase{
		userRepo:        userRepo,
		otpRepo:         otpRepo,
		authSessionRepo: authSessionRepo,
		sessionCreator:  sessionCreator,
		tokenService:    tokenService,
		idGenerator:     idGenerator,
		timeProvider:    timeProvider,
		logger:          logger,
		maxAttempts:     maxAttempts,
	}

	// Apply options
	for _, option := range options {
		option(uc)
	}

	return uc
}

// Execute processes an OTP verification
func (uc *VerifyOTPUseCase) Execute(ctx context.Context, input VerifyOTPInput) (*VerifyOTPOutput, error) {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Record OTP verification attempt metric if metrics recorder is available
	if uc.metricsRecorder != nil {
		uc.metricsRecorder.IncCounter("otp_verification_attempts", map[string]string{})
	}

	// Validate input
	if len(input.PhoneNumber) < 8 || len(input.PhoneNumber) > 15 {
		return nil, domainErr.NewValidationError("phoneNumber", "invalid phone number format")
	}

	if len(input.Code) < 4 || len(input.Code) > 8 {
		return nil, domainErr.NewValidationError("code", "invalid OTP code format")
	}

	// Get the OTP record
	otp, err := uc.otpRepo.GetByPhoneNumber(ctx, input.PhoneNumber)
	if err != nil {
		uc.logger.Error("Failed to get OTP record", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})

		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("otp_verification_failures", map[string]string{
				"reason": "not_found",
			})
		}

		return nil, domainErr.ErrInvalidOTP
	}

	// Validate the OTP
	if !otp.Validate(input.Code, uc.maxAttempts, uc.timeProvider) {
		// Increment attempt count
		otp.IncrementAttempt()
		if err := uc.otpRepo.Update(ctx, otp); err != nil {
			uc.logger.Error("Failed to update OTP attempts", map[string]any{
				"phoneNumber": input.PhoneNumber,
				"error":       err.Error(),
			})
		}

		if otp.IsExpired(uc.timeProvider) {
			if uc.metricsRecorder != nil {
				uc.metricsRecorder.IncCounter("otp_verification_failures", map[string]string{
					"reason": "expired",
				})
			}
			return nil, domainErr.ErrExpiredOTP
		}

		if otp.IsUsed {
			if uc.metricsRecorder != nil {
				uc.metricsRecorder.IncCounter("otp_verification_failures", map[string]string{
					"reason": "already_used",
				})
			}
			return nil, domainErr.ErrUsedOTP
		}

		if otp.HasExceededMaxAttempts(uc.maxAttempts) {
			if uc.metricsRecorder != nil {
				uc.metricsRecorder.IncCounter("otp_verification_failures", map[string]string{
					"reason": "max_attempts",
				})
			}
			return nil, domainErr.ErrMaxAttemptsExceeded
		}

		// Code doesn't match
		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("otp_verification_failures", map[string]string{
				"reason": "invalid_code",
			})
		}
		return nil, domainErr.ErrInvalidOTP
	}

	// Mark OTP as used
	otp.MarkAsUsed(uc.timeProvider)
	if err := uc.otpRepo.Update(ctx, otp); err != nil {
		uc.logger.Error("Failed to mark OTP as used", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})
		// We'll continue anyway as this is not critical
	}

	// Try to find existing user with this phone number
	user, err := uc.userRepo.GetByPhoneNumber(ctx, input.PhoneNumber)
	isNewUser := false
	if err != nil {
		if domainErr.IsNotFound(err) {
			// User doesn't exist, create a new one
			isNewUser = true
			userId := entity.ID(uc.idGenerator.GenerateID())
			user = entity.NewUser(
				userId,
				"", // Empty email - will be updated later if needed
				input.PhoneNumber,
				"", // Empty first name
				"", // Empty last name
				uc.timeProvider,
			)

			if err := uc.userRepo.Create(ctx, user); err != nil {
				uc.logger.Error("Failed to create user", map[string]any{
					"phoneNumber": input.PhoneNumber,
					"error":       err.Error(),
				})
				return nil, err
			}
		} else {
			uc.logger.Error("Failed to check user existence", map[string]any{
				"phoneNumber": input.PhoneNumber,
				"error":       err.Error(),
			})
			return nil, err
		}
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

	// Log successful verification
	elapsed := uc.timeProvider.Now().Sub(startTime)
	uc.logger.Info("OTP verified successfully", map[string]any{
		"userId":      user.ID.String(),
		"phoneNumber": input.PhoneNumber,
		"isNewUser":   isNewUser,
		"elapsed":     elapsed.String(),
	})

	if uc.metricsRecorder != nil {
		uc.metricsRecorder.IncCounter("otp_verification_success", map[string]string{
			"is_new_user": strconv.FormatBool(isNewUser),
		})
	}

	return &VerifyOTPOutput{
		User:         user,
		IsNewUser:    isNewUser,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}
