package auth

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/idgenerator"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"
	otpPort "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/otp"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// RequestOTPInput represents data needed for OTP request
type RequestOTPInput struct {
	PhoneNumber string
	IP          string
}

// RequestOTPOutput represents the result of a successful OTP request
type RequestOTPOutput struct {
	ExpiresIn int // seconds until expiry
	Message   string
}

// RequestOTPUseCase handles OTP request process
type RequestOTPUseCase struct {
	otpRepo       repository.OTPRepository
	otpService    otpPort.OTPService
	idGenerator   idgenerator.IDGenerator
	timeProvider  tport.Provider
	logger        logger.Logger
	rateLimiter   storage.RateLimiter
	otpLength     int
	expirySeconds int
	cooldownSec   int
	maxAttempts   int
	// Optional components
	metricsRecorder metrics.Recorder
	auditLogger     logger.AuditLogger
}

// RequestOTPUseCaseOption defines a request OTP use case option function
type RequestOTPUseCaseOption func(*RequestOTPUseCase)

// WithMetricsRecorderForOTP sets the metrics recorder for OTP request use case
func WithMetricsRecorderForOTP(metricsRecorder metrics.Recorder) RequestOTPUseCaseOption {
	return func(uc *RequestOTPUseCase) {
		uc.metricsRecorder = metricsRecorder
	}
}

// WithAuditLoggerForOTP sets the audit logger for OTP request use case
func WithAuditLoggerForOTP(auditLogger logger.AuditLogger) RequestOTPUseCaseOption {
	return func(uc *RequestOTPUseCase) {
		uc.auditLogger = auditLogger
	}
}

// NewRequestOTPUseCase creates a new instance of RequestOTPUseCase
func NewRequestOTPUseCase(
	otpRepo repository.OTPRepository,
	otpService otpPort.OTPService,
	idGenerator idgenerator.IDGenerator,
	timeProvider tport.Provider,
	logger logger.Logger,
	rateLimiter storage.RateLimiter,
	otpLength int,
	expirySeconds int,
	cooldownSec int,
	maxAttempts int,
	options ...RequestOTPUseCaseOption,
) *RequestOTPUseCase {
	uc := &RequestOTPUseCase{
		otpRepo:       otpRepo,
		otpService:    otpService,
		idGenerator:   idGenerator,
		timeProvider:  timeProvider,
		logger:        logger,
		rateLimiter:   rateLimiter,
		otpLength:     otpLength,
		expirySeconds: expirySeconds,
		cooldownSec:   cooldownSec,
		maxAttempts:   maxAttempts,
	}

	// Apply options
	for _, option := range options {
		option(uc)
	}

	return uc
}

// Execute processes an OTP request
func (uc *RequestOTPUseCase) Execute(ctx context.Context, input RequestOTPInput) (*RequestOTPOutput, error) {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Record OTP request metric if metrics recorder is available
	if uc.metricsRecorder != nil {
		uc.metricsRecorder.IncCounter("otp_requests", map[string]string{})
	}

	// Validate phone number (basic format check)
	if len(input.PhoneNumber) < 8 || len(input.PhoneNumber) > 15 {
		return nil, domainErr.NewValidationError("phoneNumber", "invalid phone number format")
	}

	// Check rate limiting
	key := "otp_req:" + input.PhoneNumber
	allowed, err := uc.rateLimiter.Allow(ctx, key, 1, time.Duration(uc.cooldownSec)*time.Second)
	if err != nil {
		uc.logger.Error("Rate limiter error", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})
	}

	if !allowed {
		if uc.metricsRecorder != nil {
			uc.metricsRecorder.IncCounter("otp_requests_rate_limited", map[string]string{})
		}

		if uc.auditLogger != nil {
			uc.auditLogger.Log(ctx, logger.AuditEvent{
				Action:     "otp.request.rate_limited",
				TargetType: "otp",
				TargetID:   input.PhoneNumber,
				IP:         input.IP,
				Success:    false,
				Metadata: map[string]interface{}{
					"reason": "cooldown_period",
				},
			})
		}

		return nil, domainErr.ErrTooManyRequests
	}

	// Check if there's an existing active OTP for this phone number
	existingOTP, err := uc.otpRepo.GetByPhoneNumber(ctx, input.PhoneNumber)
	if err != nil && !domainErr.IsNotFound(err) {
		uc.logger.Error("Failed to check existing OTP", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})
		return nil, err
	}

	// If there is an active OTP and it hasn't expired and it's within cooldown period, reject
	if existingOTP != nil && !existingOTP.IsExpired(uc.timeProvider) {
		timeSinceCreation := uc.timeProvider.Since(existingOTP.CreatedAt)
		if timeSinceCreation < time.Duration(uc.cooldownSec)*time.Second {
			remainingSec := uc.cooldownSec - int(timeSinceCreation.Seconds())

			if uc.metricsRecorder != nil {
				uc.metricsRecorder.IncCounter("otp_requests_throttled", map[string]string{})
			}

			return nil, domainErr.NewThrottlingError("Too many requests", remainingSec)
		}
	}

	// Generate a new OTP code
	code := uc.otpService.Generate(uc.otpLength)

	// Create a new OTP entity
	otpId := entity.ID(uc.idGenerator.GenerateID())
	otp := entity.NewOTP(otpId, input.PhoneNumber, code, uc.expirySeconds, uc.timeProvider)

	// Store the OTP
	if err := uc.otpRepo.Create(ctx, otp); err != nil {
		uc.logger.Error("Failed to store OTP", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})
		return nil, err
	}

	// Send the OTP
	err = uc.otpService.Send(ctx, input.PhoneNumber, code)
	if err != nil {
		uc.logger.Error("Failed to send OTP", map[string]any{
			"phoneNumber": input.PhoneNumber,
			"error":       err.Error(),
		})
		// We don't want to return an error here because the OTP is already created
		// Just log the error
	}

	// Log successful OTP request
	elapsed := uc.timeProvider.Now().Sub(startTime)
	uc.logger.Info("OTP requested successfully", map[string]any{
		"phoneNumber": input.PhoneNumber,
		"expiresIn":   uc.expirySeconds,
		"elapsed":     elapsed.String(),
	})

	if uc.auditLogger != nil {
		uc.auditLogger.Log(ctx, logger.AuditEvent{
			Action:     "otp.request.success",
			TargetType: "otp",
			TargetID:   input.PhoneNumber,
			IP:         input.IP,
			Success:    true,
		})
	}

	return &RequestOTPOutput{
		ExpiresIn: uc.expirySeconds,
		Message:   "OTP sent successfully",
	}, nil
}
