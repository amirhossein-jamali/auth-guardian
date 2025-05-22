package usecase

import (
	"context"
	"sync"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/idgenerator"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/password"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/risk"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/session"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/user"
)

// Factory creates use cases
type Factory struct {
	// Dependencies
	userRepo           repository.UserRepository
	authSessionRepo    repository.AuthSessionRepository
	tokenService       token.TokenService
	passwordHasher     password.Hasher
	idGenerator        idgenerator.IDGenerator
	timeProvider       tport.Provider
	logger             logger.Logger
	maxSessionsPerUser int64

	// Enhanced features
	auditLogger      logger.AuditLogger
	metricsRecorder  metrics.Recorder
	riskEvaluator    risk.Evaluator
	operationTimeout tport.Duration

	// Cached instances - created lazily and thread-safely
	mu              sync.RWMutex
	sessionCreator  *auth.DefaultSessionCreator
	registerUseCase *auth.RegisterUseCase
	loginUseCase    *auth.LoginUseCase
}

// NewFactory creates a new Factory
func NewFactory(
	userRepo repository.UserRepository,
	authSessionRepo repository.AuthSessionRepository,
	tokenService token.TokenService,
	passwordHasher password.Hasher,
	idGenerator idgenerator.IDGenerator,
	timeProvider tport.Provider,
	logger logger.Logger,
	maxSessionsPerUser int64,
	// Optional parameters with default values
	options ...FactoryOption,
) *Factory {
	factory := &Factory{
		userRepo:           userRepo,
		authSessionRepo:    authSessionRepo,
		tokenService:       tokenService,
		passwordHasher:     passwordHasher,
		idGenerator:        idGenerator,
		timeProvider:       timeProvider,
		logger:             logger,
		maxSessionsPerUser: maxSessionsPerUser,
		operationTimeout:   30 * tport.Second,
	}

	// Apply options
	for _, option := range options {
		option(factory)
	}

	return factory
}

// FactoryOption defines a factory option function
type FactoryOption func(*Factory)

// WithAuditLogger sets the audit logger
func WithAuditLogger(auditLogger logger.AuditLogger) FactoryOption {
	return func(f *Factory) {
		f.auditLogger = auditLogger
	}
}

// WithMetricsRecorder sets the metrics recorder
func WithMetricsRecorder(metricsRecorder metrics.Recorder) FactoryOption {
	return func(f *Factory) {
		f.metricsRecorder = metricsRecorder
	}
}

// WithRiskEvaluator sets the risk evaluator
func WithRiskEvaluator(riskEvaluator risk.Evaluator) FactoryOption {
	return func(f *Factory) {
		f.riskEvaluator = riskEvaluator
	}
}

// WithOperationTimeout sets the operation timeout
func WithOperationTimeout(timeout tport.Duration) FactoryOption {
	return func(f *Factory) {
		f.operationTimeout = timeout
	}
}

// WithTimeout wraps context with timeout for long-running operations
func (f *Factory) WithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return f.timeProvider.WithTimeout(ctx, f.operationTimeout.Std())
}

// createSessionCreator creates a new session creator without caching
// This is an internal helper method to avoid deadlocks
func (f *Factory) createSessionCreator() *auth.DefaultSessionCreator {
	return auth.NewSessionCreator(
		f.authSessionRepo,
		f.idGenerator,
		f.timeProvider,
		f.logger,
	)
}

// SessionCreator returns a cached session creator
func (f *Factory) SessionCreator() *auth.DefaultSessionCreator {
	f.mu.RLock()
	if sc := f.sessionCreator; sc != nil {
		f.mu.RUnlock()
		return sc
	}
	f.mu.RUnlock()

	// Create the session creator outside the lock to prevent deadlocks
	sc := f.createSessionCreator()

	// Store it in the cache under lock
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check if another thread created it while we were waiting
	if f.sessionCreator == nil {
		f.sessionCreator = sc
	}

	return f.sessionCreator
}

// RegisterUseCase returns a cached register use case
func (f *Factory) RegisterUseCase() *auth.RegisterUseCase {
	f.mu.RLock()
	if uc := f.registerUseCase; uc != nil {
		f.mu.RUnlock()
		return uc
	}
	f.mu.RUnlock()

	// Get dependencies outside of lock to prevent deadlocks
	sc := f.SessionCreator()

	// Create the use case outside the lock
	uc := auth.NewRegisterUseCase(
		f.userRepo,
		sc,
		f.passwordHasher,
		f.tokenService,
		f.idGenerator,
		f.timeProvider,
		f.logger,
	)

	// Store it in the cache under lock
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check if another thread created it while we were waiting
	if f.registerUseCase == nil {
		f.registerUseCase = uc
	}

	return f.registerUseCase
}

// LoginUseCase returns a cached login use case
func (f *Factory) LoginUseCase() *auth.LoginUseCase {
	f.mu.RLock()
	if uc := f.loginUseCase; uc != nil {
		f.mu.RUnlock()
		return uc
	}
	f.mu.RUnlock()

	// Get dependencies outside of lock to prevent deadlocks
	sc := f.SessionCreator()

	// Create login use case options
	var options []auth.LoginUseCaseOption
	if f.metricsRecorder != nil {
		options = append(options, auth.WithMetricsRecorder(f.metricsRecorder))
	}
	if f.riskEvaluator != nil {
		options = append(options, auth.WithRiskEvaluator(f.riskEvaluator))
	}
	if f.auditLogger != nil {
		options = append(options, auth.WithAuditLogger(f.auditLogger))
	}

	// Create the use case outside the lock
	uc := auth.NewLoginUseCase(
		f.userRepo,
		f.authSessionRepo,
		sc,
		f.passwordHasher,
		f.tokenService,
		f.timeProvider,
		f.logger,
		f.maxSessionsPerUser,
		options...,
	)

	// Store it in the cache under lock
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check if another thread created it while we were waiting
	if f.loginUseCase == nil {
		f.loginUseCase = uc
	}

	return f.loginUseCase
}

// RefreshTokenUseCase returns a refresh token use case
func (f *Factory) RefreshTokenUseCase() *auth.RefreshTokenUseCase {
	return auth.NewRefreshTokenUseCase(
		f.authSessionRepo,
		f.tokenService,
		f.timeProvider,
		f.logger,
	)
}

// LogoutUseCase returns a logout use case
func (f *Factory) LogoutUseCase() *auth.LogoutUseCase {
	return auth.NewLogoutUseCase(
		f.authSessionRepo,
		f.tokenService,
		f.logger,
	)
}

// LogoutAllUseCase returns a logout all use case
func (f *Factory) LogoutAllUseCase() *auth.LogoutAllUseCase {
	return auth.NewLogoutAllUseCase(
		f.authSessionRepo,
		f.logger,
	)
}

// LogoutOtherSessionsUseCase returns a logout other sessions use case
func (f *Factory) LogoutOtherSessionsUseCase() *auth.LogoutOtherSessionsUseCase {
	return auth.NewLogoutOtherSessionsUseCase(
		f.authSessionRepo,
		f.tokenService,
		f.logger,
		f.timeProvider,
		f.auditLogger,
	)
}

// GetUserUseCase returns a get user use case
func (f *Factory) GetUserUseCase() *user.GetUserUseCase {
	return user.NewGetUserUseCase(
		f.userRepo,
		f.logger,
		f.timeProvider,
	)
}

// UpdateProfileUseCase returns an update profile use case
func (f *Factory) UpdateProfileUseCase() *user.UpdateProfileUseCase {
	return user.NewUpdateProfileUseCase(
		f.userRepo,
		f.timeProvider,
		f.logger,
		f.auditLogger,
	)
}

// GetSessionsUseCase returns a get sessions use case
func (f *Factory) GetSessionsUseCase() *session.GetSessionsUseCase {
	return session.NewGetSessionsUseCase(
		f.authSessionRepo,
		f.logger,
	)
}

// CleanupExpiredSessionsUseCase returns a cleanup expired sessions use case
func (f *Factory) CleanupExpiredSessionsUseCase() *session.CleanupExpiredSessionsUseCase {
	return session.NewCleanupExpiredSessionsUseCase(
		f.authSessionRepo,
		f.timeProvider,
		f.logger,
	)
}
