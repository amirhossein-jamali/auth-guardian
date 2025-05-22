package tests

import (
	"context"
	"testing"
	stdtime "time"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase"

	// Mocks
	mockIdGen "github.com/amirhossein-jamali/auth-guardian/mocks/port/idgenerator"
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockMetrics "github.com/amirhossein-jamali/auth-guardian/mocks/port/metrics"
	mockPassword "github.com/amirhossein-jamali/auth-guardian/mocks/port/password"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockRisk "github.com/amirhossein-jamali/auth-guardian/mocks/port/risk"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// setupMocks sets up all the mocks for testing
func setupMocks(t *testing.T) (
	*mockRepo.MockUserRepository,
	*mockRepo.MockAuthSessionRepository,
	*mockToken.MockTokenService,
	*mockPassword.MockPasswordHasher,
	*mockIdGen.MockIDGenerator,
	*mockTime.MockTimeProvider,
	*mockLogger.MockLogger,
) {
	userRepo := mockRepo.NewMockUserRepository(t)
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	tokenService := mockToken.NewMockTokenService(t)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	return userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger
}

// setupSessionCreatorExpectations sets up all expectations needed for session creator
func setupSessionCreatorExpectations(
	timeProvider *mockTime.MockTimeProvider,
	idGenerator *mockIdGen.MockIDGenerator,
	authSessionRepo *mockRepo.MockAuthSessionRepository,
) {
	// These expectations are crucial to prevent hanging tests
	currentTime := stdtime.Now()
	timeProvider.EXPECT().Now().Return(currentTime).Maybe()
	idGenerator.EXPECT().GenerateID().Return("test-session-id").Maybe()
	authSessionRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(nil).Maybe()
}

// setupRegisterExpectations sets up all expectations needed for register use case
func setupRegisterExpectations(
	userRepo *mockRepo.MockUserRepository,
	passwordHasher *mockPassword.MockPasswordHasher,
	tokenService *mockToken.MockTokenService,
) {
	// Add necessary expectations to make RegisterUseCase work without deadlocks
	passwordHasher.EXPECT().HashPassword(mock.Anything).Return("hashed-password", nil).Maybe()
	userRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(nil).Maybe()
	tokenService.EXPECT().GenerateTokens(mock.Anything).Return("access", "refresh", int64(1000), nil).Maybe()
}

// setupLoginExpectations sets up all expectations needed for login use case
func setupLoginExpectations(
	userRepo *mockRepo.MockUserRepository,
	passwordHasher *mockPassword.MockPasswordHasher,
	tokenService *mockToken.MockTokenService,
) {
	// Add necessary expectations to make LoginUseCase work without deadlocks
	userRepo.EXPECT().GetByEmail(mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	passwordHasher.EXPECT().VerifyPassword(mock.Anything, mock.Anything).Return(true, nil).Maybe()
	tokenService.EXPECT().GenerateTokens(mock.Anything).Return("access", "refresh", int64(1000), nil).Maybe()
}

// TestNewFactory tests the creation of a new factory
func TestNewFactory(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Act
	factory := usecase.NewFactory(
		userRepo,
		authSessionRepo,
		tokenService,
		passwordHasher,
		idGenerator,
		timeProvider,
		logger,
		5, // maxSessionsPerUser
	)

	// Assert
	assert.NotNil(t, factory, "Factory should not be nil")
}

// TestFactoryOptions tests the factory options
func TestFactoryOptions(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	auditLogger := mockLogger.NewMockAuditLogger(t)
	metricsRecorder := mockMetrics.NewMockMetricsRecorder(t)
	riskEvaluator := mockRisk.NewMockRiskEvaluator(t)
	// Use the custom Duration type instead of standard time.Duration
	operationTimeout := tport.Duration(45 * stdtime.Second)

	t.Run("WithAuditLogger", func(t *testing.T) {
		// Act
		factory := usecase.NewFactory(
			userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
			usecase.WithAuditLogger(auditLogger),
		)

		// Assert - just verify the factory was created with audit logger
		assert.NotNil(t, factory, "Factory should be created with audit logger")

		// Create a use case that uses audit logger to verify it was properly set
		logoutOtherSessions := factory.LogoutOtherSessionsUseCase()
		assert.NotNil(t, logoutOtherSessions, "LogoutOtherSessionsUseCase should not be nil")
	})

	t.Run("WithMetricsRecorder", func(t *testing.T) {
		// Setup mocks needed to prevent deadlocks
		setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)

		// Act - create factory with metricsRecorder
		factory := usecase.NewFactory(
			userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
			usecase.WithMetricsRecorder(metricsRecorder),
		)

		// Verify that factory was created with metricsRecorder
		assert.NotNil(t, factory, "Factory should be created with metrics recorder")
	})

	t.Run("WithRiskEvaluator", func(t *testing.T) {
		// Setup mocks to avoid deadlocks
		setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)

		// Act
		factory := usecase.NewFactory(
			userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
			usecase.WithRiskEvaluator(riskEvaluator),
		)

		// Verify that factory was created with risk evaluator
		assert.NotNil(t, factory, "Factory should be created with risk evaluator")
	})

	t.Run("WithOperationTimeout", func(t *testing.T) {
		// Setup timeout expectations
		ctx := context.Background()
		timeoutCtx, cancel := context.WithTimeout(ctx, 45*stdtime.Second)
		defer cancel() // Call cancel to prevent context leak
		// Standard time.Duration for the mock
		stdDuration := 45 * stdtime.Second
		timeProvider.EXPECT().WithTimeout(ctx, stdDuration).Return(timeoutCtx, func() {}).Once()

		// Act
		factory := usecase.NewFactory(
			userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
			usecase.WithOperationTimeout(operationTimeout),
		)

		// Execute WithTimeout function
		resultCtx, _ := factory.WithTimeout(ctx)

		// Assert
		assert.Equal(t, timeoutCtx, resultCtx, "Timeout context should match")
	})

	t.Run("Multiple Options", func(t *testing.T) {
		// Act
		factory := usecase.NewFactory(
			userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
			usecase.WithAuditLogger(auditLogger),
			usecase.WithMetricsRecorder(metricsRecorder),
			usecase.WithRiskEvaluator(riskEvaluator),
			usecase.WithOperationTimeout(operationTimeout),
		)

		// Assert - check that factory was created successfully
		assert.NotNil(t, factory, "Factory should not be nil with multiple options")
	})
}

// TestSessionCreatorCaching tests that the SessionCreator is properly cached
func TestSessionCreatorCaching(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Set up proper expectations to prevent hanging
	setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)

	// Create the factory
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Act - call twice to test caching
	firstCreator := factory.SessionCreator()
	secondCreator := factory.SessionCreator()

	// Assert
	assert.NotNil(t, firstCreator, "First SessionCreator should not be nil")
	assert.NotNil(t, secondCreator, "Second SessionCreator should not be nil")
	assert.Same(t, firstCreator, secondCreator, "Session creators should be the same instance (cached)")
}

// TestRegisterUseCaseCaching tests that the RegisterUseCase is properly cached
func TestRegisterUseCaseCaching(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Set up expectations to prevent hanging
	setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)
	setupRegisterExpectations(userRepo, passwordHasher, tokenService)

	// Create the factory with all needed mocks properly set up
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Act - call twice to test caching
	firstUseCase := factory.RegisterUseCase()
	secondUseCase := factory.RegisterUseCase()

	// Assert
	assert.NotNil(t, firstUseCase, "First RegisterUseCase should not be nil")
	assert.NotNil(t, secondUseCase, "Second RegisterUseCase should not be nil")
	assert.Same(t, firstUseCase, secondUseCase, "Register use cases should be the same instance (cached)")
}

// TestLoginUseCaseCaching tests that the LoginUseCase is properly cached
func TestLoginUseCaseCaching(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Set up expectations to prevent hanging
	setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)
	setupLoginExpectations(userRepo, passwordHasher, tokenService)

	// Create the factory with all needed mocks properly set up
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Act - call twice to test caching
	firstUseCase := factory.LoginUseCase()
	secondUseCase := factory.LoginUseCase()

	// Assert
	assert.NotNil(t, firstUseCase, "First LoginUseCase should not be nil")
	assert.NotNil(t, secondUseCase, "Second LoginUseCase should not be nil")
	assert.Same(t, firstUseCase, secondUseCase, "Login use cases should be the same instance (cached)")
}

// TestAllUseCases tests that all use cases can be created without deadlocks
func TestAllUseCases(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Set up expectations to prevent hanging
	setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)
	setupRegisterExpectations(userRepo, passwordHasher, tokenService)
	setupLoginExpectations(userRepo, passwordHasher, tokenService)

	// Create the factory
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Act & Assert - create and verify all use cases
	assert.NotNil(t, factory.SessionCreator(), "SessionCreator should not be nil")
	assert.NotNil(t, factory.RegisterUseCase(), "RegisterUseCase should not be nil")
	assert.NotNil(t, factory.LoginUseCase(), "LoginUseCase should not be nil")
	assert.NotNil(t, factory.RefreshTokenUseCase(), "RefreshTokenUseCase should not be nil")
	assert.NotNil(t, factory.LogoutUseCase(), "LogoutUseCase should not be nil")
	assert.NotNil(t, factory.LogoutAllUseCase(), "LogoutAllUseCase should not be nil")
	assert.NotNil(t, factory.LogoutOtherSessionsUseCase(), "LogoutOtherSessionsUseCase should not be nil")
	assert.NotNil(t, factory.GetUserUseCase(), "GetUserUseCase should not be nil")
	assert.NotNil(t, factory.UpdateProfileUseCase(), "UpdateProfileUseCase should not be nil")
	assert.NotNil(t, factory.GetSessionsUseCase(), "GetSessionsUseCase should not be nil")
	assert.NotNil(t, factory.CleanupExpiredSessionsUseCase(), "CleanupExpiredSessionsUseCase should not be nil")
}

// TestWithTimeoutFunctionality tests the WithTimeout functionality
func TestWithTimeoutFunctionality(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Set up expectations for WithTimeout
	ctx := context.Background()
	stdDuration := 30 * stdtime.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, stdDuration)
	defer cancel() // Call cancel to prevent context leak
	timeProvider.EXPECT().WithTimeout(ctx, stdDuration).Return(timeoutCtx, func() {}).Once()

	// Create factory
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Act
	resultCtx, resultCancel := factory.WithTimeout(ctx)

	// Assert
	assert.Equal(t, timeoutCtx, resultCtx, "Context returned should be the timeout context")
	assert.NotNil(t, resultCancel, "Cancel function should not be nil")
}

// TestFactoryWithRealParams tests the factory with real optional parameters
func TestFactoryWithRealParams(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Create real optional parameters
	auditLogger := mockLogger.NewMockAuditLogger(t)
	metricsRecorder := mockMetrics.NewMockMetricsRecorder(t)
	riskEvaluator := mockRisk.NewMockRiskEvaluator(t)

	// Create factory with all options
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
		usecase.WithAuditLogger(auditLogger),
		usecase.WithMetricsRecorder(metricsRecorder),
		usecase.WithRiskEvaluator(riskEvaluator),
		usecase.WithOperationTimeout(tport.Duration(60*stdtime.Second)),
	)

	// Act & Assert - just ensure factory is created
	assert.NotNil(t, factory, "Factory should be created successfully with all options")
}

// TestFactoryWithoutOptionalParams tests the factory creation without optional parameters
func TestFactoryWithoutOptionalParams(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Act
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Assert
	assert.NotNil(t, factory, "Factory should be created successfully without optional parameters")
}

// TestFactoryInternalCache tests that the factory's internal cache works as expected
func TestFactoryInternalCache(t *testing.T) {
	// Arrange
	userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger := setupMocks(t)

	// Set up expectations needed for session creator and other use cases
	setupSessionCreatorExpectations(timeProvider, idGenerator, authSessionRepo)

	// Create the factory
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Get session creator twice and verify caching
	sc1 := factory.SessionCreator()
	sc2 := factory.SessionCreator()
	assert.Same(t, sc1, sc2, "Session creators should be the same instance")

	// Further tests for other use cases can be added here
}

// TestMinimalFactoryCreation tests if we can create a factory without deadlocks
func TestMinimalFactoryCreation(t *testing.T) {
	// Arrange - create minimal mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	tokenService := mockToken.NewMockTokenService(t)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create our factory with no initialization
	factory := usecase.NewFactory(
		userRepo, authSessionRepo, tokenService, passwordHasher, idGenerator, timeProvider, logger, 5,
	)

	// Just assert it was created
	assert.NotNil(t, factory, "Factory should be created successfully")
}
