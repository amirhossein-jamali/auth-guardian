package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/risk"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"

	// Mocks

	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockMetrics "github.com/amirhossein-jamali/auth-guardian/mocks/port/metrics"
	mockPassword "github.com/amirhossein-jamali/auth-guardian/mocks/port/password"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockRisk "github.com/amirhossein-jamali/auth-guardian/mocks/port/risk"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// We'll reuse the mockSessionCreator from register_test.go
// mockSessionCreator is defined in register_test.go

func createTestUser() *entity.User {
	return &entity.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		FirstName:    "John",
		LastName:     "Doe",
		PasswordHash: "hashed-password-123",
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func setupLoginMocks(t *testing.T) (
	*mockRepo.MockUserRepository,
	*mockRepo.MockAuthSessionRepository,
	*mockSessionCreator,
	*mockPassword.MockPasswordHasher,
	*mockToken.MockTokenService,
	*mockTime.MockTimeProvider,
	*mockLogger.MockLogger,
	*mockMetrics.MockMetricsRecorder,
	*mockRisk.MockRiskEvaluator,
	*mockLogger.MockAuditLogger,
) {
	userRepo := mockRepo.NewMockUserRepository(t)
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)
	metricsRecorder := mockMetrics.NewMockMetricsRecorder(t)
	riskEvaluator := mockRisk.NewMockRiskEvaluator(t)
	auditLogger := mockLogger.NewMockAuditLogger(t)

	return userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, riskEvaluator, auditLogger
}

func TestLoginUseCase_Execute_Success(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, _, _, _ := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	testUser := createTestUser()
	accessToken := "access-token-xyz"
	refreshToken := "refresh-token-abc"
	expiresAt := int64(1000)
	maxSessions := int64(5)

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime)
	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)
	passwordHasher.EXPECT().VerifyPassword("hashed-password-123", "Password123!").Return(true, nil)
	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, testUser.ID, maxSessions).Return(nil)
	tokenService.EXPECT().GenerateTokens(testUser.ID.String()).Return(accessToken, refreshToken, expiresAt, nil)

	// Session creator expectations
	sessionCreator.On("CreateSession", mock.Anything, testUser.ID, refreshToken, "Mozilla/5.0", "192.168.1.1", expiresAt).Return(nil)

	// Time for duration measurement
	timeProvider.EXPECT().Since(currentTime).Return(100 * time.Millisecond)

	// Logger calls
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		maxSessions,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, testUser, result.User)
	assert.Equal(t, accessToken, result.AccessToken)
	assert.Equal(t, refreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)

	// Verify all expectations were met
	sessionCreator.AssertExpectations(t)
}

func TestLoginUseCase_Execute_WithMetricsAndRiskEvaluator(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, riskEvaluator, auditLogger := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	testUser := createTestUser()
	accessToken := "access-token-xyz"
	refreshToken := "refresh-token-abc"
	expiresAt := int64(1000)
	maxSessions := int64(5)

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime)

	// Metrics calls
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)
	passwordHasher.EXPECT().VerifyPassword("hashed-password-123", "Password123!").Return(true, nil)

	// Risk evaluation
	riskEvaluator.EXPECT().EvaluateLoginRisk(mock.Anything, mock.Anything).Return(risk.Low, nil)

	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, testUser.ID, maxSessions).Return(nil)
	tokenService.EXPECT().GenerateTokens(testUser.ID.String()).Return(accessToken, refreshToken, expiresAt, nil)

	// Session creator expectations
	sessionCreator.On("CreateSession", mock.Anything, testUser.ID, refreshToken, "Mozilla/5.0", "192.168.1.1", expiresAt).Return(nil)

	// Audit log the successful login
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, "user_login", mock.Anything).Return(nil)

	// Time for duration measurement
	timeProvider.EXPECT().Since(currentTime).Return(100 * time.Millisecond)

	// More metrics for success
	metricsRecorder.EXPECT().IncCounter("login_success", map[string]string{}).Return()
	metricsRecorder.EXPECT().ObserveHistogram("login_duration_ms", float64(100), map[string]string{}).Return()

	// Logger calls
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case with options
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		maxSessions,
		auth.WithMetricsRecorder(metricsRecorder),
		auth.WithRiskEvaluator(riskEvaluator),
		auth.WithAuditLogger(auditLogger),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, testUser, result.User)
	assert.Equal(t, accessToken, result.AccessToken)
	assert.Equal(t, refreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)

	// Verify all expectations were met
	sessionCreator.AssertExpectations(t)
}

func TestLoginUseCase_Execute_InvalidEmail(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create input with invalid email
	input := auth.LoginInput{
		Email:     "not-an-email",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Metrics call for login attempt
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestLoginUseCase_Execute_EmptyPassword(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create input with empty password
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "", // Empty password
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Metrics call for login attempt
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestLoginUseCase_Execute_UserNotFound(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "nonexistent@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Metrics call for login attempt
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	// User not found
	userRepo.EXPECT().GetByEmail(mock.Anything, "nonexistent@example.com").Return(nil, nil)

	// Logger warning
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Return()

	// Metrics for failed login
	metricsRecorder.EXPECT().IncCounter("login_failures", map[string]string{
		"reason": "user_not_found",
	}).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrInvalidCredentials, err)
	assert.Nil(t, result)
}

func TestLoginUseCase_Execute_InactiveUser(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "inactive@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Create an inactive user
	inactiveUser := createTestUser()
	inactiveUser.Email = "inactive@example.com"
	inactiveUser.IsActive = false

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Metrics call for login attempt
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	// User found but inactive
	userRepo.EXPECT().GetByEmail(mock.Anything, "inactive@example.com").Return(inactiveUser, nil)

	// Logger warning
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Return()

	// Metrics for failed login
	metricsRecorder.EXPECT().IncCounter("login_failures", map[string]string{
		"reason": "account_inactive",
	}).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrUserDeactivated, err)
	assert.Nil(t, result)
}

func TestLoginUseCase_Execute_InvalidPassword(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create valid input but with wrong password
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "WrongPassword123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	testUser := createTestUser()

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Metrics call for login attempt
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	// User found
	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)

	// Password verification fails
	passwordHasher.EXPECT().VerifyPassword("hashed-password-123", "WrongPassword123!").Return(false, nil)

	// Logger warning
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Return()

	// Metrics for failed login
	metricsRecorder.EXPECT().IncCounter("login_failures", map[string]string{
		"reason": "invalid_password",
	}).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrInvalidCredentials, err)
	assert.Nil(t, result)
}

func TestLoginUseCase_Execute_HighRiskLogin(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, riskEvaluator, auditLogger := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	testUser := createTestUser()
	accessToken := "access-token-xyz"
	refreshToken := "refresh-token-abc"
	expiresAt := int64(1000)
	maxSessions := int64(5)

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime)

	// Metrics calls
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)
	passwordHasher.EXPECT().VerifyPassword("hashed-password-123", "Password123!").Return(true, nil)

	// Risk evaluation returns high risk
	riskEvaluator.EXPECT().EvaluateLoginRisk(mock.Anything, mock.Anything).Return(risk.High, nil)

	// Logger warning for high risk
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Return()

	// Metrics for high risk login
	metricsRecorder.EXPECT().IncCounter("high_risk_logins", map[string]string{
		"risk_level": "high",
	}).Return()

	// Audit log the high risk login
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, "high_risk_login", mock.Anything).Return(nil)

	// Still continue with login process
	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, testUser.ID, maxSessions).Return(nil)
	tokenService.EXPECT().GenerateTokens(testUser.ID.String()).Return(accessToken, refreshToken, expiresAt, nil)

	// Session creator expectations
	sessionCreator.On("CreateSession", mock.Anything, testUser.ID, refreshToken, "Mozilla/5.0", "192.168.1.1", expiresAt).Return(nil)

	// Audit log the successful login despite high risk
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, "user_login", mock.Anything).Return(nil)

	// Time for duration measurement
	timeProvider.EXPECT().Since(currentTime).Return(100 * time.Millisecond)

	// More metrics for success
	metricsRecorder.EXPECT().IncCounter("login_success", map[string]string{}).Return()
	metricsRecorder.EXPECT().ObserveHistogram("login_duration_ms", float64(100), map[string]string{}).Return()

	// Logger calls
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case with options
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		maxSessions,
		auth.WithMetricsRecorder(metricsRecorder),
		auth.WithRiskEvaluator(riskEvaluator),
		auth.WithAuditLogger(auditLogger),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert - should succeed despite high risk
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, testUser, result.User)
	assert.Equal(t, accessToken, result.AccessToken)
	assert.Equal(t, refreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)

	// Verify all expectations were met
	sessionCreator.AssertExpectations(t)
}

func TestLoginUseCase_Execute_DatabaseError(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Metrics call for login attempt
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	// Database error
	dbError := errors.New("database connection failed")
	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(nil, dbError)

	// Logger error
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, dbError, err)
	assert.Nil(t, result)
}

func TestLoginUseCase_Execute_SessionCreationError(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	testUser := createTestUser()
	accessToken := "access-token-xyz"
	refreshToken := "refresh-token-abc"
	expiresAt := int64(1000)
	maxSessions := int64(5)

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime)

	// Metrics calls
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)
	passwordHasher.EXPECT().VerifyPassword("hashed-password-123", "Password123!").Return(true, nil)
	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, testUser.ID, maxSessions).Return(nil)
	tokenService.EXPECT().GenerateTokens(testUser.ID.String()).Return(accessToken, refreshToken, expiresAt, nil)

	// Session creator returns an error
	sessionCreator.On("CreateSession", mock.Anything, testUser.ID, refreshToken, "Mozilla/5.0", "192.168.1.1", expiresAt).
		Return(errors.New("session creation failed"))

	// Logger warning for session creation error
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Return()

	// Time for duration measurement
	timeProvider.EXPECT().Since(currentTime).Return(100 * time.Millisecond)

	// More metrics for success
	metricsRecorder.EXPECT().IncCounter("login_success", map[string]string{}).Return()
	metricsRecorder.EXPECT().ObserveHistogram("login_duration_ms", float64(100), map[string]string{}).Return()

	// Logger calls
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		maxSessions,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act - should still succeed despite session creation error
	result, err := useCase.Execute(context.Background(), input)

	// Assert - login should succeed even with session creation error
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, testUser, result.User)
	assert.Equal(t, accessToken, result.AccessToken)
	assert.Equal(t, refreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)

	// Verify all expectations were met
	sessionCreator.AssertExpectations(t)
}

func TestLoginUseCase_Execute_TokenGenerationError(t *testing.T) {
	// Arrange - create mocks
	userRepo, authSessionRepo, sessionCreator, passwordHasher, tokenService, timeProvider, logger, metricsRecorder, _, _ := setupLoginMocks(t)

	// Create valid input
	input := auth.LoginInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	testUser := createTestUser()
	maxSessions := int64(5)
	tokenError := errors.New("token generation failed")

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime)

	// Metrics calls
	metricsRecorder.EXPECT().IncCounter("login_attempts", map[string]string{}).Return()

	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)
	passwordHasher.EXPECT().VerifyPassword("hashed-password-123", "Password123!").Return(true, nil)
	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, testUser.ID, maxSessions).Return(nil)

	// Token service returns an error
	tokenService.EXPECT().GenerateTokens(testUser.ID.String()).Return("", "", int64(0), tokenError)

	// Logger error
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		maxSessions,
		auth.WithMetricsRecorder(metricsRecorder),
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrTokenGenerationFailed, err)
	assert.Nil(t, result)
}
