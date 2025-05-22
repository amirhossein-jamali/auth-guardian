package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupLogoutOtherSessionsMocks(t *testing.T) (
	*mockRepo.MockAuthSessionRepository,
	*mockToken.MockTokenService,
	*mockLogger.MockLogger,
	*mockTime.MockTimeProvider,
	*mockLogger.MockAuditLogger,
) {
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	tokenService := mockToken.NewMockTokenService(t)
	logger := mockLogger.NewMockLogger(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	auditLogger := mockLogger.NewMockAuditLogger(t)

	return authSessionRepo, tokenService, logger, timeProvider, auditLogger
}

func TestLogoutOtherSessionsUseCase_Execute_Success(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data
	session := createTestSession() // Reusing the helper from refresh_token_test.go
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}
	sessionsRemoved := int64(3) // Assuming 3 other sessions were removed

	// Setup expectations
	startTime := time.Now()
	endTime := startTime.Add(100 * time.Millisecond)
	timeProvider.EXPECT().Now().Return(startTime) // Start time

	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, session.UserID, session.ID).Return(sessionsRemoved, nil)

	auditLogger.EXPECT().LogSecurityEvent(
		mock.Anything,
		"logout_other_sessions",
		mock.MatchedBy(func(data map[string]any) bool {
			return data["userId"] == session.UserID.String() &&
				data["sessionId"] == session.ID.String() &&
				data["sessionsRemoved"] == sessionsRemoved &&
				data["ip"] == input.IP &&
				data["userAgent"] == input.UserAgent
		}),
	).Return(nil)

	timeProvider.EXPECT().Now().Return(endTime) // End time for elapsed calculation
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestLogoutOtherSessionsUseCase_Execute_WithoutAuditLogger(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, _ := setupLogoutOtherSessionsMocks(t)

	// Test data
	session := createTestSession()
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}
	sessionsRemoved := int64(2)

	// Setup expectations
	startTime := time.Now()
	endTime := startTime.Add(100 * time.Millisecond)
	timeProvider.EXPECT().Now().Return(startTime) // Start time

	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, session.UserID, session.ID).Return(sessionsRemoved, nil)

	timeProvider.EXPECT().Now().Return(endTime) // End time for elapsed calculation
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case WITHOUT audit logger
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		nil, // No audit logger
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err, "Should succeed even without audit logger")
}

func TestLogoutOtherSessionsUseCase_Execute_EmptyToken(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data with empty refresh token
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: "",
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations
	startTime := time.Now()
	timeProvider.EXPECT().Now().Return(startTime)

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	var validationErr domainErr.ValidationError
	ok := errors.As(err, &validationErr)
	assert.True(t, ok, "Error should be of type ValidationError")
	assert.Equal(t, "refreshToken", validationErr.Field)
}

func TestLogoutOtherSessionsUseCase_Execute_SessionNotFound(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: "valid-but-non-existent-token",
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations
	startTime := time.Now()
	timeProvider.EXPECT().Now().Return(startTime)
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, "valid-but-non-existent-token").Return(nil, nil)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Maybe()

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrInvalidSession, err)
}

func TestLogoutOtherSessionsUseCase_Execute_GetSessionDatabaseError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: "valid-token",
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations
	startTime := time.Now()
	timeProvider.EXPECT().Now().Return(startTime)

	dbError := errors.New("database error")
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, "valid-token").Return(nil, dbError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, dbError, err)
}

func TestLogoutOtherSessionsUseCase_Execute_DeleteSessionsError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data
	session := createTestSession()
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations
	startTime := time.Now()
	timeProvider.EXPECT().Now().Return(startTime)

	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)

	deleteError := errors.New("delete sessions failed")
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, session.UserID, session.ID).Return(int64(0), deleteError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, deleteError, err)
}

func TestLogoutOtherSessionsUseCase_Execute_AuditLoggerError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data
	session := createTestSession()
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}
	sessionsRemoved := int64(3)

	// Setup expectations
	startTime := time.Now()
	endTime := startTime.Add(100 * time.Millisecond)
	timeProvider.EXPECT().Now().Return(startTime)

	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, session.UserID, session.ID).Return(sessionsRemoved, nil)

	// Audit logger error (should be ignored)
	auditLogError := errors.New("audit log failed")
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, mock.Anything, mock.Anything).Return(auditLogError)

	timeProvider.EXPECT().Now().Return(endTime)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err, "Should succeed even if audit logging fails")
}

func TestLogoutOtherSessionsUseCase_Execute_ZeroSessionsRemoved(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Test data
	session := createTestSession()
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}
	sessionsRemoved := int64(0) // No other sessions to remove

	// Setup expectations
	startTime := time.Now()
	endTime := startTime.Add(100 * time.Millisecond)
	timeProvider.EXPECT().Now().Return(startTime)

	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, session.UserID, session.ID).Return(sessionsRemoved, nil)

	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	timeProvider.EXPECT().Now().Return(endTime)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err, "Should succeed even if no sessions were removed")
}

func TestNewLogoutOtherSessionsUseCase(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger, timeProvider, auditLogger := setupLogoutOtherSessionsMocks(t)

	// Act
	useCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &auth.LogoutOtherSessionsUseCase{}, useCase)
}
