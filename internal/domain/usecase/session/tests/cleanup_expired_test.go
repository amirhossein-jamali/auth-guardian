package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/session"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupCleanupExpiredMocks(t *testing.T) (
	*mockRepo.MockAuthSessionRepository,
	*mockTime.MockTimeProvider,
	*mockLogger.MockLogger,
) {
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	return authSessionRepo, timeProvider, logger
}

func TestCleanupExpiredSessionsUseCase_Execute_Success_SingleBatch(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 500
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	deletedCount := int64(300) // Less than batch size to complete in one batch
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2) // Once at start, once for 'before' param

	// Convert tport.Duration to time.Duration (Std method)
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// BatchDeleteExpired should be called once with the correct parameters
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, batchSize).Return(deletedCount, nil)

	// Logging expectations
	timeProvider.EXPECT().Since(startTime).Return(100 * time.Millisecond)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Times(2) // Progress log and final log

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_Success_MultipleBatches(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 100
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second

	// Setup minimal expectations - focus on the core functionality, not exact values
	timeProvider.EXPECT().Now().Return(startTime).Times(2)
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// Set up repository batches with Times() - this is the critical part
	authSessionRepo.EXPECT().BatchDeleteExpired(mock.Anything, mock.Anything, mock.Anything).Return(int64(100), nil).Times(2)
	authSessionRepo.EXPECT().BatchDeleteExpired(mock.Anything, mock.Anything, mock.Anything).Return(int64(50), nil).Times(1)

	// Final logs - every run will have these
	logger.EXPECT().Info("Expired sessions cleanup completed", mock.Anything).Return()
	timeProvider.EXPECT().Since(startTime).Return(300 * time.Millisecond)
	logger.EXPECT().Info("Expired sessions cleaned up successfully", mock.Anything).Return()

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_NoExpiredSessions(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 500
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Timeout context
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// BatchDeleteExpired returns 0 (no expired sessions)
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, batchSize).Return(int64(0), nil)

	// Elapsed time for final log
	timeProvider.EXPECT().Since(startTime).Return(50 * time.Millisecond)

	// Final success log (no progress log since deletedCount=0)
	logger.EXPECT().Info("Expired sessions cleaned up successfully", mock.Anything).Return()

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_WithCustomTimeout(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data with custom timeout
	batchSize := 500
	customTimeout := tport.Duration(60 * time.Second)
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
		Timeout:   customTimeout,
	}
	now := time.Now()
	startTime := now

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Should use custom timeout instead of default
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, customTimeout.Std()).Return(timeoutCtx, cancelFunc)

	// BatchDeleteExpired returns some deleted sessions
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, batchSize).Return(int64(100), nil)

	// Logging expectations
	timeProvider.EXPECT().Since(startTime).Return(75 * time.Millisecond)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Times(2)

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_WithDefaultTimeoutMethod(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 500
	newDefaultTimeout := tport.Duration(45 * time.Second)
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	now := time.Now()
	startTime := now

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Should use new default timeout
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, newDefaultTimeout.Std()).Return(timeoutCtx, cancelFunc)

	// BatchDeleteExpired returns some deleted sessions
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, batchSize).Return(int64(100), nil)

	// Logging expectations
	timeProvider.EXPECT().Since(startTime).Return(60 * time.Millisecond)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Times(2)

	// Create use case with chained method to set default timeout
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	).WithDefaultTimeout(newDefaultTimeout)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_DefaultBatchSize(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data with no batch size specified (should use default)
	input := session.CleanupExpiredSessionsInput{
		// BatchSize not set, should use default of 500
	}
	defaultBatchSize := 500
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Timeout context
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// BatchDeleteExpired should use default batch size
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, defaultBatchSize).Return(int64(100), nil)

	// Logging expectations
	timeProvider.EXPECT().Since(startTime).Return(45 * time.Millisecond)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Times(2)

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_DatabaseError(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 500
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second
	dbError := errors.New("database error")

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Timeout context
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// BatchDeleteExpired returns error
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, batchSize).Return(int64(0), dbError)

	// Error log
	logger.EXPECT().Error("Failed to delete expired sessions", mock.Anything).Return()

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, dbError, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_Timeout(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 500
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Regular context - implementation will handle errors
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// Return a context timeout error
	ctxErr := context.DeadlineExceeded
	authSessionRepo.EXPECT().BatchDeleteExpired(timeoutCtx, now, batchSize).Return(int64(0), ctxErr)

	// Error will be logged
	logger.EXPECT().Error("Failed to delete expired sessions", mock.Anything).Return()

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// The implementation DOESN'T handle the error gracefully and returns it
	assert.Error(t, err)
	assert.Equal(t, ctxErr, err)
}

func TestCleanupExpiredSessionsUseCase_Execute_PartialSuccess(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Test data
	batchSize := 500
	input := session.CleanupExpiredSessionsInput{
		BatchSize: batchSize,
	}
	now := time.Now()
	startTime := now
	defaultTimeout := 30 * time.Second

	// Setup expectations
	timeProvider.EXPECT().Now().Return(startTime).Times(2)

	// Timeout context
	timeoutCtx := context.Background()
	cancelFunc := func() {}
	timeProvider.EXPECT().WithTimeout(mock.Anything, defaultTimeout).Return(timeoutCtx, cancelFunc)

	// First batch succeeds, but no need to specify progress log expectation
	dbError := errors.New("connection reset")
	authSessionRepo.EXPECT().BatchDeleteExpired(mock.Anything, mock.Anything, mock.Anything).Return(int64(batchSize), nil).Times(1)

	// Second batch fails with database error - the important part
	authSessionRepo.EXPECT().BatchDeleteExpired(mock.Anything, mock.Anything, mock.Anything).Return(int64(0), dbError).Times(1)

	// Error log for the database error
	logger.EXPECT().Error("Failed to delete expired sessions", mock.Anything).Return()

	// Create use case
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert - error is returned from the database operation
	assert.Error(t, err)
	assert.Equal(t, dbError, err)
}

func TestNewCleanupExpiredSessionsUseCase(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)

	// Act
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &session.CleanupExpiredSessionsUseCase{}, useCase)
}

func TestNewCleanupExpiredSessionsUseCase_WithDefaultTimeout(t *testing.T) {
	// Arrange
	authSessionRepo, timeProvider, logger := setupCleanupExpiredMocks(t)
	customTimeout := tport.Duration(60 * time.Second)

	// Act
	useCase := session.NewCleanupExpiredSessionsUseCase(
		authSessionRepo,
		timeProvider,
		logger,
	).WithDefaultTimeout(customTimeout)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &session.CleanupExpiredSessionsUseCase{}, useCase)

	// We can't directly test the timeout value since it's private
	// but we can indirectly test it by executing and checking that
	// WithTimeout is called with the expected value
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Times(2)
	timeProvider.EXPECT().WithTimeout(mock.Anything, customTimeout.Std()).Return(context.Background(), func() {})
	authSessionRepo.EXPECT().BatchDeleteExpired(mock.Anything, mock.Anything, mock.Anything).Return(int64(0), nil)
	timeProvider.EXPECT().Since(now).Return(50 * time.Millisecond)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Execute with empty input to test the default timeout
	_ = useCase.Execute(context.Background(), session.CleanupExpiredSessionsInput{})
}
