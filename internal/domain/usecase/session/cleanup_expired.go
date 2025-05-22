package session

import (
	"context"
	"errors"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// CleanupExpiredSessionsInput represents data needed to clean up expired sessions
type CleanupExpiredSessionsInput struct {
	BatchSize int            // Number of records per batch, zero means full cleanup
	Timeout   tport.Duration // Optional timeout for the operation
}

// CleanupExpiredSessionsUseCase handles cleaning up expired sessions
type CleanupExpiredSessionsUseCase struct {
	authSessionRepo repository.AuthSessionRepository
	timeProvider    tport.Provider
	logger          logger.Logger
	defaultTimeout  tport.Duration
}

// NewCleanupExpiredSessionsUseCase creates a new instance of CleanupExpiredSessionsUseCase
func NewCleanupExpiredSessionsUseCase(
	authSessionRepo repository.AuthSessionRepository,
	timeProvider tport.Provider,
	logger logger.Logger,
) *CleanupExpiredSessionsUseCase {
	return &CleanupExpiredSessionsUseCase{
		authSessionRepo: authSessionRepo,
		timeProvider:    timeProvider,
		logger:          logger,
		defaultTimeout:  30 * tport.Second, // Default timeout
	}
}

// WithDefaultTimeout sets the default timeout for cleanup operations
func (uc *CleanupExpiredSessionsUseCase) WithDefaultTimeout(timeout tport.Duration) *CleanupExpiredSessionsUseCase {
	uc.defaultTimeout = timeout
	return uc
}

// Execute cleans up expired sessions with batch processing to prevent overload
func (uc *CleanupExpiredSessionsUseCase) Execute(ctx context.Context, input CleanupExpiredSessionsInput) error {
	// Start measuring execution time
	startTime := uc.timeProvider.Now()

	// Apply timeout to context if specified, otherwise use default
	timeout := uc.defaultTimeout
	if input.Timeout > 0 {
		timeout = input.Timeout
	}

	// Create a new context with timeout - convert tport.Duration to time.Duration using Std()
	ctx, cancel := uc.timeProvider.WithTimeout(ctx, timeout.Std())
	defer cancel()

	now := uc.timeProvider.Now()

	// If batch size not specified, use default
	batchSize := 500
	if input.BatchSize > 0 {
		batchSize = input.BatchSize
	}

	// Use the batch delete method from the repository
	// In a real implementation, this method would delete expired sessions in batches
	// to prevent database overload
	totalDeleted, err := uc.deleteExpiredInBatches(ctx, now, batchSize)
	if err != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			uc.logger.Warn("Session cleanup timed out", map[string]any{
				"timeout":       timeout.String(),
				"deleted_count": totalDeleted,
			})
			return nil
		}

		uc.logger.Error("Failed to delete expired sessions", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	// Calculate execution time - use Provider for time calculations
	elapsed := uc.timeProvider.Since(startTime)

	uc.logger.Info("Expired sessions cleaned up successfully", map[string]any{
		"deleted_count": totalDeleted,
		"elapsed":       elapsed.String(),
	})
	return nil
}

// deleteExpiredInBatches deletes expired sessions in batches to prevent overload
func (uc *CleanupExpiredSessionsUseCase) deleteExpiredInBatches(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	var totalDeleted int64

	// Continue deleting in batches until no more expired sessions are found
	for {
		// Check for context cancellation
		if ctx.Err() != nil {
			return totalDeleted, ctx.Err()
		}

		// Delete a batch of expired sessions
		deletedCount, err := uc.authSessionRepo.BatchDeleteExpired(ctx, before, batchSize)
		if err != nil {
			return totalDeleted, err
		}

		// Update total count
		totalDeleted += deletedCount

		// Log progress for larger cleanups
		if totalDeleted > 0 && totalDeleted%int64(batchSize*5) == 0 {
			uc.logger.Info("Cleanup progress", map[string]any{
				"deleted_so_far": totalDeleted,
			})
		}

		// If we deleted fewer sessions than the batch size, we're done
		if deletedCount < int64(batchSize) {
			break
		}
	}

	// Log final count only if sessions were deleted
	if totalDeleted > 0 {
		uc.logger.Info("Expired sessions cleanup completed", map[string]any{
			"total_deleted": totalDeleted,
		})
	}

	return totalDeleted, nil
}
