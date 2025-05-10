package task

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/repository"
)

// SessionCleanupTask periodically cleans up expired sessions
type SessionCleanupTask struct {
	authSessionRepo repository.AuthSessionRepository
	logger          logger.Logger
	interval        time.Duration
	stopChan        chan struct{}
}

// NewSessionCleanupTask creates a new session cleanup task
func NewSessionCleanupTask(
	authSessionRepo repository.AuthSessionRepository,
	logger logger.Logger,
	interval time.Duration,
) *SessionCleanupTask {
	return &SessionCleanupTask{
		authSessionRepo: authSessionRepo,
		logger:          logger,
		interval:        interval,
		stopChan:        make(chan struct{}),
	}
}

// Start begins the session cleanup task in a goroutine
func (t *SessionCleanupTask) Start() {
	go func() {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				t.CleanupExpiredSessions()
			case <-t.stopChan:
				return
			}
		}
	}()

	t.logger.Info("Session cleanup task started", model.NewField("interval", t.interval.String()))
}

// Stop terminates the session cleanup task
func (t *SessionCleanupTask) Stop() {
	close(t.stopChan)
	t.logger.Info("Session cleanup task stopped")
}

// CleanupExpiredSessions performs the actual cleanup operation
func (t *SessionCleanupTask) CleanupExpiredSessions() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.logger.Debug("Running session cleanup task")

	err := t.authSessionRepo.DeleteExpired(ctx)
	if err != nil {
		t.logger.Error("Failed to cleanup expired sessions", model.NewField("error", err.Error()))
		return
	}

	t.logger.Info("Cleaned up expired sessions")
}
