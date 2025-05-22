package logger

import (
	"context"
	"sync"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
)

// CompositeAuditLogger implements AuditLogger by delegating to multiple loggers
type CompositeAuditLogger struct {
	loggers []lport.AuditLogger
	logger  lport.Logger
}

// NewCompositeAuditLogger creates a new composite audit logger
func NewCompositeAuditLogger(logger lport.Logger, loggers ...lport.AuditLogger) lport.AuditLogger {
	return &CompositeAuditLogger{
		loggers: loggers,
		logger:  logger,
	}
}

// LogSecurityEvent logs a security-related event with metadata to all underlying loggers
func (l *CompositeAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error {
	// If no loggers, just return
	if len(l.loggers) == 0 {
		return nil
	}

	// If only one logger, use it directly
	if len(l.loggers) == 1 {
		return l.loggers[0].LogSecurityEvent(ctx, eventType, metadata)
	}

	// For multiple loggers, use concurrent execution with error aggregation
	var wg sync.WaitGroup
	errs := make([]error, len(l.loggers))

	for i, auditLogger := range l.loggers {
		wg.Add(1)
		go func(idx int, lg interface {
			LogSecurityEvent(context.Context, string, map[string]any) error
		}) {
			defer wg.Done()
			errs[idx] = lg.LogSecurityEvent(ctx, eventType, metadata)
		}(i, auditLogger)
	}

	// Wait for all logging operations to complete
	wg.Wait()

	// Check for errors
	for i, err := range errs {
		if err != nil {
			// Log the error but don't fail the operation
			l.logger.Warn("Audit logger failed", map[string]any{
				"index": i,
				"error": err.Error(),
				"event": eventType,
			})
		}
	}

	// Return nil as we've already logged any errors
	// This prevents audit log failures from affecting the main application flow
	return nil
}

// Flush ensures all buffered logs are written to their destination by all underlying loggers
func (l *CompositeAuditLogger) Flush() error {
	// If no loggers, just return
	if len(l.loggers) == 0 {
		return nil
	}

	// If only one logger, use it directly
	if len(l.loggers) == 1 {
		return l.loggers[0].Flush()
	}

	// For multiple loggers, use concurrent execution with error aggregation
	var wg sync.WaitGroup
	errs := make([]error, len(l.loggers))

	for i, auditLogger := range l.loggers {
		wg.Add(1)
		go func(idx int, lg interface{ Flush() error }) {
			defer wg.Done()
			errs[idx] = lg.Flush()
		}(i, auditLogger)
	}

	// Wait for all flush operations to complete
	wg.Wait()

	// Check for errors
	for i, err := range errs {
		if err != nil {
			// Log the error but don't fail the operation
			l.logger.Warn("Audit logger flush failed", map[string]any{
				"index": i,
				"error": err.Error(),
			})
		}
	}

	// Return nil as we've already logged any errors
	return nil
}
