package logger

import (
	"context"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
)

// NoopAuditLogger implements the AuditLogger interface but doesn't do anything
// Useful for testing, development or when audit logging is disabled
type NoopAuditLogger struct{}

// NewNoopAuditLogger creates a new no-op audit logger
func NewNoopAuditLogger() lport.AuditLogger {
	return &NoopAuditLogger{}
}

// LogSecurityEvent implements AuditLogger interface but does nothing
func (l *NoopAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error {
	// Do nothing
	return nil
}

// Flush implements AuditLogger interface but does nothing
func (l *NoopAuditLogger) Flush() error {
	// Do nothing
	return nil
}
