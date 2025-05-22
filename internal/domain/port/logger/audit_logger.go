package logger

import "context"

// AuditLogger defines interface for security audit logging
type AuditLogger interface {
	// LogSecurityEvent logs a security-related event with metadata
	LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error

	// Flush ensures all buffered logs are written to their destination
	// Useful during application shutdown to prevent log loss
	Flush() error
}
