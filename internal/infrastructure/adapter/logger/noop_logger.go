package logger

import (
	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
)

// NoopLogger implements the Logger interface but doesn't do anything
// Useful for testing, development or when logging is disabled
type NoopLogger struct {
	level lport.LogLevel
}

// NewNoopLogger creates a new no-op logger
func NewNoopLogger() lport.Logger {
	return &NoopLogger{
		level: lport.LogLevelInfo,
	}
}

// SetLevel sets the minimum log level to output
func (l *NoopLogger) SetLevel(level lport.LogLevel) {
	l.level = level
}

// GetLevel gets the current log level
func (l *NoopLogger) GetLevel() lport.LogLevel {
	return l.level
}

// Debug logs debug messages
func (l *NoopLogger) Debug(message string, fields map[string]any) {
	// Do nothing
}

// Info logs informational messages
func (l *NoopLogger) Info(message string, fields map[string]any) {
	// Do nothing
}

// Warn logs warning messages
func (l *NoopLogger) Warn(message string, fields map[string]any) {
	// Do nothing
}

// Error logs error messages
func (l *NoopLogger) Error(message string, fields map[string]any) {
	// Do nothing
}
