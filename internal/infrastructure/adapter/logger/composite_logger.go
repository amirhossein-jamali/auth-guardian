package logger

import (
	"sync"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
)

// CompositeLogger implements Logger by delegating to multiple loggers
type CompositeLogger struct {
	loggers []lport.Logger
	level   lport.LogLevel
	mu      sync.RWMutex
}

// NewCompositeLogger creates a new composite logger
func NewCompositeLogger(loggers ...lport.Logger) lport.Logger {
	return &CompositeLogger{
		loggers: loggers,
		level:   lport.LogLevelInfo, // Default to Info level
	}
}

// SetLevel sets the minimum log level to output on all underlying loggers
func (l *CompositeLogger) SetLevel(level lport.LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.level = level
	// Propagate to all contained loggers
	for _, logger := range l.loggers {
		logger.SetLevel(level)
	}
}

// GetLevel gets the current log level
func (l *CompositeLogger) GetLevel() lport.LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

// AddLogger adds a logger to the composite
func (l *CompositeLogger) AddLogger(logger lport.Logger) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Set the new logger to current level
	logger.SetLevel(l.level)
	l.loggers = append(l.loggers, logger)
}

// Debug logs debug messages to all loggers
func (l *CompositeLogger) Debug(message string, fields map[string]any) {
	l.mu.RLock()
	loggers := l.loggers
	l.mu.RUnlock()

	for _, logger := range loggers {
		logger.Debug(message, fields)
	}
}

// Info logs informational messages to all loggers
func (l *CompositeLogger) Info(message string, fields map[string]any) {
	l.mu.RLock()
	loggers := l.loggers
	l.mu.RUnlock()

	for _, logger := range loggers {
		logger.Info(message, fields)
	}
}

// Warn logs warning messages to all loggers
func (l *CompositeLogger) Warn(message string, fields map[string]any) {
	l.mu.RLock()
	loggers := l.loggers
	l.mu.RUnlock()

	for _, logger := range loggers {
		logger.Warn(message, fields)
	}
}

// Error logs error messages to all loggers
func (l *CompositeLogger) Error(message string, fields map[string]any) {
	l.mu.RLock()
	loggers := l.loggers
	l.mu.RUnlock()

	for _, logger := range loggers {
		logger.Error(message, fields)
	}
}
