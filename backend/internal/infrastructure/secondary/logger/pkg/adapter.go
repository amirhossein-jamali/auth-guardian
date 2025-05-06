package pkg

import (
	domainLogger "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/converter"
	pkgLogger "github.com/amirhossein-jamali/auth-guardian/pkg/logger"
	pkgModel "github.com/amirhossein-jamali/auth-guardian/pkg/logger/model"
)

// Adapter adapts a domain logger to the pkg logger interface
type Adapter struct {
	domainLogger domainLogger.Logger
}

// NewAdapter creates a new adapter that converts domain logger to pkg logger
func NewAdapter(logger domainLogger.Logger) pkgLogger.Logger {
	return &Adapter{
		domainLogger: logger,
	}
}

// Debug logs a debug message
func (a *Adapter) Debug(msg string, fields ...pkgModel.Field) {
	a.domainLogger.Debug(msg, converter.PkgToDomain(fields...)...)
}

// Info logs an info message
func (a *Adapter) Info(msg string, fields ...pkgModel.Field) {
	a.domainLogger.Info(msg, converter.PkgToDomain(fields...)...)
}

// Warn logs a warning message
func (a *Adapter) Warn(msg string, fields ...pkgModel.Field) {
	a.domainLogger.Warn(msg, converter.PkgToDomain(fields...)...)
}

// Error logs an error message
func (a *Adapter) Error(msg string, fields ...pkgModel.Field) {
	a.domainLogger.Error(msg, converter.PkgToDomain(fields...)...)
}

// Fatal logs a fatal message
func (a *Adapter) Fatal(msg string, fields ...pkgModel.Field) {
	a.domainLogger.Fatal(msg, converter.PkgToDomain(fields...)...)
}

// With creates a new logger with the given fields
func (a *Adapter) With(fields ...pkgModel.Field) pkgLogger.Logger {
	// Convert all pkg fields to domain fields
	domainFields := converter.PkgToDomain(fields...)

	// Create a new domain logger with these fields
	newLogger := a.domainLogger.With(domainFields...)

	// Return a new adapter with the updated domain logger
	return &Adapter{
		domainLogger: newLogger,
	}
}
