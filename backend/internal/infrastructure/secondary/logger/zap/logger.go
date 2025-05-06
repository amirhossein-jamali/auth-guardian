package zap

import (
	domainLogger "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	domainModel "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/converter"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger implements the domain Logger interface using zap
type Logger struct {
	logger *zap.Logger
	fields []zap.Field
}

// NewLogger creates a new Logger instance
func NewLogger(isProduction bool) domainLogger.Logger {
	var cfg zap.Config

	if isProduction {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	zapLogger, err := cfg.Build()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}

	return &Logger{
		logger: zapLogger,
		fields: []zap.Field{},
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...domainModel.Field) {
	zapFields := l.mergeFields(fields...)
	l.logger.Debug(msg, zapFields...)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...domainModel.Field) {
	zapFields := l.mergeFields(fields...)
	l.logger.Info(msg, zapFields...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...domainModel.Field) {
	zapFields := l.mergeFields(fields...)
	l.logger.Warn(msg, zapFields...)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...domainModel.Field) {
	zapFields := l.mergeFields(fields...)
	l.logger.Error(msg, zapFields...)
}

// Fatal logs a fatal message and then exits
func (l *Logger) Fatal(msg string, fields ...domainModel.Field) {
	zapFields := l.mergeFields(fields...)
	l.logger.Fatal(msg, zapFields...)
}

// With creates a new logger with the given fields
func (l *Logger) With(fields ...domainModel.Field) domainLogger.Logger {
	// Convert domain fields to zap fields
	newZapFields := converter.DomainToZap(fields...)

	// Combine with existing fields
	combinedFields := make([]zap.Field, 0, len(l.fields)+len(newZapFields))
	combinedFields = append(combinedFields, l.fields...)
	combinedFields = append(combinedFields, newZapFields...)

	return &Logger{
		logger: l.logger,
		fields: combinedFields,
	}
}

// mergeFields combines persistent fields with the ones passed to a log method
func (l *Logger) mergeFields(fields ...domainModel.Field) []zap.Field {
	if len(fields) == 0 {
		return l.fields
	}

	newFields := converter.DomainToZap(fields...)
	result := make([]zap.Field, 0, len(l.fields)+len(newFields))
	result = append(result, l.fields...)
	result = append(result, newFields...)

	return result
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.logger.Sync()
}
