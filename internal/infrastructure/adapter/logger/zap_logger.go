package logger

import (
	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ZapLogger implements the Logger interface using Zap
type ZapLogger struct {
	logger *zap.Logger
	level  lport.LogLevel
}

// NewZapLogger creates a new logger instance
func NewZapLogger(isProduction bool) lport.Logger {
	// Configure zap logger
	var cfg zap.Config

	if isProduction {
		// In production, use a JSON encoder for structured logging
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		// In development, use a console encoder for easier reading
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set additional encoding options
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.MessageKey = "message"

	// Build the logger
	zapLogger, err := cfg.Build()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}

	return &ZapLogger{
		logger: zapLogger,
		level:  lport.LogLevelInfo, // Default level
	}
}

// SetLevel sets the minimum log level to output
func (l *ZapLogger) SetLevel(level lport.LogLevel) {
	l.level = level

	// Convert logger.LogLevel to zap.AtomicLevel
	var zapLevel zapcore.Level
	switch level {
	case lport.LogLevelDebug:
		zapLevel = zap.DebugLevel
	case lport.LogLevelInfo:
		zapLevel = zap.InfoLevel
	case lport.LogLevelWarn:
		zapLevel = zap.WarnLevel
	case lport.LogLevelError:
		zapLevel = zap.ErrorLevel
	default:
		zapLevel = zap.InfoLevel
	}

	// Update the logger's level
	l.logger.Core().Enabled(zapLevel)
}

// GetLevel gets the current log level
func (l *ZapLogger) GetLevel() lport.LogLevel {
	return l.level
}

// Debug logs debug messages
func (l *ZapLogger) Debug(message string, fields map[string]any) {
	if l.level > lport.LogLevelDebug {
		return
	}
	l.logger.Debug(message, mapToZapFields(fields)...)
}

// Info logs informational messages
func (l *ZapLogger) Info(message string, fields map[string]any) {
	if l.level > lport.LogLevelInfo {
		return
	}
	l.logger.Info(message, mapToZapFields(fields)...)
}

// Warn logs warning messages
func (l *ZapLogger) Warn(message string, fields map[string]any) {
	if l.level > lport.LogLevelWarn {
		return
	}
	l.logger.Warn(message, mapToZapFields(fields)...)
}

// Error logs error messages
func (l *ZapLogger) Error(message string, fields map[string]any) {
	l.logger.Error(message, mapToZapFields(fields)...)
}

// Flush ensures all buffered logs are written to their destination
func (l *ZapLogger) Flush() error {
	// Sync forces buffered logs to be written
	err := l.logger.Sync()
	
	// On Windows, syncing stdout/stderr can fail with "invalid argument"
	// We can safely ignore this specific error
	if err != nil && (err.Error() == "sync /dev/stdout: invalid argument" || 
		err.Error() == "sync /dev/stderr: invalid argument") {
		return nil
	}
	return err
}

// mapToZapFields converts a map to zap fields
func mapToZapFields(fields map[string]any) []zap.Field {
	if fields == nil {
		return []zap.Field{}
	}

	zapFields := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}
	return zapFields
}
