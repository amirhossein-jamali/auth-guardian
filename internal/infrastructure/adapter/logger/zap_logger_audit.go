package logger

import (
	"context"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ZapAuditLogger implements the AuditLogger interface using Zap
type ZapAuditLogger struct {
	logger     *zap.Logger
	timeSource tport.Provider
}

// NewZapAuditLogger creates a new audit logger instance
func NewZapAuditLogger(timeSource tport.Provider, isProduction bool) lport.AuditLogger {
	// Configure zap logger
	var cfg zap.Config

	if isProduction {
		// In production, use a JSON encoder for structured logging
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		cfg.OutputPaths = []string{"stdout", "audit.log"} // Log to both console and file
	} else {
		// In development, use a console encoder for easier reading
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set additional encoding options
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.MessageKey = "event"
	cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel) // Audit logs are always at least Info level

	// Build the logger
	zapLogger, err := cfg.Build(
		zap.Fields(
			zap.String("logger", "audit"),
		),
	)
	if err != nil {
		panic("failed to initialize audit logger: " + err.Error())
	}

	return &ZapAuditLogger{
		logger:     zapLogger,
		timeSource: timeSource,
	}
}

// LogSecurityEvent logs a security-related event with metadata
func (l *ZapAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error {
	// Extract common fields from metadata
	userID := extractUserID(metadata)
	ip, _ := metadata["ip"].(string)
	requestID := extractRequestID(ctx)

	// Get timestamp using timeSource
	timestamp := l.timeSource.Now().Format(tport.RFC3339Format)

	// Create standard fields that we want in every audit log
	fields := []zap.Field{
		zap.String("eventType", eventType),
		zap.String("timestamp", timestamp),
	}

	// Add user ID if available
	if userID != "" {
		fields = append(fields, zap.String("userId", userID))
	}

	// Add IP if available
	if ip != "" {
		fields = append(fields, zap.String("ip", ip))
	}

	// Add request ID if available
	if requestID != "" {
		fields = append(fields, zap.String("requestId", requestID))
	}

	// Add all other metadata (excluding fields we've already handled)
	cleanMeta := cleanMetadata(metadata, []string{"userId", "user_id", "ip"})
	for k, v := range cleanMeta {
		fields = append(fields, zap.Any(k, v))
	}

	// Log the event
	l.logger.Info(eventType, fields...)

	return nil
}

// Flush ensures all buffered logs are written to their destination
func (l *ZapAuditLogger) Flush() error {
	// Sync forces buffered logs to be written
	return l.logger.Sync()
}
