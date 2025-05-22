package bootstrap

import (
	"os"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	loggerAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
)

// SetupLogger initializes and configures the application logger
func SetupLogger(cfg *config.Config) (logger.Logger, logger.AuditLogger) {
	// Check if we're in production mode
	var isProduction bool
	if os.Getenv("ENV") == "production" {
		isProduction = true
	}

	// Initialize the application logger
	appLogger := loggerAdapter.NewZapLogger(isProduction)

	// Initialize time provider for audit logger
	timeProvider := time.NewRealTimeProvider()

	// Initialize audit logger if enabled in config
	var auditLogger logger.AuditLogger
	if cfg.Logger.EnableAudit {
		auditLogger = loggerAdapter.NewZapAuditLogger(timeProvider, isProduction)
	}

	return appLogger, auditLogger
}

// FatalError logs a fatal error and exits the application
func FatalError(message string, err error) {
	// Create a simple logger for bootstrapping errors
	appLogger := loggerAdapter.NewZapLogger(false)
	appLogger.Error(message, map[string]any{"error": err.Error()})
	os.Exit(1)
}
