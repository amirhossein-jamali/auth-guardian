package database

import (
	"context"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	gormlogger "gorm.io/gorm/logger"
)

// GormLoggerAdapter adapts our domain logger to GORM logger
type GormLoggerAdapter struct {
	logger        logger.Logger
	logLevel      gormlogger.LogLevel
	slowThreshold time.Duration
	timeProvider  tport.Provider
}

// newGormLogger creates a custom GORM logger adapter
func newGormLogger(log logger.Logger) gormlogger.Interface {
	return &GormLoggerAdapter{
		logger:        log,
		logLevel:      gormlogger.Info,
		slowThreshold: 200 * time.Millisecond,
		timeProvider:  nil,
	}
}

// newGormLoggerWithTimeProvider creates a GORM logger with time provider
func newGormLoggerWithTimeProvider(log logger.Logger, timeProvider tport.Provider) gormlogger.Interface {
	slowThreshold := time.Duration(200 * tport.Millisecond)

	return &GormLoggerAdapter{
		logger:        log,
		logLevel:      gormlogger.Info,
		slowThreshold: slowThreshold,
		timeProvider:  timeProvider,
	}
}

// LogMode sets the log level
func (l *GormLoggerAdapter) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	newLogger := *l
	newLogger.logLevel = level
	return &newLogger
}

// Info logs info messages
func (l *GormLoggerAdapter) Info(ctx context.Context, msg string, data ...interface{}) {
	if l.logLevel >= gormlogger.Info {
		l.logger.Info(fmt.Sprintf(msg, data...), map[string]any{"source": "gorm"})
	}
}

// Warn logs warn messages
func (l *GormLoggerAdapter) Warn(ctx context.Context, msg string, data ...interface{}) {
	if l.logLevel >= gormlogger.Warn {
		l.logger.Warn(fmt.Sprintf(msg, data...), map[string]any{"source": "gorm"})
	}
}

// Error logs error messages
func (l *GormLoggerAdapter) Error(ctx context.Context, msg string, data ...interface{}) {
	if l.logLevel >= gormlogger.Error {
		l.logger.Error(fmt.Sprintf(msg, data...), map[string]any{"source": "gorm"})
	}
}

// Trace logs SQL statements
func (l *GormLoggerAdapter) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.logLevel <= gormlogger.Silent {
		return
	}

	// اینجا باید از time.Since استفاده کنیم چون GORM ورودی time.Time می‌دهد
	elapsed := time.Since(begin)
	sql, rows := fc()

	fields := map[string]any{
		"elapsed": elapsed.String(),
		"rows":    rows,
		"sql":     sql,
	}

	// Add error field if there's an error
	if err != nil {
		fields["error"] = err.Error()
	}

	// Log slow queries as warnings
	if elapsed > l.slowThreshold && l.slowThreshold > 0 {
		l.logger.Warn("SLOW SQL", fields)
		return
	}

	// Log successful queries as info or errors
	if err != nil {
		l.logger.Error("SQL Error", fields)
	} else if l.logLevel >= gormlogger.Info {
		l.logger.Debug("SQL Query", fields) // Using debug level for SQL queries to reduce noise
	}
}
