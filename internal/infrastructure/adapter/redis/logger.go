package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/redis/go-redis/v9"
)

// RedisLogger provides logging for Redis operations using the central logger
type RedisLogger struct {
	logger        logger.Logger
	minLogLevel   logger.LogLevel
	enableLogging bool
}

// NewRedisLogger creates a new Redis logger that uses the central logger
func NewRedisLogger(log logger.Logger, enableLogging bool) *RedisLogger {
	return &RedisLogger{
		logger:        log,
		minLogLevel:   logger.LogLevelDebug,
		enableLogging: enableLogging,
	}
}

// SetLogLevel sets the minimum log level
func (l *RedisLogger) SetLogLevel(level logger.LogLevel) {
	l.minLogLevel = level
}

// EnableLogging enables or disables logging
func (l *RedisLogger) EnableLogging(enable bool) {
	l.enableLogging = enable
}

// LogCommand logs a Redis command
func (l *RedisLogger) LogCommand(cmd, key string, args ...interface{}) {
	if !l.enableLogging || l.minLogLevel > logger.LogLevelDebug {
		return
	}

	fields := map[string]any{
		"source":  "redis",
		"command": cmd,
		"key":     key,
	}

	if len(args) > 0 {
		fields["args"] = fmt.Sprintf("%v", args)
	}

	l.logger.Debug(fmt.Sprintf("Redis command: %s %s", cmd, key), fields)
}

// LogError logs a Redis error
func (l *RedisLogger) LogError(cmd string, err error) {
	if !l.enableLogging || err == nil || l.minLogLevel > logger.LogLevelError {
		return
	}

	fields := map[string]any{
		"source":  "redis",
		"command": cmd,
		"error":   err.Error(),
	}

	l.logger.Error(fmt.Sprintf("Redis error: %s", cmd), fields)
}

// LogConnection logs connection-related events
func (l *RedisLogger) LogConnection(action, address string, err error) {
	if !l.enableLogging {
		return
	}

	fields := map[string]any{
		"source":  "redis",
		"action":  action,
		"address": address,
	}

	if err != nil {
		if l.minLogLevel <= logger.LogLevelError {
			fields["error"] = err.Error()
			l.logger.Error(fmt.Sprintf("Redis connection %s failed", action), fields)
		}
	} else if l.minLogLevel <= logger.LogLevelInfo {
		l.logger.Info(fmt.Sprintf("Redis connection %s successful", action), fields)
	}
}

// ConfigureRedisLogging sets up Redis logging according to the settings
func ConfigureRedisLogging(client *redis.Client, redisLogger *RedisLogger) {
	if redisLogger.enableLogging {
		client.Options().OnConnect = func(ctx context.Context, cn *redis.Conn) error {
			redisLogger.LogConnection("Connect", client.Options().Addr, nil)
			return nil
		}
	}
}

// WithTimeout executes a Redis function with a timeout
func WithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn(ctx)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w: %s", ErrRedisTimeout, ctx.Err())
	}
}
