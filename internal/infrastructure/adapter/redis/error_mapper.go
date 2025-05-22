package redis

import (
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Common Redis error types
var (
	ErrRedisConnection      = errors.New("redis connection error")
	ErrRedisTimeout         = errors.New("redis operation timed out")
	ErrRedisKeyNotFound     = errors.New("redis key not found")
	ErrRedisCommandFailed   = errors.New("redis command failed")
	ErrRedisMarshal         = errors.New("failed to marshal data for redis")
	ErrRedisUnmarshal       = errors.New("failed to unmarshal data from redis")
	ErrRedisTransactionFail = errors.New("redis transaction failed")
)

// MapError converts Redis errors to more specific domain errors
func MapError(err error) error {
	if err == nil {
		return nil
	}

	// Handle specific Redis errors
	if errors.Is(err, redis.Nil) {
		return ErrRedisKeyNotFound
	}

	// Check for various errors based on error strings
	errorString := err.Error()

	switch {
	case isConnectionError(errorString):
		return fmt.Errorf("%w: %s", ErrRedisConnection, err)
	case isTimeoutError(errorString):
		return fmt.Errorf("%w: %s", ErrRedisTimeout, err)
	default:
		return fmt.Errorf("%w: %s", ErrRedisCommandFailed, err)
	}
}

// Helper functions to identify error types
func isConnectionError(errorString string) bool {
	connectionErrors := []string{
		"connection refused",
		"connection reset",
		"connection closed",
		"no connection",
		"dial timeout",
	}

	for _, msg := range connectionErrors {
		if containsString(errorString, msg) {
			return true
		}
	}
	return false
}

func isTimeoutError(errorString string) bool {
	timeoutErrors := []string{
		"timeout",
		"deadline exceeded",
	}

	for _, msg := range timeoutErrors {
		if containsString(errorString, msg) {
			return true
		}
	}
	return false
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr
}
