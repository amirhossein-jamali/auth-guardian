// Create file: internal/domain/port/secondary/cache/rate_limiter.go
package cache

import (
	"context"
	"time"
)

// RateLimiter defines the interface for rate limiting service
type RateLimiter interface {
	// Allow checks if a request is allowed based on the key, rate and window
	Allow(ctx context.Context, key string, rate int, window time.Duration) (bool, error)

	// Reset resets the counter for a specific key
	Reset(ctx context.Context, key string) error

	// GetRemaining returns the number of remaining requests for a specific key
	GetRemaining(ctx context.Context, key string, rate int) (int, error)

	// GetTTL returns the TTL of a specific key
	GetTTL(ctx context.Context, key string) (time.Duration, error)
}
