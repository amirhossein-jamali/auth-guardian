package storage

import (
	"context"
	"time"
)

// RateLimiter defines the interface for rate limiting functionality
type RateLimiter interface {
	// Allow checks if a new request is allowed based on rate limits
	Allow(ctx context.Context, key string, rate int, window time.Duration) (bool, error)
	// GetRemaining returns the remaining allowed requests for a key
	GetRemaining(ctx context.Context, key string, rate int) (int, error)
	// GetTTL returns the remaining time before a key expires
	GetTTL(ctx context.Context, key string) (time.Duration, error)
}
