package redis

import (
	"context"
	"sync"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"
	"github.com/redis/go-redis/v9"
)

// RateLimiter implements the rate limiter interface
type RateLimiter interface {
	storage.RateLimiter
}

// RedisRateLimiter implements the rate limiter using Redis
type RedisRateLimiter struct {
	client    *redis.Client
	keyPrefix string
}

// InMemoryRateLimiter implements the rate limiter using local memory
type InMemoryRateLimiter struct {
	mu    sync.RWMutex
	items map[string]time.Time
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client *redis.Client, keyPrefix string) RateLimiter {
	return &RedisRateLimiter{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter() RateLimiter {
	return &InMemoryRateLimiter{
		items: make(map[string]time.Time),
	}
}

// Allow checks if the operation is allowed based on rate limits
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, tokens int, window time.Duration) (bool, error) {
	key = r.keyPrefix + "rate:" + key
	
	// Check if key exists
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	
	// If key doesn't exist, create it with expiration
	if exists == 0 {
		// Allow the request and set the key with expiration
		err = r.client.Set(ctx, key, tokens, window).Err()
		if err != nil {
			return false, err
		}
		return true, nil
	}
	
	// Key exists, rate limit is in effect
	return false, nil
}

// GetRemaining returns the remaining tokens for a key
func (r *RedisRateLimiter) GetRemaining(ctx context.Context, key string, rate int) (int, error) {
	key = r.keyPrefix + "rate:" + key
	
	// Check if key exists
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	
	if exists == 0 {
		// Key doesn't exist, no limit is in effect
		return rate, nil
	}
	
	// For simplicity, we return 0 if key exists (meaning limit is in effect)
	// In a real implementation, you'd want to check TTL and maintain a counter
	return 0, nil
}

// GetTTL returns the remaining time before a key expires
func (r *RedisRateLimiter) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	key = r.keyPrefix + "rate:" + key
	
	// Get TTL for the key
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	
	// If key doesn't exist or has no expiry, return 0
	if ttl < 0 {
		return 0, nil
	}
	
	return ttl, nil
}

// Allow checks if the operation is allowed based on rate limits
func (r *InMemoryRateLimiter) Allow(ctx context.Context, key string, tokens int, window time.Duration) (bool, error) {
	r.mu.RLock()
	lastAttempt, exists := r.items[key]
	r.mu.RUnlock()
	
	now := time.Now()
	
	// If the key doesn't exist or the window has passed, allow the operation
	if !exists || now.After(lastAttempt.Add(window)) {
		r.mu.Lock()
		r.items[key] = now
		r.mu.Unlock()
		return true, nil
	}
	
	// Rate limit is in effect
	return false, nil
}

// GetRemaining returns the remaining tokens for a key
func (r *InMemoryRateLimiter) GetRemaining(ctx context.Context, key string, rate int) (int, error) {
	r.mu.RLock()
	lastAttempt, exists := r.items[key]
	r.mu.RUnlock()
	
	if !exists {
		// Key doesn't exist, no limit is in effect
		return rate, nil
	}
	
	now := time.Now()
	
	// If window has passed, return rate (meaning limit is not in effect)
	if now.After(lastAttempt.Add(time.Minute)) {
		return rate, nil
	}
	
	// Limit is in effect
	return 0, nil
}

// GetTTL returns the remaining time before a key expires
func (r *InMemoryRateLimiter) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	r.mu.RLock()
	lastAttempt, exists := r.items[key]
	r.mu.RUnlock()
	
	if !exists {
		// Key doesn't exist, no TTL
		return 0, nil
	}
	
	now := time.Now()
	expiry := lastAttempt.Add(time.Minute)
	
	// If already expired, return 0
	if now.After(expiry) {
		return 0, nil
	}
	
	// Return remaining time
	return expiry.Sub(now), nil
} 