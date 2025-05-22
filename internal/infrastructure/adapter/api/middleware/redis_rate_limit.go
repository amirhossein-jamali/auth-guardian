package middleware

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"
	"github.com/gin-gonic/gin"
)

// RedisRateLimiterMiddleware provides rate limiting using Redis
type RedisRateLimiterMiddleware struct {
	rateLimiter storage.RateLimiter
	logger      logger.Logger
	window      time.Duration
	rate        int
}

// NewRedisRateLimiterMiddleware creates a new instance of RedisRateLimiterMiddleware
func NewRedisRateLimiterMiddleware(
	rateLimiter storage.RateLimiter,
	logger logger.Logger,
	window time.Duration,
	rate int,
) *RedisRateLimiterMiddleware {
	return &RedisRateLimiterMiddleware{
		rateLimiter: rateLimiter,
		logger:      logger,
		window:      window,
		rate:        rate,
	}
}

// LimitWithRedis provides the Gin middleware function for Redis-based rate limiting
func (m *RedisRateLimiterMiddleware) LimitWithRedis() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a key based on the client's IP address
		key := c.ClientIP()

		// Check if the request is allowed
		allowed, err := m.rateLimiter.Allow(c.Request.Context(), key, m.rate, m.window)

		if err != nil {
			m.logger.Error("Rate limiting error", map[string]any{
				"ip":    key,
				"error": err.Error(),
			})

			// Allow the request to proceed if there's an error with rate limiting
			c.Next()
			return
		}

		if !allowed {
			m.logger.Warn("Rate limit exceeded", map[string]any{
				"ip":     key,
				"rate":   m.rate,
				"window": m.window.String(),
			})

			// Get remaining time until rate limit resets
			ttl, err := m.getTTL(c.Request.Context(), key)
			if err != nil {
				ttl = m.window // Use window time as fallback
			}

			// Set headers to inform client about rate limits
			c.Header("X-RateLimit-Limit", strconv.Itoa(m.rate))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(ttl).Unix(), 10))
			c.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"wait":  ttl.String(),
			})
			return
		}

		// Get remaining requests
		remaining, err := m.rateLimiter.GetRemaining(c.Request.Context(), key, m.rate)
		if err == nil {
			c.Header("X-RateLimit-Limit", strconv.Itoa(m.rate))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		}

		c.Next()
	}
}

// getTTL gets the TTL of a rate limit key
func (m *RedisRateLimiterMiddleware) getTTL(ctx context.Context, key string) (time.Duration, error) {
	return m.rateLimiter.GetTTL(ctx, "rate_limit:"+key)
}
