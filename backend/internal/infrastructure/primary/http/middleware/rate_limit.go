package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"

	"github.com/gin-gonic/gin"
)

type SimpleRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	window   time.Duration
	limit    int
	logger   logger.Logger
}

func NewSimpleRateLimiter(window time.Duration, limit int, logger logger.Logger) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		limit:    limit,
		logger:   logger,
	}
}

func (rl *SimpleRateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean up old requests
	if times, exists := rl.requests[key]; exists {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rl.requests[key] = valid
	}

	// Check if over limit
	if len(rl.requests[key]) >= rl.limit {
		return false
	}

	// Allow and record the request
	rl.requests[key] = append(rl.requests[key], now)
	return true
}

func RateLimit(limiter *SimpleRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use IP address as the rate limiting key
		clientIP := c.ClientIP()

		if !limiter.Allow(clientIP) {
			limiter.logger.Warn("Rate limit exceeded",
				model.NewField("ip", clientIP),
				model.NewField("path", c.FullPath()))

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
