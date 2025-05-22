package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// Context keys
const (
	UserAgentContextKey contextKey = "user_agent"
	IPContextKey        contextKey = "ip"
)

// ContextMiddleware adds useful information to the request context
type ContextMiddleware struct{}

// NewContextMiddleware creates a new instance of ContextMiddleware
func NewContextMiddleware() *ContextMiddleware {
	return &ContextMiddleware{}
}

// EnrichContext adds useful information to the request context
func (m *ContextMiddleware) EnrichContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user agent and store in context
		userAgent := c.Request.UserAgent()

		// Extract IP address and store in context
		clientIP := c.ClientIP()

		// Create a new context with the values
		ctx := c.Request.Context()
		ctx = context.WithValue(ctx, UserAgentContextKey, userAgent)
		ctx = context.WithValue(ctx, IPContextKey, clientIP)

		// Replace the request context
		c.Request = c.Request.WithContext(ctx)

		// Also store in Gin context for easy access
		c.Set(string(UserAgentContextKey), userAgent)
		c.Set(string(IPContextKey), clientIP)

		c.Next()
	}
}
