package middleware

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/gin-gonic/gin"
)

// ContextEnricher adds useful information to the request context
func ContextEnricher() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user agent and store in context
		userAgent := c.Request.UserAgent()

		// Extract IP address and store in context
		clientIP := c.ClientIP()

		// Create a new context with the values
		ctx := c.Request.Context()
		ctx = context.WithValue(ctx, valueobject.UserAgentContextKey, userAgent)
		ctx = context.WithValue(ctx, valueobject.IPContextKey, clientIP)

		// Replace the request context
		c.Request = c.Request.WithContext(ctx)

		// Also store in Gin context for backward compatibility
		c.Set("user_agent", userAgent)
		c.Set("ip", clientIP)

		c.Next()
	}
}
