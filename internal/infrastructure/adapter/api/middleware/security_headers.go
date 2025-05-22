package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityMiddleware adds security headers to all responses
type SecurityMiddleware struct{}

// NewSecurityMiddleware creates a new instance of SecurityMiddleware
func NewSecurityMiddleware() *SecurityMiddleware {
	return &SecurityMiddleware{}
}

// AddSecurityHeaders adds security headers to HTTP responses
func (m *SecurityMiddleware) AddSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content security policy
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Protection against clickjacking
		c.Header("X-Frame-Options", "DENY")

		// XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		c.Header("Referrer-Policy", "no-referrer-when-downgrade")

		// HSTS header for HTTPS
		// c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	}
}
