package middleware

import (
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/gin-gonic/gin"
)

// LoggerMiddleware handles HTTP request logging
type LoggerMiddleware struct {
	logger logger.Logger
}

// NewLoggerMiddleware creates a new instance of LoggerMiddleware
func NewLoggerMiddleware(logger logger.Logger) *LoggerMiddleware {
	return &LoggerMiddleware{
		logger: logger,
	}
}

// LogRequest logs HTTP request details
func (m *LoggerMiddleware) LogRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()

		m.logger.Info("HTTP Request", map[string]any{
			"method":  method,
			"path":    path,
			"status":  statusCode,
			"latency": latency.String(),
			"ip":      clientIP,
		})
	}
}
