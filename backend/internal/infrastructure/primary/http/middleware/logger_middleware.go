package middleware

import (
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/gin-gonic/gin"
)

func RequestLogger(log logger.Logger) gin.HandlerFunc {
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

		log.Info("HTTP Request",
			model.NewField("method", method),
			model.NewField("path", path),
			model.NewField("status", statusCode),
			model.NewField("latency", latency.String()),
			model.NewField("ip", clientIP),
		)
	}
}
