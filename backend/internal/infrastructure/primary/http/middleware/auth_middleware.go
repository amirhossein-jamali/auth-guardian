// internal/infrastructure/primary/http/middleware/auth_middleware.go
package middleware

import (
	"net/http"
	"strings"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(tokenService jwt.TokenService, logger logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check if the header has the correct format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := tokenService.ValidateAccessToken(token)
		if err != nil {
			logger.Warn("Invalid token", model.NewField("error", err.Error()))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Check if token is blacklisted
		blacklisted, err := tokenService.BlacklistCheck(token)
		if err != nil {
			logger.Error("Failed to check token blacklist", model.NewField("error", err.Error()))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate token"})
			c.Abort()
			return
		}

		if blacklisted {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
			c.Abort()
			return
		}

		// Set user ID to context for future use
		c.Set("userID", claims.UserID)
		logger.Info("User authenticated", model.NewField("userId", claims.UserID))
		c.Next()
	}
}
