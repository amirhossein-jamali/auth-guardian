package middleware

import (
	"strings"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	apiErrors "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/errors"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware handles authentication for protected routes
type AuthMiddleware struct {
	tokenService token.TokenService
}

// NewAuthMiddleware creates a new instance of AuthMiddleware
func NewAuthMiddleware(tokenService token.TokenService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
	}
}

// AuthRequired checks for a valid authentication token and sets user information in the context
func (m *AuthMiddleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Create proper authorization error using the domain function
			err := domainErr.NewAuthorizationError("api", "access", "Authorization header is required")
			status, errResponse := apiErrors.HTTPError(err)
			c.JSON(status, errResponse)
			c.Abort()
			return
		}

		// Check if the Authorization header has the correct format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			// Create proper authorization error using the domain function
			err := domainErr.NewAuthorizationError("api", "access", "Authorization header must be in the format: Bearer {token}")
			status, errResponse := apiErrors.HTTPError(err)
			c.JSON(status, errResponse)
			c.Abort()
			return
		}

		// Extract the token
		tokenString := parts[1]
		if tokenString == "" {
			// Create proper authorization error using the domain function
			err := domainErr.NewAuthorizationError("api", "access", "Token is required")
			status, errResponse := apiErrors.HTTPError(err)
			c.JSON(status, errResponse)
			c.Abort()
			return
		}

		// Validate the token
		userID, err := m.tokenService.ValidateAccessToken(tokenString)
		if err != nil {
			// For token validation errors, we can use the domain error directly
			status, errResponse := apiErrors.HTTPError(err)
			c.JSON(status, errResponse)
			c.Abort()
			return
		}

		// Set the user ID in the context
		c.Set("userID", entity.ID(userID))
		c.Next()
	}
}
