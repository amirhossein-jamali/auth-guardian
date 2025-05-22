package routes

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/handler"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/middleware"
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all the API routes
func SetupRoutes(
	router *gin.Engine,
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	sessionHandler *handler.SessionHandler,
	authMiddleware *middleware.AuthMiddleware,
) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// API group
	api := router.Group("/api")
	{
		// Auth endpoints (public)
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
		}

		// Protected routes
		protected := api.Group("/")
		protected.Use(authMiddleware.AuthRequired())
		{
			// Auth endpoints (protected)
			protectedAuth := protected.Group("/auth")
			{
				protectedAuth.POST("/logout", authHandler.Logout)
				protectedAuth.POST("/logout-all", authHandler.LogoutAll)
				protectedAuth.POST("/logout-others", authHandler.LogoutOtherSessions)
			}

			// User endpoints
			users := protected.Group("/users")
			{
				users.GET("/me", userHandler.GetCurrentUser)
				users.PUT("/me", userHandler.UpdateCurrentUser)
			}

			// Session endpoints
			sessions := protected.Group("/sessions")
			{
				sessions.GET("", sessionHandler.GetUserSessions)
			}
		}
	}
}
