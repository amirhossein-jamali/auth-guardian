package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/session"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/handler"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/middleware"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/routes"
	redisAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/redis"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
	"github.com/gin-gonic/gin"
)

// SetupMiddleware initializes all middleware used by the application
func SetupMiddleware(
	tokenSvc token.TokenService,
	rateLimiter storage.RateLimiter,
	appLogger logger.Logger,
) (
	*middleware.AuthMiddleware,
	*middleware.LoggerMiddleware,
	*middleware.SecurityMiddleware,
	*middleware.RedisRateLimiterMiddleware,
	*middleware.ContextMiddleware,
) {
	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(tokenSvc)
	loggerMiddleware := middleware.NewLoggerMiddleware(appLogger)
	securityMiddleware := middleware.NewSecurityMiddleware()
	contextMiddleware := middleware.NewContextMiddleware()

	// Setup rate limiter middleware if available
	var rateLimiterMiddleware *middleware.RedisRateLimiterMiddleware
	if rateLimiter != nil {
		rateLimiterMiddleware = middleware.NewRedisRateLimiterMiddleware(rateLimiter, appLogger, time.Minute, 100)
	}

	return authMiddleware, loggerMiddleware, securityMiddleware, rateLimiterMiddleware, contextMiddleware
}

// SetupHandlers initializes all API handlers with proper use cases from the service container
func SetupHandlers(services *ServiceContainer, appLogger logger.Logger) (*handler.AuthHandler, *handler.UserHandler, *handler.SessionHandler) {
	if services == nil || services.UseCaseFactory == nil {
		appLogger.Error("UseCaseFactory is nil, cannot create handlers", nil)
		return &handler.AuthHandler{}, &handler.UserHandler{}, &handler.SessionHandler{}
	}

	appLogger.Info("Creating authentication handler", nil)
	authHandler := handler.NewAuthHandler(
		services.UseCaseFactory.RegisterUseCase(),
		services.UseCaseFactory.LoginUseCase(),
		services.UseCaseFactory.LogoutUseCase(),
		services.UseCaseFactory.LogoutAllUseCase(),
		services.UseCaseFactory.LogoutOtherSessionsUseCase(),
		services.UseCaseFactory.RefreshTokenUseCase(),
	)

	appLogger.Info("Creating user handler", nil)
	userHandler := handler.NewUserHandler(
		services.UseCaseFactory.GetUserUseCase(),
		services.UseCaseFactory.UpdateProfileUseCase(),
	)

	appLogger.Info("Creating session handler", nil)
	sessionHandler := handler.NewSessionHandler(
		services.UseCaseFactory.GetSessionsUseCase(),
	)

	appLogger.Info("Handlers initialized successfully", nil)
	return authHandler, userHandler, sessionHandler
}

// SetupSessionCleanupTask initializes a periodic task to clean up expired sessions
func SetupSessionCleanupTask(services *ServiceContainer, appLogger logger.Logger) {
	if services == nil || services.UseCaseFactory == nil {
		appLogger.Error("UseCaseFactory is nil, cannot create session cleanup task", nil)
		return
	}

	// Clean up expired sessions on startup
	cleanupUseCase := services.UseCaseFactory.CleanupExpiredSessionsUseCase()
	go func() {
		if err := cleanupUseCase.Execute(context.Background(), session.CleanupExpiredSessionsInput{
			BatchSize: 1000,
		}); err != nil {
			appLogger.Error("Failed to cleanup expired sessions on startup", map[string]any{
				"error": err.Error(),
			})
		} else {
			appLogger.Info("Initial expired sessions cleanup completed", nil)
		}
	}()

	// Setup periodic task to clean up expired sessions
	ticker := time.NewTicker(24 * time.Hour) // Run once a day
	go func() {
		for range ticker.C {
			appLogger.Info("Starting periodic expired sessions cleanup", nil)
			if err := cleanupUseCase.Execute(context.Background(), session.CleanupExpiredSessionsInput{
				BatchSize: 1000,
			}); err != nil {
				appLogger.Error("Failed to cleanup expired sessions", map[string]any{
					"error": err.Error(),
				})
			} else {
				appLogger.Info("Periodic expired sessions cleanup completed", nil)
			}
		}
	}()

	appLogger.Info("Session cleanup task scheduled", nil)
}

// SetupServer initializes and configures the HTTP server
func SetupServer(
	cfg *config.Config,
	services *ServiceContainer,
	rateLimiter storage.RateLimiter,
	tokenSvc token.TokenService,
	appLogger logger.Logger,
) *http.Server {
	// Set up session cleanup task
	SetupSessionCleanupTask(services, appLogger)

	// Set Gin mode based on environment
	if os.Getenv("ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	appLogger.Info("Initializing router", nil)

	// Initialize router
	router := gin.New()

	appLogger.Info("Setting up middleware", nil)

	// Set up middleware
	authMiddleware, loggerMiddleware, securityMiddleware, rateLimiterMiddleware, contextMiddleware :=
		SetupMiddleware(tokenSvc, rateLimiter, appLogger)

	// Add middleware to router
	router.Use(gin.Recovery())
	router.Use(loggerMiddleware.LogRequest())
	router.Use(securityMiddleware.AddSecurityHeaders())
	router.Use(contextMiddleware.EnrichContext())

	// Add rate limiter if available
	if rateLimiterMiddleware != nil {
		router.Use(rateLimiterMiddleware.LimitWithRedis())
	}

	appLogger.Info("Initializing handlers", nil)

	// Initialize handlers
	authHandler, userHandler, sessionHandler := SetupHandlers(services, appLogger)

	appLogger.Info("Setting up routes", nil)

	// Set up all routes
	routes.SetupRoutes(router, authHandler, userHandler, sessionHandler, authMiddleware)

	appLogger.Info("Creating HTTP server configuration", map[string]any{
		"host": cfg.Server.Host,
		"port": cfg.Server.Port,
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	return server
}

// StartServer starts the HTTP server in a non-blocking way
func StartServer(server *http.Server, logger logger.Logger) {
	logger.Info("Starting HTTP server", map[string]any{
		"address": server.Addr,
	})

	go func() {
		logger.Info("HTTP server now listening", nil)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", map[string]any{"error": err.Error()})
		}
	}()

	logger.Info("HTTP server started in background", nil)
}

// GracefulShutdown handles graceful shutdown of all components
func GracefulShutdown(
	ctx context.Context,
	server *http.Server,
	redisManager *redisAdapter.Manager,
	logger logger.Logger,
) {
	logger.Info("Shutting down server...", nil)

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10*time.Second)
	defer shutdownCancel()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", map[string]any{"error": err.Error()})
	}

	// Close Redis connection if initialized
	if redisManager != nil {
		if err := redisManager.Close(); err != nil {
			logger.Error("Error closing Redis connection", map[string]any{"error": err.Error()})
		}
	}

	logger.Info("Server gracefully stopped", nil)
}
