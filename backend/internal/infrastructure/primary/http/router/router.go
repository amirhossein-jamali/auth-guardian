package router

import (
	"strings"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/primary/http/handler"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/primary/http/middleware"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// RouterConfig holds configuration for the router
type RouterConfig struct {
	// Rate limiting configuration
	AuthRateLimitWindow time.Duration
	AuthRateLimitCount  int
	// Config for accessing settings
	Config *viper.Viper
}

// DefaultRouterConfig returns default configuration for the router
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		AuthRateLimitWindow: time.Minute,
		AuthRateLimitCount:  10,
	}
}

// SetupRouter configures and returns a Gin router with all application routes
func SetupRouter(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	healthHandler *handler.HealthHandler,
	tokenService jwt.TokenService,
	logger logger.Logger,
	config RouterConfig,
) *gin.Engine {
	// Create a new Gin router without default middleware
	r := gin.New()

	// Apply global middleware
	setupGlobalMiddleware(r, logger)

	// Create rate limiter for auth endpoints
	authRateLimiter := middleware.NewSimpleRateLimiter(
		config.AuthRateLimitWindow,
		config.AuthRateLimitCount,
		logger,
	)

	// Set up API routes
	api := r.Group("/api")
	{
		// Health check endpoint
		setupHealthRoutes(api, healthHandler, authRateLimiter, logger, config.Config)

		// Auth routes
		setupAuthRoutes(api, authHandler, tokenService, logger, authRateLimiter)

		// User routes (protected by auth middleware)
		setupUserRoutes(api, userHandler, tokenService, logger)
	}

	logger.Info("Router setup completed", model.NewField("endpoints", "health, auth, users"))
	return r
}

// SetupRouterWithRedis configures and returns a Gin router with Redis rate limiting
func SetupRouterWithRedis(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	healthHandler *handler.HealthHandler,
	tokenService jwt.TokenService,
	logger logger.Logger,
	config RouterConfig,
	redisRateLimiter *middleware.RedisRateLimiterMiddleware,
) *gin.Engine {
	// Create a new Gin router without default middleware
	r := gin.New()

	// Apply global middleware
	setupGlobalMiddleware(r, logger)

	// Create a simple rate limiter for health endpoint
	healthRateLimiter := middleware.NewSimpleRateLimiter(
		config.AuthRateLimitWindow,
		config.AuthRateLimitCount,
		logger,
	)

	// Set up API routes
	api := r.Group("/api")
	{
		// Health check endpoint
		setupHealthRoutes(api, healthHandler, healthRateLimiter, logger, config.Config)

		// Auth routes with Redis rate limiting
		setupAuthRoutesWithRedis(api, authHandler, tokenService, logger, redisRateLimiter)

		// User routes (protected by auth middleware)
		setupUserRoutes(api, userHandler, tokenService, logger)
	}

	logger.Info("Router setup completed with Redis rate limiting",
		model.NewField("endpoints", "health, auth, users"))
	return r
}

// setupGlobalMiddleware adds middleware that applies to all routes
func setupGlobalMiddleware(r *gin.Engine, logger logger.Logger) {
	// Recovery middleware handles panics and returns 500
	r.Use(gin.Recovery())

	// Request logging
	r.Use(middleware.RequestLogger(logger))

	// Security headers for all responses
	r.Use(middleware.SecurityHeaders())

	// Enriches request context with common data (user-agent, IP)
	r.Use(middleware.ContextEnricher())
}

// setupHealthRoutes configures health check endpoints
func setupHealthRoutes(api *gin.RouterGroup, healthHandler *handler.HealthHandler, rateLimiter *middleware.SimpleRateLimiter, logger logger.Logger, config *viper.Viper) {
	var allowedIPs []string

	if config != nil {
		ipsList := config.GetString("monitoring.allowed_ips")
		if ipsList != "" {
			allowedIPs = strings.Split(ipsList, ",")
		} else {
			allowedIPs = config.GetStringSlice("monitoring.allowed_ips")
		}
	}

	if len(allowedIPs) == 0 {
		allowedIPs = []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	}

	healthGroup := api.Group("/monitoring")
	healthGroup.Use(middleware.RestrictByIP(logger, allowedIPs))
	healthGroup.GET("/health", middleware.RateLimit(rateLimiter), healthHandler.HandleHealthCheck)
}

// setupAuthRoutes configures authentication endpoints
func setupAuthRoutes(
	api *gin.RouterGroup,
	authHandler *handler.AuthHandler,
	tokenService jwt.TokenService,
	logger logger.Logger,
	rateLimiter *middleware.SimpleRateLimiter,
) {
	auth := api.Group("/auth")

	// Public endpoints (rate limited)
	auth.POST("/register", middleware.RateLimit(rateLimiter), authHandler.Register)
	auth.POST("/login", middleware.RateLimit(rateLimiter), authHandler.Login)
	auth.POST("/refresh", middleware.RateLimit(rateLimiter), authHandler.RefreshToken)

	// Protected endpoints (require authentication)
	authProtected := auth.Group("/")
	authProtected.Use(middleware.AuthMiddleware(tokenService, logger))
	{
		authProtected.POST("/logout", authHandler.Logout)
		authProtected.POST("/logout-all", authHandler.LogoutAll)
		authProtected.GET("/sessions", authHandler.GetSessions)
	}
}

// setupAuthRoutesWithRedis configures authentication endpoints with Redis rate limiting
func setupAuthRoutesWithRedis(
	api *gin.RouterGroup,
	authHandler *handler.AuthHandler,
	tokenService jwt.TokenService,
	logger logger.Logger,
	redisRateLimiter *middleware.RedisRateLimiterMiddleware,
) {
	auth := api.Group("/auth")

	// Public endpoints (rate limited with Redis)
	auth.POST("/register", redisRateLimiter.Handle(), authHandler.Register)
	auth.POST("/login", redisRateLimiter.Handle(), authHandler.Login)
	auth.POST("/refresh", redisRateLimiter.Handle(), authHandler.RefreshToken)

	// Protected endpoints (require authentication)
	authProtected := auth.Group("/")
	authProtected.Use(middleware.AuthMiddleware(tokenService, logger))
	{
		authProtected.POST("/logout", authHandler.Logout)
		authProtected.POST("/logout-all", authHandler.LogoutAll)
		authProtected.GET("/sessions", authHandler.GetSessions)
	}
}

// setupUserRoutes configures user profile management endpoints
func setupUserRoutes(
	api *gin.RouterGroup,
	userHandler *handler.UserHandler,
	tokenService jwt.TokenService,
	logger logger.Logger,
) {
	users := api.Group("/users")
	users.Use(middleware.AuthMiddleware(tokenService, logger))
	{
		users.GET("/me", userHandler.GetProfile)
		users.PUT("/me", userHandler.UpdateProfile)
	}
}
