package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/configs"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/cache"
	domainJWT "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/service"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/primary/http/handler"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/primary/http/middleware"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/primary/http/router"
	cacheImpl "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/cache"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/crypto"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/identification"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/factory"
	repoImpl "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/task"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

// Application version
const (
	appVersion = "0.1.0"
)

// AppContext holds all application-wide dependencies
type AppContext struct {
	Config         *viper.Viper
	Logger         logger.Logger
	DBManager      *database.PostgresManager
	TokenService   domainJWT.TokenService
	AuthService    *service.AuthService
	SessionCleaner *task.SessionCleanupTask
	HTTPServer     *http.Server
	CacheFactory   cache.Factory
}

func main() {
	// Create a root context with cancellation for the entire application lifetime
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the application
	app, err := initializeApp(ctx)
	if err != nil {
		fmt.Printf("Failed to initialize application: %v\n", err)
		os.Exit(1)
	}
	defer cleanupApp(app)

	// Start the HTTP server
	startHTTPServer(app)

	// Start background tasks
	if err := startBackgroundTasks(app); err != nil {
		app.Logger.Error("Failed to start background tasks", model.NewField("error", err.Error()))
		// Continue execution despite task startup failure
	}

	// Wait for shutdown signal
	waitForShutdown(ctx, app)
}

// initializeApp sets up all application components
func initializeApp(ctx context.Context) (*AppContext, error) {
	app := &AppContext{}

	// Load configuration
	app.Config = configs.LoadConfig()

	// Initialize logger
	loggerFactory := factory.GetFactory(app.Config)
	app.Logger = loggerFactory.GetDomainLogger()

	app.Logger.Info("Initializing Auth Guardian API",
		model.NewField("environment", app.Config.GetString("app.environment")),
		model.NewField("version", appVersion))

	// Initialize database
	if err := initializeDatabase(ctx, app); err != nil {
		return nil, fmt.Errorf("database initialization failed: %w", err)
	}

	// Initialize cache services if Redis rate limiting is enabled
	if app.Config.GetBool("rate_limit.enabled") && app.Config.GetBool("rate_limit.use_redis") {
		if err := initializeCache(app); err != nil {
			return nil, fmt.Errorf("cache initialization failed: %w", err)
		}
	} else {
		app.Logger.Info("Redis cache initialization skipped",
			model.NewField("rate_limit.enabled", app.Config.GetBool("rate_limit.enabled")),
			model.NewField("rate_limit.use_redis", app.Config.GetBool("rate_limit.use_redis")))
	}

	// Initialize services
	if err := initializeServices(app); err != nil {
		return nil, fmt.Errorf("service initialization failed: %w", err)
	}

	// Initialize background tasks
	initializeBackgroundTasks(app)

	app.Logger.Info("Application initialization completed successfully")
	return app, nil
}

// initializeCache sets up Redis and cache-related services
func initializeCache(app *AppContext) error {
	// Initialize Redis factory
	redisFactory, err := cacheImpl.NewRedisFactory(app.Config, app.Logger)
	if err != nil {
		app.Logger.Error("Failed to create Redis factory", model.NewField("error", err.Error()))
		return err
	}

	app.CacheFactory = redisFactory
	app.Logger.Info("Redis cache services initialized")
	return nil
}

// initializeDatabase sets up the database connection and runs migrations
func initializeDatabase(ctx context.Context, app *AppContext) error {
	var err error

	// Initialize database connection
	app.DBManager, err = database.NewPostgresManager(app.Config, app.Logger)
	if err != nil {
		app.Logger.Error("Failed to connect to database", model.NewField("error", err.Error()))
		return err
	}

	// Initialize migration manager
	migrationManager := database.NewMigrationManager(app.DBManager.GetDB(), app.Logger)

	// Run database migrations
	if err := migrationManager.MigrateAll(); err != nil {
		app.Logger.Error("Failed to run database migrations", model.NewField("error", err.Error()))
		return err
	}

	// Seed initial data if needed
	if err := migrationManager.SeedData(); err != nil {
		app.Logger.Error("Failed to seed database", model.NewField("error", err.Error()))
		return err
	}

	// Verify database connection
	if err := verifyDatabaseConnection(ctx, app); err != nil {
		app.Logger.Warn("Database verification test failed", model.NewField("error", err.Error()))
		// Continue execution despite test failure
	}

	app.Logger.Info("Database initialized successfully")
	return nil
}

// verifyDatabaseConnection performs a simple database operation to verify connection
func verifyDatabaseConnection(ctx context.Context, app *AppContext) error {
	return app.DBManager.RunInTransaction(ctx, func(tx *gorm.DB) error {
		// Create a repository factory with the transaction
		repoFactory := repoImpl.NewRepositoryFactory(tx, app.Logger)

		// Get a user repository from the factory
		txUserRepo := repoFactory.CreateUserRepository()

		// Example: Check if a test email exists
		testEmail, err := valueobject.NewEmail("test@example.com")
		if err != nil {
			return err
		}
		exists, err := txUserRepo.EmailExists(ctx, *testEmail)
		if err != nil {
			return err
		}

		app.Logger.Info("Database connection verified", model.NewField("emailExists", exists))
		return nil
	})
}

// initializeServices sets up all application services
func initializeServices(app *AppContext) error {
	// Initialize repository factory
	repoFactory := repoImpl.NewRepositoryFactory(app.DBManager.GetDB(), app.Logger)

	// Initialize JWT token service
	jwtFactory, err := jwt.NewFactory(app.Config, app.Logger)
	if err != nil {
		app.Logger.Error("Failed to create JWT factory", model.NewField("error", err.Error()))
		return err
	}
	app.TokenService = jwtFactory.CreateTokenService()
	app.Logger.Info("JWT token service initialized")

	// Initialize password hasher
	passwordHasher := crypto.NewArgon2Hasher()

	// Initialize ID services
	idGenerator := identification.NewUUIDGenerator()
	idParser := identification.NewUUIDParser()
	app.Logger.Info("ID and crypto services initialized")

	// Create repositories
	userRepo := repoFactory.CreateUserRepository()
	authSessionRepo := repoFactory.CreateAuthSessionRepository()

	// Get maximum sessions per user from config
	maxSessionsPerUser := getIntWithFallback(app.Config, "sessions.maxPerUser", 5)

	// Create auth service config
	authConfig := &service.AuthServiceConfig{
		MaxSessionsPerUser:        int64(maxSessionsPerUser),
		LegacyTokenSupportEnabled: true,
		SessionCleanupTimeout:     30 * time.Second,
	}

	// Initialize auth service with all required dependencies
	app.AuthService = service.NewAuthService(
		userRepo,
		authSessionRepo,
		app.TokenService,
		app.Logger,
		passwordHasher,
		idGenerator,
		idParser,
		authConfig,
	)
	app.Logger.Info("Domain services initialized",
		model.NewField("maxSessionsPerUser", maxSessionsPerUser))

	return nil
}

// initializeBackgroundTasks sets up background maintenance tasks
func initializeBackgroundTasks(app *AppContext) {
	// Get auth session repository
	repoFactory := repoImpl.NewRepositoryFactory(app.DBManager.GetDB(), app.Logger)
	authSessionRepo := repoFactory.CreateAuthSessionRepository()

	// Get cleanup interval from config
	cleanupInterval := app.Config.GetDuration("sessions.cleanupInterval")
	if cleanupInterval <= 0 {
		cleanupInterval = 6 * time.Hour // Fallback to default
		app.Logger.Warn("Using default session cleanup interval",
			model.NewField("interval", cleanupInterval.String()))
	}

	// Create session cleanup task
	app.SessionCleaner = task.NewSessionCleanupTask(
		authSessionRepo,
		app.Logger,
		cleanupInterval,
	)

	app.Logger.Info("Background tasks prepared",
		model.NewField("cleanupInterval", cleanupInterval.String()))
}

// startBackgroundTasks starts all background maintenance tasks
func startBackgroundTasks(app *AppContext) error {
	// Start session cleanup task
	if app.SessionCleaner != nil {
		app.SessionCleaner.Start()
		app.Logger.Info("Session cleanup task started")
	} else {
		return fmt.Errorf("session cleanup task not initialized")
	}

	return nil
}

// startHTTPServer initializes and starts the HTTP server
func startHTTPServer(app *AppContext) {
	// Initialize HTTP handlers
	authHandler := handler.NewAuthHandler(app.AuthService, app.Logger)
	userHandler := handler.NewUserHandler(app.AuthService, app.Logger)
	healthHandler := handler.NewHealthHandler(app.DBManager, app.Logger)

	// Create router config
	routerConfig := router.RouterConfig{
		AuthRateLimitWindow: app.Config.GetDuration("rate_limit.auth.window"),
		AuthRateLimitCount:  getIntWithFallback(app.Config, "rate_limit.auth.count", 5),
		Config:              app.Config,
	}

	// If rate limit values are not set, use defaults
	if routerConfig.AuthRateLimitWindow <= 0 {
		routerConfig.AuthRateLimitWindow = time.Minute
		app.Logger.Warn("Using default rate limit window",
			model.NewField("window", routerConfig.AuthRateLimitWindow.String()))
	}

	if routerConfig.AuthRateLimitCount <= 0 {
		routerConfig.AuthRateLimitCount = 10
		app.Logger.Warn("Using default rate limit count",
			model.NewField("count", routerConfig.AuthRateLimitCount))
	}

	// Initialize router based on rate limiting configuration
	var httpRouter *gin.Engine

	if app.Config.GetBool("rate_limit.enabled") {
		if app.Config.GetBool("rate_limit.use_redis") && app.CacheFactory != nil {
			// Use Redis-based rate limiting
			app.Logger.Info("Using Redis-based rate limiting")

			// Create rate limiter from Redis
			rateLimiter := app.CacheFactory.CreateRateLimiter()

			// Create Redis rate limiter middleware
			redisRateLimiterMiddleware := middleware.NewRedisRateLimiterMiddleware(
				rateLimiter,
				app.Logger,
				routerConfig.AuthRateLimitWindow,
				routerConfig.AuthRateLimitCount,
			)

			// Setup router with Redis rate limiter
			httpRouter = router.SetupRouterWithRedis(
				authHandler,
				userHandler,
				healthHandler,
				app.TokenService,
				app.Logger,
				routerConfig,
				redisRateLimiterMiddleware,
			)
		} else {
			// Use simple in-memory rate limiting
			app.Logger.Info("Using simple in-memory rate limiting")
			httpRouter = router.SetupRouter(
				authHandler,
				userHandler,
				healthHandler,
				app.TokenService,
				app.Logger,
				routerConfig,
			)
		}
	} else {
		// Rate limiting is disabled, use router without rate limiting
		app.Logger.Info("Rate limiting is disabled")
		httpRouter = router.SetupRouter(
			authHandler,
			userHandler,
			healthHandler,
			app.TokenService,
			app.Logger,
			routerConfig,
		)
	}

	// Configure and create the HTTP server
	port := app.Config.GetString("app.port")
	if port == "" {
		port = "8080"
	}

	// Get timeout settings from config
	readTimeout := app.Config.GetDuration("server.readTimeout")
	writeTimeout := app.Config.GetDuration("server.writeTimeout")
	idleTimeout := app.Config.GetDuration("server.idleTimeout")

	// Use defaults if not specified
	if readTimeout <= 0 {
		readTimeout = 15 * time.Second
	}
	if writeTimeout <= 0 {
		writeTimeout = 15 * time.Second
	}
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}

	app.Logger.Info("Setting up HTTP server",
		model.NewField("port", port),
		model.NewField("readTimeout", readTimeout.String()),
		model.NewField("writeTimeout", writeTimeout.String()),
		model.NewField("idleTimeout", idleTimeout.String()))

	// Add root-level health endpoint for container health checks
	httpRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})
	app.Logger.Info("Added root-level health endpoint for container monitoring")

	app.HTTPServer = &http.Server{
		Addr:         ":" + port,
		Handler:      httpRouter,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Start the server in a goroutine
	go func() {
		app.Logger.Info("Starting HTTP server", model.NewField("port", port))
		if err := app.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.Logger.Error("Server failed", model.NewField("error", err.Error()))
			os.Exit(1)
		}
	}()
}

// waitForShutdown blocks until shutdown signal is received
func waitForShutdown(ctx context.Context, app *AppContext) {
	// Setup graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal or context cancellation
	select {
	case sig := <-shutdown:
		app.Logger.Info("Shutdown signal received", model.NewField("signal", sig.String()))
	case <-ctx.Done():
		app.Logger.Info("Context cancelled, shutting down")
	}

	// Create a context with timeout for graceful shutdown
	shutdownTimeout := app.Config.GetDuration("server.shutdownTimeout")
	if shutdownTimeout <= 0 {
		shutdownTimeout = 10 * time.Second // Default timeout
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Gracefully shut down HTTP server
	if err := app.HTTPServer.Shutdown(shutdownCtx); err != nil {
		app.Logger.Error("Server shutdown error", model.NewField("error", err.Error()))
	} else {
		app.Logger.Info("HTTP server shutdown completed")
	}
}

// cleanupApp ensures proper cleanup of all resources
func cleanupApp(app *AppContext) {
	// Cleanup ordering is important - stop tasks first, then close connections

	// Stop background tasks
	if app.SessionCleaner != nil {
		app.SessionCleaner.Stop()
		app.Logger.Info("Session cleanup task stopped")
	}

	// Close Redis connections if initialized
	if app.CacheFactory != nil {
		if err := app.CacheFactory.Close(); err != nil {
			app.Logger.Error("Error closing Redis connections", model.NewField("error", err.Error()))
		} else {
			app.Logger.Info("Redis connections closed")
		}
	}

	// Close database connection
	if app.DBManager != nil {
		if err := app.DBManager.Close(); err != nil {
			app.Logger.Error("Error closing database connection", model.NewField("error", err.Error()))
		} else {
			app.Logger.Info("Database connection closed successfully")
		}
	}

	app.Logger.Info("All resources cleaned up, application shutdown complete")
}

// getIntWithFallback gets an int value from config with fallback to default if not found
func getIntWithFallback(config *viper.Viper, key string, fallback int) int {
	if !config.IsSet(key) {
		return fallback
	}
	return config.GetInt(key)
}
