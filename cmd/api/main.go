package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/amirhossein-jamali/auth-guardian/internal/bootstrap"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
)

func main() {
	// 1. Create a cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		bootstrap.FatalError("Failed to load configuration", err)
	}

	// 3. Setup loggers
	appLogger, auditLogger := bootstrap.SetupLogger(cfg)
	appLogger.Info("Starting Auth Guardian service", map[string]any{"environment": cfg.Environment})

	// 4. Setup database connection
	db := bootstrap.SetupDatabase(cfg, appLogger)
	appLogger.Info("Database connection established", nil)

	// 5. Setup Redis connection
	redisClient, rateLimiter := bootstrap.SetupRedis(ctx, cfg, appLogger)
	appLogger.Info("Redis connection established", nil)

	// 6. Setup application services
	services := bootstrap.SetupServices(cfg, db, appLogger, auditLogger)
	appLogger.Info("Application services initialized", nil)

	// 7. Setup HTTP server
	server := bootstrap.SetupServer(cfg, services, rateLimiter, services.TokenService, appLogger)
	appLogger.Info("HTTP server configured", map[string]any{"port": cfg.Server.Port})

	// 8. Start server in a non-blocking way
	bootstrap.StartServer(server, appLogger)
	appLogger.Info("Server started", map[string]any{"address": server.Addr})

	// 9. Setup graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal
	sig := <-quit
	appLogger.Info("Shutting down server", map[string]any{"signal": sig.String()})

	// Graceful shutdown with timeout context
	bootstrap.GracefulShutdown(ctx, server, redisClient, appLogger)

	appLogger.Info("Server exited properly", nil)
} 