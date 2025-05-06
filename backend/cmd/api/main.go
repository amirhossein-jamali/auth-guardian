package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/configs"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/factory"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/mapper"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/repository"
	"gorm.io/gorm"
)

func main() {
	// Create a root context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	config := configs.LoadConfig()

	// Initialize logger
	loggerFactory := factory.GetFactory(config)
	log := loggerFactory.GetDomainLogger()

	log.Info("Starting Auth Guardian API",
		model.NewField("environment", config.GetString("app.environment")),
		model.NewField("version", "0.1.0"))

	// Initialize database connection
	dbManager, err := database.NewPostgresManager(config, log)
	if err != nil {
		log.Error("Failed to connect to database", model.NewField("error", err.Error()))
		os.Exit(1)
	}

	// Initialize migration manager
	migrationManager := database.NewMigrationManager(dbManager.GetDB(), log)

	// Run database migrations
	if err := migrationManager.MigrateAll(); err != nil {
		log.Error("Failed to run database migrations", model.NewField("error", err.Error()))
		os.Exit(1)
	}

	// Seed initial data if needed
	if err := migrationManager.SeedData(); err != nil {
		log.Error("Failed to seed database", model.NewField("error", err.Error()))
		os.Exit(1)
	}

	// Initialize repository factory
	repoFactory := repository.NewRepositoryFactory(dbManager.GetDB(), log)

	// Initialize repositories
	// Just create the repository instance but we don't need to use it right now
	_ = repoFactory.CreateUserRepository()

	// Test database connection with a simple transaction
	err = dbManager.RunInTransaction(ctx, func(tx *gorm.DB) error {
		// Create a repository with the transaction
		txUserRepo := repository.NewGormUserRepository(tx, log, mapper.NewUserMapper(log))

		// Example: Check if a test email exists
		testEmail, err := valueobject.NewEmail("test@example.com")
		if err != nil {
			return err
		}
		exists, err := txUserRepo.EmailExists(ctx, *testEmail)
		if err != nil {
			return err
		}

		log.Info("Database transaction test", model.NewField("emailExists", exists))
		return nil
	})

	if err != nil {
		log.Error("Database transaction test failed", model.NewField("error", err.Error()))
		// Continue execution, as this is just a test
	} else {
		log.Info("Database transaction test succeeded")
	}

	// Initialize auth service (to be implemented in the next phase)
	// TODO: Initialize auth service with the repositories

	// Initialize HTTP server (to be implemented in the next phase)
	// TODO: Initialize and start HTTP server

	log.Info("Server initialization completed, ready to serve requests")

	// Setup graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt signal or context cancellation
	select {
	case sig := <-shutdown:
		log.Info("Shutdown signal received", model.NewField("signal", sig.String()))
	case <-ctx.Done():
		log.Info("Context cancelled, shutting down")
	}

	// Create a context with timeout for graceful shutdown
	_, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// TODO: Gracefully shut down HTTP server
	log.Info("HTTP server shutdown completed")

	// Close database connection
	if err := dbManager.Close(); err != nil {
		log.Error("Error closing database connection", model.NewField("error", err.Error()))
	} else {
		log.Info("Database connection closed successfully")
	}

	log.Info("Server has been gracefully shut down")
}
