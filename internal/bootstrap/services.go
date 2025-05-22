package bootstrap

import (
	"context"
	"strconv"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/crypto"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/idgenerator"
	metricsAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/metrics"
	redisAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/redis"
	repoAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/repository"
	riskAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/risk"
	timeAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/time"
	tokenAdapter "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

// ServiceContainer holds all the application services
type ServiceContainer struct {
	UseCaseFactory *usecase.Factory
	TokenService   token.TokenService
}

// SetupServices initializes and configures all application services
func SetupServices(cfg *config.Config, db *gorm.DB, appLogger logger.Logger, auditLogger logger.AuditLogger) *ServiceContainer {
	// Add debug log
	appLogger.Info("Debug: Starting service initialization", nil)

	// Initialize time provider
	timeProvider := timeAdapter.NewRealTimeProvider()
	appLogger.Info("Debug: Time provider initialized", nil)

	// Initialize repositories
	userRepo := repoAdapter.NewGormUserRepository(db, appLogger, timeProvider)
	appLogger.Info("Debug: User repository initialized", nil)

	authSessionRepo := repoAdapter.NewGormAuthSessionRepository(db, appLogger, timeProvider)
	appLogger.Info("Debug: Auth session repository initialized", nil)

	// Initialize core services
	idGen := idgenerator.NewUUIDGenerator()
	appLogger.Info("Debug: ID generator initialized", nil)

	// Initialize password hasher with configuration values
	argon2Hasher := crypto.NewArgon2Hasher()
	if cfg.Auth.Argon2.Memory > 0 {
		argon2Params := crypto.Argon2Params{
			Memory:      cfg.Auth.Argon2.Memory,
			Iterations:  cfg.Auth.Argon2.Iterations,
			Parallelism: uint8(cfg.Auth.Argon2.Parallelism),
			SaltLength:  cfg.Auth.Argon2.SaltLength,
			KeyLength:   cfg.Auth.Argon2.KeyLength,
		}
		argon2Hasher = argon2Hasher.WithParams(argon2Params)
		appLogger.Info("Debug: Custom Argon2 parameters applied", map[string]any{
			"memory":      cfg.Auth.Argon2.Memory,
			"iterations":  cfg.Auth.Argon2.Iterations,
			"parallelism": cfg.Auth.Argon2.Parallelism,
		})
	}
	passwordHasher := argon2Hasher
	appLogger.Info("Debug: Password hasher initialized", nil)

	// Initialize token service
	jwtConfig := tokenAdapter.JWTConfig{
		AccessSecret:     cfg.JWT.AccessSecret,
		RefreshSecret:    cfg.JWT.RefreshSecret,
		AccessExpiresIn:  time.Duration(cfg.JWT.AccessTTL) * time.Minute,
		RefreshExpiresIn: time.Duration(cfg.JWT.RefreshTTL) * time.Hour,
	}

	// Initialize token store based on configuration
	var tokenStore token.TokenStore
	// Check if Redis is configured and available
	if cfg.Redis.Host != "" {
		// Create Redis configuration
		redisPort, _ := strconv.Atoi(cfg.Redis.Port)
		redisConfig := &redisAdapter.Config{
			Host:     cfg.Redis.Host,
			Port:     redisPort,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		}
		
		// Initialize Redis manager to get key-value store
		redisManager := redisAdapter.NewRedisManager(redisConfig, appLogger)
		ctx := context.Background()
		
		if err := redisManager.Initialize(ctx); err != nil {
			appLogger.Warn("Failed to connect to Redis for token store, falling back to in-memory store", map[string]any{"error": err.Error()})
			tokenStore = tokenAdapter.NewInMemoryTokenStore()
		} else {
			// Use Redis-based token store
			keyValueStore := redisManager.GetKeyValueStore()
			tokenStore = tokenAdapter.NewRedisTokenStore(keyValueStore)
			appLogger.Info("Using Redis-based token store", nil)
		}
	} else {
		// Using an in-memory token store if Redis is not configured
		tokenStore = tokenAdapter.NewInMemoryTokenStore()
		appLogger.Info("Redis not configured, using in-memory token store", nil)
	}
	appLogger.Info("Debug: Token store initialized", nil)

	tokenSvc := tokenAdapter.NewJWTTokenService(jwtConfig, timeProvider, tokenStore, appLogger)
	appLogger.Info("Debug: JWT token service initialized", nil)

	// Create factory options
	var factoryOptions []usecase.FactoryOption
	appLogger.Info("Debug: Factory options created", nil)

	if auditLogger != nil {
		factoryOptions = append(factoryOptions, usecase.WithAuditLogger(auditLogger))
		appLogger.Info("Debug: Audit logger added to factory options", nil)
	}

	// Initialize and add metrics recorder
	metricsFactory := metricsAdapter.NewFactory()
	var metricsType = metricsAdapter.TypePrometheus
	if cfg.Environment == "development" || cfg.Environment == "test" {
		metricsType = metricsAdapter.TypeMemory
	}
	metricsRecorder := metricsFactory.Create(metricsType, map[string]string{
		"namespace": "auth_guardian",
	})
	factoryOptions = append(factoryOptions, usecase.WithMetricsRecorder(metricsRecorder))
	appLogger.Info("Debug: Metrics recorder added to factory options", nil)

	// Initialize and add risk evaluator
	viperConfig := viper.New()
	viperConfig.Set("environment", cfg.Environment)
	viperConfig.Set("risk.known_ips", cfg.Security.KnownIPs)
	viperConfig.Set("risk.suspicious_ips", cfg.Security.SuspiciousIPs)
	viperConfig.Set("risk.suspicious_user_agents", cfg.Security.SuspiciousUserAgents)

	riskFactory := riskAdapter.NewFactory(viperConfig, appLogger, timeProvider)
	riskEvaluator := riskFactory.CreateRiskEvaluator()
	factoryOptions = append(factoryOptions, usecase.WithRiskEvaluator(riskEvaluator))
	appLogger.Info("Debug: Risk evaluator added to factory options", nil)

	// Set operation timeout
	operationTimeout := tport.Duration(time.Duration(cfg.Auth.OperationTimeoutSeconds) * time.Second)
	if operationTimeout <= 0 {
		operationTimeout = 30 * tport.Second // Default 30 seconds
	}
	factoryOptions = append(factoryOptions, usecase.WithOperationTimeout(operationTimeout))
	appLogger.Info("Debug: Operation timeout added to factory options", nil)

	// Initialize use case factory
	maxSessionsPerUser := int64(cfg.Auth.MaxSessionsPerUser)
	appLogger.Info("Debug: About to create use case factory", map[string]any{
		"maxSessionsPerUser": maxSessionsPerUser,
	})

	// Wrap factory creation in a recover to catch panics
	var useCaseFactory *usecase.Factory
	func() {
		defer func() {
			if r := recover(); r != nil {
				appLogger.Error("PANIC in factory creation", map[string]any{"error": r})
			}
		}()

		useCaseFactory = usecase.NewFactory(
			userRepo,
			authSessionRepo,
			tokenSvc,
			passwordHasher,
			idGen,
			timeProvider,
			appLogger,
			maxSessionsPerUser,
			factoryOptions...,
		)
	}()

	if useCaseFactory == nil {
		appLogger.Error("Use case factory creation failed", nil)
	} else {
		appLogger.Info("Debug: Use case factory created successfully", nil)
	}

	appLogger.Info("Debug: Service initialization completed", nil)

	return &ServiceContainer{
		UseCaseFactory: useCaseFactory,
		TokenService:   tokenSvc,
	}
}
