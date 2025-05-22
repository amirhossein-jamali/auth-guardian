package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// Load loads the configuration from the specified path and environment
// This is the main entry point used by the bootstrap package
func Load(configPath, env string) (*Config, error) {
	// Load .env file if it exists
	loadDotEnvFiles(env)

	// Initialize viper
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure viper for config file
	v.SetConfigName(env)        // Name of config file (without extension)
	v.SetConfigType("yaml")     // YAML format
	v.AddConfigPath(configPath) // Look for config in the specified directory

	// Read the config file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Configure environment variables
	v.SetEnvPrefix("AUTH_GUARDIAN") // Prefix for environment variables
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv() // Read environment variables that match

	// Explicitly bind sensitive environment variables
	if err := bindSensitiveEnvVars(v); err != nil {
		return nil, err
	}

	// Unmarshal config into struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	// Store the current environment in the config
	config.Environment = env

	// Validate config
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// loadDotEnvFiles loads environment variables from .env files
func loadDotEnvFiles(env string) {
	if env == "" {
		env = os.Getenv("APP_ENV")
		if env == "" {
			env = "development"
		}
	}

	// Try to load environment-specific .env file
	envFile := fmt.Sprintf(".env.%s", env)
	if _, err := os.Stat(envFile); err == nil {
		if err := godotenv.Load(envFile); err != nil {
			fmt.Printf("Warning: Error loading %s file: %v\n", envFile, err)
		} else {
			fmt.Printf("Loaded environment variables from %s\n", envFile)
		}
	}

	// Always try to load default .env file as a fallback
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			fmt.Printf("Warning: Error loading .env file: %v\n", err)
		} else {
			fmt.Printf("Loaded environment variables from .env\n")
		}
	}
}

// setDefaults sets default values for configuration parameters
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.readTimeout", 5)
	v.SetDefault("server.writeTimeout", 10)
	v.SetDefault("server.idleTimeout", 120)

	// Database defaults
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", "5432")
	v.SetDefault("database.sslMode", "disable")
	v.SetDefault("database.maxOpenConns", 25)
	v.SetDefault("database.maxIdleConns", 5)
	v.SetDefault("database.connMaxLifetime", 30)

	// JWT defaults
	v.SetDefault("jwt.accessTTL", 15)
	v.SetDefault("jwt.refreshTTL", 24)
	v.SetDefault("jwt.issuer", "auth-guardian")
	v.SetDefault("jwt.audience", "auth-guardian-api")
	v.SetDefault("jwt.maxConcurrent", 5)
	v.SetDefault("jwt.allowedClockSkew", 30)

	// Logger defaults
	v.SetDefault("logger.level", "info")
	v.SetDefault("logger.format", "json")
	v.SetDefault("logger.output", "stdout")
	v.SetDefault("logger.timeFormat", time.RFC3339)
	v.SetDefault("logger.callerInfo", true)
	v.SetDefault("logger.enableAudit", false)

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", "6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.keyPrefix", "ag:")

	// Auth defaults
	v.SetDefault("auth.accessTokenTTL", 15)
	v.SetDefault("auth.refreshTokenTTL", 24)
	v.SetDefault("auth.maxSessionsPerUser", 5)
	v.SetDefault("auth.sessionInactivityTTL", 30)
}

// bindSensitiveEnvVars explicitly binds sensitive environment variables
func bindSensitiveEnvVars(v *viper.Viper) error {
	// Database sensitive information
	if err := v.BindEnv("database.username", "AUTH_GUARDIAN_DB_USERNAME"); err != nil {
		return fmt.Errorf("failed to bind database.username env var: %w", err)
	}
	if err := v.BindEnv("database.password", "AUTH_GUARDIAN_DB_PASSWORD"); err != nil {
		return fmt.Errorf("failed to bind database.password env var: %w", err)
	}
	if err := v.BindEnv("database.database", "AUTH_GUARDIAN_DB_NAME"); err != nil {
		return fmt.Errorf("failed to bind database.database env var: %w", err)
	}
	if err := v.BindEnv("database.host", "AUTH_GUARDIAN_DB_HOST"); err != nil {
		return fmt.Errorf("failed to bind database.host env var: %w", err)
	}

	// JWT secrets
	if err := v.BindEnv("jwt.accessSecret", "AUTH_GUARDIAN_JWT_ACCESS_SECRET"); err != nil {
		return fmt.Errorf("failed to bind jwt.accessSecret env var: %w", err)
	}
	if err := v.BindEnv("jwt.refreshSecret", "AUTH_GUARDIAN_JWT_REFRESH_SECRET"); err != nil {
		return fmt.Errorf("failed to bind jwt.refreshSecret env var: %w", err)
	}

	// Redis configuration
	if err := v.BindEnv("redis.host", "AUTH_GUARDIAN_REDIS_HOST"); err != nil {
		return fmt.Errorf("failed to bind redis.host env var: %w", err)
	}
	if err := v.BindEnv("redis.password", "AUTH_GUARDIAN_REDIS_PASSWORD"); err != nil {
		return fmt.Errorf("failed to bind redis.password env var: %w", err)
	}
	if err := v.BindEnv("redis.keyPrefix", "AUTH_GUARDIAN_REDIS_KEY_PREFIX"); err != nil {
		return fmt.Errorf("failed to bind redis.keyPrefix env var: %w", err)
	}

	// Auth secrets
	if err := v.BindEnv("auth.accessTokenSecret", "AUTH_GUARDIAN_ACCESS_TOKEN_SECRET"); err != nil {
		return fmt.Errorf("failed to bind auth.accessTokenSecret env var: %w", err)
	}
	if err := v.BindEnv("auth.refreshTokenSecret", "AUTH_GUARDIAN_REFRESH_TOKEN_SECRET"); err != nil {
		return fmt.Errorf("failed to bind auth.refreshTokenSecret env var: %w", err)
	}

	return nil
}

// validateConfig performs validation on the configuration values
func validateConfig(config *Config) error {
	// Validate database configuration in non-test environments
	env := os.Getenv("APP_ENV")
	if env != "test" {
		if config.Database.Username == "" {
			return fmt.Errorf("database username is required")
		}

		if config.Database.Database == "" {
			return fmt.Errorf("database name is required")
		}
	}

	// Validate JWT configuration
	if config.JWT.AccessSecret == "" {
		return fmt.Errorf("JWT access secret is required")
	}

	if config.JWT.RefreshSecret == "" {
		return fmt.Errorf("JWT refresh secret is required")
	}

	// Validate Auth configuration
	if config.Auth.AccessTokenSecret == "" {
		// Use JWT secrets as fallback
		config.Auth.AccessTokenSecret = config.JWT.AccessSecret
	}

	if config.Auth.RefreshTokenSecret == "" {
		// Use JWT secrets as fallback
		config.Auth.RefreshTokenSecret = config.JWT.RefreshSecret
	}

	return nil
}

// LoadConfig loads and initializes the application configuration
// This is the main entry point for loading configuration
func LoadConfig() (*Config, error) {
	// Determine environment
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	// Find config file
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		// Default to configs directory
		configPath = "configs"
	}

	// Use the config loader
	return Load(configPath, env)
}
