package configs

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// LoadConfig loads all configuration files
func LoadConfig() *viper.Viper {
	config := viper.New()

	// Set defaults
	setDefaults(config)

	// Configure viper to handle environment variables
	config.AutomaticEnv()
	config.SetEnvPrefix("AUTH_GUARDIAN")

	// Replace dots with underscores in env vars
	config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind environment variables explicitly
	// Database environment variables
	config.BindEnv("db.host", "AUTH_GUARDIAN_DB_HOST")
	config.BindEnv("db.port", "AUTH_GUARDIAN_DB_PORT")
	config.BindEnv("db.user", "AUTH_GUARDIAN_DB_USER")
	config.BindEnv("db.password", "AUTH_GUARDIAN_DB_PASSWORD")
	config.BindEnv("db.name", "AUTH_GUARDIAN_DB_NAME")
	config.BindEnv("db.ssl_mode", "AUTH_GUARDIAN_DB_SSL_MODE")

	// Redis environment variables
	config.BindEnv("redis.host", "AUTH_GUARDIAN_REDIS_HOST")
	config.BindEnv("redis.port", "AUTH_GUARDIAN_REDIS_PORT")
	config.BindEnv("redis.password", "AUTH_GUARDIAN_REDIS_PASSWORD")
	config.BindEnv("redis.db", "AUTH_GUARDIAN_REDIS_DB")

	// Rate limiting environment variables
	config.BindEnv("rate_limit.auth.window", "AUTH_GUARDIAN_RATE_LIMIT_AUTH_WINDOW")
	config.BindEnv("rate_limit.auth.count", "AUTH_GUARDIAN_RATE_LIMIT_AUTH_COUNT")
	config.BindEnv("rate_limit.enabled", "AUTH_GUARDIAN_RATE_LIMIT_ENABLED")
	config.BindEnv("rate_limit.use_redis", "AUTH_GUARDIAN_RATE_LIMIT_USE_REDIS")

	// JWT environment variables
	config.BindEnv("jwt.accessTokenSecret", "AUTH_GUARDIAN_JWT_ACCESS_TOKEN_SECRET")
	config.BindEnv("jwt.refreshTokenSecret", "AUTH_GUARDIAN_JWT_REFRESH_TOKEN_SECRET")
	config.BindEnv("jwt.accessTokenExpiration", "AUTH_GUARDIAN_JWT_ACCESS_TOKEN_EXPIRATION")
	config.BindEnv("jwt.refreshTokenExpiration", "AUTH_GUARDIAN_JWT_REFRESH_TOKEN_EXPIRATION")
	config.BindEnv("jwt.issuer", "AUTH_GUARDIAN_JWT_ISSUER")

	// Server timeouts
	config.BindEnv("server.readTimeout", "AUTH_GUARDIAN_SERVER_READ_TIMEOUT")
	config.BindEnv("server.writeTimeout", "AUTH_GUARDIAN_SERVER_WRITE_TIMEOUT")
	config.BindEnv("server.idleTimeout", "AUTH_GUARDIAN_SERVER_IDLE_TIMEOUT")
	config.BindEnv("server.shutdownTimeout", "AUTH_GUARDIAN_SERVER_SHUTDOWN_TIMEOUT")

	// Sessions configuration
	config.BindEnv("sessions.maxPerUser", "AUTH_GUARDIAN_SESSIONS_MAX_PER_USER")
	config.BindEnv("sessions.cleanupInterval", "AUTH_GUARDIAN_SESSIONS_CLEANUP_INTERVAL")

	// Determine config path - use CONFIG_PATH env var or default to ./configs/
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./configs/"
	}

	fmt.Printf("Loading configs from: %s\n", configPath)

	// Load app.env
	loadConfigFile(config, "app", configPath)

	// Load db.env
	loadConfigFile(config, "db", configPath)

	// Load redis.env
	loadConfigFile(config, "redis", configPath)

	// Load jwt.env
	loadConfigFile(config, "jwt", configPath)

	// Load server.env
	loadConfigFile(config, "server", configPath)

	// Debug: Print all loaded config values
	fmt.Printf("DEBUG - DB Config: host=%s, port=%d, user=%s, name=%s, sslmode=%s\n",
		config.GetString("db.host"),
		config.GetInt("db.port"),
		config.GetString("db.user"),
		config.GetString("db.name"),
		config.GetString("db.ssl_mode"))

	fmt.Printf("DEBUG - Redis Config: host=%s, port=%s, password=%s, db=%d\n",
		config.GetString("redis.host"),
		config.GetString("redis.port"),
		maskPassword(config.GetString("redis.password")),
		config.GetInt("redis.db"))

	fmt.Printf("DEBUG - Rate Limit Config: enabled=%t, use_redis=%t, window=%s, count=%d\n",
		config.GetBool("rate_limit.enabled"),
		config.GetBool("rate_limit.use_redis"),
		config.GetString("rate_limit.auth.window"),
		config.GetInt("rate_limit.auth.count"))

	fmt.Printf("DEBUG - Server Config: readTimeout=%s, writeTimeout=%s, idleTimeout=%s\n",
		config.GetDuration("server.readTimeout"),
		config.GetDuration("server.writeTimeout"),
		config.GetDuration("server.idleTimeout"))

	return config
}

// loadConfigFile loads a specific config file
func loadConfigFile(v *viper.Viper, name string, path string) {
	v.SetConfigName(name)
	v.SetConfigType("env")
	v.AddConfigPath(path)

	err := v.MergeInConfig()
	if err != nil {
		fmt.Printf("Config file %s.env not found: %v\n", name, err)
	} else {
		fmt.Printf("Successfully loaded %s.env\n", name)
	}
}

// setDefaults sets default values for configuration
func setDefaults(v *viper.Viper) {
	// App defaults
	v.SetDefault("app.environment", "development")
	v.SetDefault("app.production", false)
	v.SetDefault("app.port", 8080)

	// DB defaults
	v.SetDefault("db.host", "postgres")
	v.SetDefault("db.port", 5432)
	v.SetDefault("db.ssl_mode", "disable")

	// Redis defaults
	v.SetDefault("redis.host", "redis")
	v.SetDefault("redis.port", "6379")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)

	// JWT defaults
	v.SetDefault("jwt.accessTokenSecret", "")
	v.SetDefault("jwt.refreshTokenSecret", "")
	v.SetDefault("jwt.accessTokenExpiration", "15m")
	v.SetDefault("jwt.refreshTokenExpiration", "7d")
	v.SetDefault("jwt.issuer", "auth-guardian-api")

	// Rate limiting defaults
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.use_redis", true)
	v.SetDefault("rate_limit.auth.window", "1m") // 1 minute window
	v.SetDefault("rate_limit.auth.count", 10)    // 10 requests per window

	// Server timeout defaults (in seconds)
	v.SetDefault("server.readTimeout", "15s")
	v.SetDefault("server.writeTimeout", "15s")
	v.SetDefault("server.idleTimeout", "60s")
	v.SetDefault("server.shutdownTimeout", "10s")

	// Session defaults
	v.SetDefault("sessions.maxPerUser", 5)
	v.SetDefault("sessions.cleanupInterval", "6h")
}

// maskPassword replaces password characters with * for logging
func maskPassword(password string) string {
	if len(password) == 0 {
		return "<empty>"
	}
	if len(password) <= 4 {
		return "****"
	}
	return password[0:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
