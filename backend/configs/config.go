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
	config.BindEnv("db.host", "AUTH_GUARDIAN_DB_HOST")
	config.BindEnv("db.port", "AUTH_GUARDIAN_DB_PORT")
	config.BindEnv("db.user", "AUTH_GUARDIAN_DB_USER")
	config.BindEnv("db.password", "AUTH_GUARDIAN_DB_PASSWORD")
	config.BindEnv("db.name", "AUTH_GUARDIAN_DB_NAME")
	config.BindEnv("db.ssl_mode", "AUTH_GUARDIAN_DB_SSL_MODE")

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

	// Debug: Print all loaded config values
	fmt.Printf("DEBUG - DB Config: host=%s, port=%d, user=%s, name=%s, sslmode=%s\n",
		config.GetString("db.host"),
		config.GetInt("db.port"),
		config.GetString("db.user"),
		config.GetString("db.name"),
		config.GetString("db.ssl_mode"))

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
}
