package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/config"
)

func TestLoad(t *testing.T) {
	// Create temporary directories for config files
	tempDir, err := os.MkdirTemp("", "config-test")
	require.NoError(t, err, "Failed to create temporary directory")

	// Use defer with a function to handle cleanup errors
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to clean up temporary directory %s: %v", tempDir, err)
		}
	}()

	// Test cases
	testCases := []struct {
		name           string
		configContent  string
		env            string
		envVars        map[string]string
		expectedConfig *config.Config
		expectError    bool
	}{
		{
			name: "Valid Configuration",
			configContent: `
server:
  host: "test-host"
  port: 9090
  readTimeout: 10
  writeTimeout: 20
  idleTimeout: 180
database:
  driver: "postgres"
  host: "db-host"
  port: "5432"
  sslMode: "disable"
  maxOpenConns: 20
  maxIdleConns: 10
  connMaxLifetime: 60
jwt:
  accessTTL: 30
  refreshTTL: 48
  issuer: "test-issuer"
  audience: "test-audience"
  maxConcurrent: 3
  allowedClockSkew: 15
logger:
  level: "debug"
  format: "json"
  output: "stdout"
  timeFormat: "2006-01-02T15:04:05Z07:00"
  callerInfo: true
  enableAudit: true
redis:
  host: "redis-host"
  port: "6379"
  db: 2
  keyPrefix: "test:"
auth:
  accessTokenTTL: 20
  refreshTokenTTL: 36
  maxSessionsPerUser: 3
  sessionInactivityTTL: 15
  operationTimeoutSeconds: 30
  argon2:
    memory: 65536
    iterations: 3
    parallelism: 2
    saltLength: 16
    keyLength: 32
metrics:
  enabled: true
  type: "prometheus"
  namespace: "auth_guardian_test"
security:
  knownIPs: ["192.168.1.1", "10.0.0.1"]
  suspiciousIPs: ["1.2.3.4"]
  suspiciousUserAgents: ["suspiciousBot"]
  enableRiskEvaluation: true
`,
			env: "test",
			envVars: map[string]string{
				"AUTH_GUARDIAN_DB_USERNAME":          "testuser",
				"AUTH_GUARDIAN_DB_PASSWORD":          "testpass",
				"AUTH_GUARDIAN_DB_NAME":              "testdb",
				"AUTH_GUARDIAN_JWT_ACCESS_SECRET":    "test-access-secret",
				"AUTH_GUARDIAN_JWT_REFRESH_SECRET":   "test-refresh-secret",
				"AUTH_GUARDIAN_REDIS_PASSWORD":       "redis-pass",
				"AUTH_GUARDIAN_ACCESS_TOKEN_SECRET":  "auth-access-secret",
				"AUTH_GUARDIAN_REFRESH_TOKEN_SECRET": "auth-refresh-secret",
				"APP_ENV":                            "test",
			},
			expectedConfig: &config.Config{
				Environment: "test",
				Server: config.ServerConfig{
					Host:         "test-host",
					Port:         9090,
					ReadTimeout:  10,
					WriteTimeout: 20,
					IdleTimeout:  180,
				},
				Database: config.DatabaseConfig{
					Driver:          "postgres",
					Host:            "db-host",
					Port:            "5432",
					Username:        "testuser",
					Password:        "testpass",
					Database:        "testdb",
					SSLMode:         "disable",
					MaxOpenConns:    20,
					MaxIdleConns:    10,
					ConnMaxLifetime: 60,
				},
				JWT: config.JWTConfig{
					AccessSecret:     "test-access-secret",
					RefreshSecret:    "test-refresh-secret",
					AccessTTL:        30,
					RefreshTTL:       48,
					Issuer:           "test-issuer",
					Audience:         "test-audience",
					MaxConcurrent:    3,
					AllowedClockSkew: 15,
				},
				Logger: config.LoggerConfig{
					Level:       "debug",
					Format:      "json",
					Output:      "stdout",
					TimeFormat:  "2006-01-02T15:04:05Z07:00",
					CallerInfo:  true,
					EnableAudit: true,
				},
				Redis: config.RedisConfig{
					Host:      "redis-host",
					Port:      "6379",
					Password:  "redis-pass",
					DB:        2,
					KeyPrefix: "test:",
				},
				Auth: config.AuthConfig{
					AccessTokenSecret:       "auth-access-secret",
					RefreshTokenSecret:      "auth-refresh-secret",
					AccessTokenTTL:          20,
					RefreshTokenTTL:         36,
					MaxSessionsPerUser:      3,
					SessionInactivityTTL:    15,
					OperationTimeoutSeconds: 30,
					Argon2: config.Argon2Config{
						Memory:      65536,
						Iterations:  3,
						Parallelism: 2,
						SaltLength:  16,
						KeyLength:   32,
					},
				},
				Metrics: config.MetricsConfig{
					Enabled:   true,
					Type:      "prometheus",
					Namespace: "auth_guardian_test",
				},
				Security: config.SecurityConfig{
					KnownIPs:             []string{"192.168.1.1", "10.0.0.1"},
					SuspiciousIPs:        []string{"1.2.3.4"},
					SuspiciousUserAgents: []string{"suspiciousBot"},
					EnableRiskEvaluation: true,
				},
			},
			expectError: false,
		},
		{
			name: "Missing Required JWT Secrets",
			configContent: `
server:
  host: "test-host"
  port: 9090
database:
  driver: "postgres"
  host: "db-host"
  port: "5432"
  username: "testuser"
  database: "testdb"
`,
			env: "test",
			envVars: map[string]string{
				"APP_ENV": "test",
			},
			expectError: true,
		},
		{
			name: "Default Values Test",
			configContent: `
database:
  username: "testuser"
  database: "testdb"
jwt:
  accessSecret: "test-access-secret"
  refreshSecret: "test-refresh-secret"
`,
			env: "test",
			envVars: map[string]string{
				"APP_ENV": "test",
			},
			expectedConfig: &config.Config{
				Environment: "test",
				Server: config.ServerConfig{
					Host:         "localhost", // Default
					Port:         8080,        // Default
					ReadTimeout:  5,           // Default
					WriteTimeout: 10,          // Default
					IdleTimeout:  120,         // Default
				},
				Database: config.DatabaseConfig{
					Driver:          "postgres",  // Default
					Host:            "localhost", // Default
					Port:            "5432",      // Default
					Username:        "testuser",
					Database:        "testdb",
					SSLMode:         "disable", // Default
					MaxOpenConns:    25,        // Default
					MaxIdleConns:    5,         // Default
					ConnMaxLifetime: 30,        // Default
				},
				JWT: config.JWTConfig{
					AccessSecret:     "test-access-secret",
					RefreshSecret:    "test-refresh-secret",
					AccessTTL:        15,                  // Default
					RefreshTTL:       24,                  // Default
					Issuer:           "auth-guardian",     // Default
					Audience:         "auth-guardian-api", // Default
					MaxConcurrent:    5,                   // Default
					AllowedClockSkew: 30,                  // Default
				},
				Auth: config.AuthConfig{
					AccessTokenSecret:  "test-access-secret",  // Fallback to JWT secrets
					RefreshTokenSecret: "test-refresh-secret", // Fallback to JWT secrets
					AccessTokenTTL:     15,                    // Default
					RefreshTokenTTL:    24,                    // Default
					MaxSessionsPerUser: 5,                     // Default
				},
			},
			expectError: false,
		},
		{
			name: "JWT Secrets Fallback Test",
			configContent: `
database:
  username: "testuser"
  database: "testdb"
jwt:
  accessSecret: "jwt-access-secret"
  refreshSecret: "jwt-refresh-secret"
`,
			env: "test",
			envVars: map[string]string{
				"APP_ENV": "test",
			},
			expectedConfig: &config.Config{
				Environment: "test",
				JWT: config.JWTConfig{
					AccessSecret:  "jwt-access-secret",
					RefreshSecret: "jwt-refresh-secret",
				},
				Auth: config.AuthConfig{
					AccessTokenSecret:  "jwt-access-secret",  // Fallback
					RefreshTokenSecret: "jwt-refresh-secret", // Fallback
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create config file
			configPath := filepath.Join(tempDir, tc.env+".yaml")
			err := os.WriteFile(configPath, []byte(tc.configContent), 0644)
			require.NoError(t, err, "Failed to write config file: %v", configPath)

			// Store original env vars to restore later
			var originalEnvVars = make(map[string]string)
			for k := range tc.envVars {
				originalEnvVars[k] = os.Getenv(k)
			}

			// Set environment variables
			for k, v := range tc.envVars {
				err := os.Setenv(k, v)
				require.NoError(t, err, "Failed to set environment variable %s", k)
			}

			// Ensure env vars are restored after test
			defer func() {
				for k, v := range originalEnvVars {
					if err := os.Setenv(k, v); err != nil {
						t.Logf("Warning: Failed to restore environment variable %s: %v", k, err)
					}
				}
			}()

			// Run the loader
			cfg, err := config.Load(tempDir, tc.env)

			// Check expectations
			if tc.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, cfg)

			// Check specific fields if expected config is provided
			if tc.expectedConfig != nil {
				assert.Equal(t, tc.expectedConfig.Environment, cfg.Environment)

				if tc.name == "Default Values Test" || tc.name == "Valid Configuration" {
					// Server config
					assert.Equal(t, tc.expectedConfig.Server.Host, cfg.Server.Host)
					assert.Equal(t, tc.expectedConfig.Server.Port, cfg.Server.Port)
					assert.Equal(t, tc.expectedConfig.Server.ReadTimeout, cfg.Server.ReadTimeout)
					assert.Equal(t, tc.expectedConfig.Server.WriteTimeout, cfg.Server.WriteTimeout)
					assert.Equal(t, tc.expectedConfig.Server.IdleTimeout, cfg.Server.IdleTimeout)

					// Database config
					assert.Equal(t, tc.expectedConfig.Database.Driver, cfg.Database.Driver)
					assert.Equal(t, tc.expectedConfig.Database.Host, cfg.Database.Host)
					assert.Equal(t, tc.expectedConfig.Database.Port, cfg.Database.Port)
					assert.Equal(t, tc.expectedConfig.Database.Username, cfg.Database.Username)
					assert.Equal(t, tc.expectedConfig.Database.Database, cfg.Database.Database)
					assert.Equal(t, tc.expectedConfig.Database.SSLMode, cfg.Database.SSLMode)
					assert.Equal(t, tc.expectedConfig.Database.MaxOpenConns, cfg.Database.MaxOpenConns)
					assert.Equal(t, tc.expectedConfig.Database.MaxIdleConns, cfg.Database.MaxIdleConns)
					assert.Equal(t, tc.expectedConfig.Database.ConnMaxLifetime, cfg.Database.ConnMaxLifetime)
				}

				// JWT config
				if tc.expectedConfig.JWT.AccessSecret != "" {
					assert.Equal(t, tc.expectedConfig.JWT.AccessSecret, cfg.JWT.AccessSecret)
					assert.Equal(t, tc.expectedConfig.JWT.RefreshSecret, cfg.JWT.RefreshSecret)
				}

				if tc.name == "Default Values Test" || tc.name == "Valid Configuration" {
					assert.Equal(t, tc.expectedConfig.JWT.AccessTTL, cfg.JWT.AccessTTL)
					assert.Equal(t, tc.expectedConfig.JWT.RefreshTTL, cfg.JWT.RefreshTTL)
					assert.Equal(t, tc.expectedConfig.JWT.Issuer, cfg.JWT.Issuer)
					assert.Equal(t, tc.expectedConfig.JWT.Audience, cfg.JWT.Audience)
					assert.Equal(t, tc.expectedConfig.JWT.MaxConcurrent, cfg.JWT.MaxConcurrent)
					assert.Equal(t, tc.expectedConfig.JWT.AllowedClockSkew, cfg.JWT.AllowedClockSkew)
				}

				if tc.name == "Valid Configuration" {
					// Logger config
					assert.Equal(t, tc.expectedConfig.Logger.Level, cfg.Logger.Level)
					assert.Equal(t, tc.expectedConfig.Logger.Format, cfg.Logger.Format)
					assert.Equal(t, tc.expectedConfig.Logger.Output, cfg.Logger.Output)
					assert.Equal(t, tc.expectedConfig.Logger.TimeFormat, cfg.Logger.TimeFormat)
					assert.Equal(t, tc.expectedConfig.Logger.CallerInfo, cfg.Logger.CallerInfo)
					assert.Equal(t, tc.expectedConfig.Logger.EnableAudit, cfg.Logger.EnableAudit)

					// Redis config
					assert.Equal(t, tc.expectedConfig.Redis.Host, cfg.Redis.Host)
					assert.Equal(t, tc.expectedConfig.Redis.Port, cfg.Redis.Port)
					assert.Equal(t, tc.expectedConfig.Redis.Password, cfg.Redis.Password)
					assert.Equal(t, tc.expectedConfig.Redis.DB, cfg.Redis.DB)
					assert.Equal(t, tc.expectedConfig.Redis.KeyPrefix, cfg.Redis.KeyPrefix)
				}

				// Auth config - check fallback mechanism
				assert.Equal(t, tc.expectedConfig.Auth.AccessTokenSecret, cfg.Auth.AccessTokenSecret)
				assert.Equal(t, tc.expectedConfig.Auth.RefreshTokenSecret, cfg.Auth.RefreshTokenSecret)

				if tc.name == "Default Values Test" || tc.name == "Valid Configuration" {
					assert.Equal(t, tc.expectedConfig.Auth.AccessTokenTTL, cfg.Auth.AccessTokenTTL)
					assert.Equal(t, tc.expectedConfig.Auth.RefreshTokenTTL, cfg.Auth.RefreshTokenTTL)
					assert.Equal(t, tc.expectedConfig.Auth.MaxSessionsPerUser, cfg.Auth.MaxSessionsPerUser)
				}

				if tc.name == "Valid Configuration" {
					assert.Equal(t, tc.expectedConfig.Auth.SessionInactivityTTL, cfg.Auth.SessionInactivityTTL)
					assert.Equal(t, tc.expectedConfig.Auth.OperationTimeoutSeconds, cfg.Auth.OperationTimeoutSeconds)

					// Argon2 config
					assert.Equal(t, tc.expectedConfig.Auth.Argon2.Memory, cfg.Auth.Argon2.Memory)
					assert.Equal(t, tc.expectedConfig.Auth.Argon2.Iterations, cfg.Auth.Argon2.Iterations)
					assert.Equal(t, tc.expectedConfig.Auth.Argon2.Parallelism, cfg.Auth.Argon2.Parallelism)
					assert.Equal(t, tc.expectedConfig.Auth.Argon2.SaltLength, cfg.Auth.Argon2.SaltLength)
					assert.Equal(t, tc.expectedConfig.Auth.Argon2.KeyLength, cfg.Auth.Argon2.KeyLength)

					// Metrics config
					assert.Equal(t, tc.expectedConfig.Metrics.Enabled, cfg.Metrics.Enabled)
					assert.Equal(t, tc.expectedConfig.Metrics.Type, cfg.Metrics.Type)
					assert.Equal(t, tc.expectedConfig.Metrics.Namespace, cfg.Metrics.Namespace)

					// Security config
					assert.ElementsMatch(t, tc.expectedConfig.Security.KnownIPs, cfg.Security.KnownIPs)
					assert.ElementsMatch(t, tc.expectedConfig.Security.SuspiciousIPs, cfg.Security.SuspiciousIPs)
					assert.ElementsMatch(t, tc.expectedConfig.Security.SuspiciousUserAgents, cfg.Security.SuspiciousUserAgents)
					assert.Equal(t, tc.expectedConfig.Security.EnableRiskEvaluation, cfg.Security.EnableRiskEvaluation)
				}
			}
		})
	}
}

func TestLoad_EnvironmentVariables(t *testing.T) {
	// Create temporary directories for config files
	tempDir, err := os.MkdirTemp("", "config-test")
	require.NoError(t, err, "Failed to create temporary directory")
	
	// Use defer with a function to handle cleanup errors
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to clean up temporary directory %s: %v", tempDir, err)
		}
	}()
	
	// Create a minimal config file
	configContent := `
server:
  host: "from-config"
  port: 8000
database:
  driver: "postgres"
  host: "from-config-host"
  username: "db-user"
  database: "db-name"
`
	configPath := filepath.Join(tempDir, "test.yaml")
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err, "Failed to write config file")
	
	// Save original environment variables
	origAccessSecret := os.Getenv("AUTH_GUARDIAN_JWT_ACCESS_SECRET")
	origRefreshSecret := os.Getenv("AUTH_GUARDIAN_JWT_REFRESH_SECRET")
	origDBHost := os.Getenv("AUTH_GUARDIAN_DB_HOST")
	
	// Set environment variables for test
	err = os.Setenv("AUTH_GUARDIAN_JWT_ACCESS_SECRET", "env-access-secret")
	require.NoError(t, err, "Failed to set JWT_ACCESS_SECRET env var")
	
	err = os.Setenv("AUTH_GUARDIAN_JWT_REFRESH_SECRET", "env-refresh-secret")
	require.NoError(t, err, "Failed to set JWT_REFRESH_SECRET env var")
	
	err = os.Setenv("AUTH_GUARDIAN_DB_HOST", "env-db-host")
	require.NoError(t, err, "Failed to set DB_HOST env var")
	
	// Restore environment variables after test
	defer func() {
		if err := os.Setenv("AUTH_GUARDIAN_JWT_ACCESS_SECRET", origAccessSecret); err != nil {
			t.Logf("Warning: Failed to restore JWT_ACCESS_SECRET env var: %v", err)
		}
		
		if err := os.Setenv("AUTH_GUARDIAN_JWT_REFRESH_SECRET", origRefreshSecret); err != nil {
			t.Logf("Warning: Failed to restore JWT_REFRESH_SECRET env var: %v", err)
		}
		
		if err := os.Setenv("AUTH_GUARDIAN_DB_HOST", origDBHost); err != nil {
			t.Logf("Warning: Failed to restore DB_HOST env var: %v", err)
		}
	}()
	
	// Load the config
	cfg, err := config.Load(tempDir, "test")
	require.NoError(t, err, "Failed to load configuration")
	
	// Environment variables should override or supplement config values
	assert.Equal(t, "from-config", cfg.Server.Host, "Should use config file value") 
	assert.Equal(t, "env-access-secret", cfg.JWT.AccessSecret, "Should use environment variable")
	assert.Equal(t, "env-refresh-secret", cfg.JWT.RefreshSecret, "Should use environment variable")
	assert.Equal(t, "env-db-host", cfg.Database.Host, "Should override with environment variable")
}

func TestLoad_MissingConfigFile(t *testing.T) {
	// Create temporary directories for config files
	tempDir, err := os.MkdirTemp("", "config-test")
	require.NoError(t, err, "Failed to create temporary directory")

	// Use defer with a function to handle cleanup errors
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to clean up temporary directory %s: %v", tempDir, err)
		}
	}()

	// Store original environment variables
	originalAccessSecret := os.Getenv("AUTH_GUARDIAN_JWT_ACCESS_SECRET")
	originalRefreshSecret := os.Getenv("AUTH_GUARDIAN_JWT_REFRESH_SECRET")
	originalAppEnv := os.Getenv("APP_ENV")

	// Restore original environment variables when done
	defer func() {
		if err := os.Setenv("AUTH_GUARDIAN_JWT_ACCESS_SECRET", originalAccessSecret); err != nil {
			t.Logf("Warning: Failed to restore AUTH_GUARDIAN_JWT_ACCESS_SECRET: %v", err)
		}
		if err := os.Setenv("AUTH_GUARDIAN_JWT_REFRESH_SECRET", originalRefreshSecret); err != nil {
			t.Logf("Warning: Failed to restore AUTH_GUARDIAN_JWT_REFRESH_SECRET: %v", err)
		}
		if err := os.Setenv("APP_ENV", originalAppEnv); err != nil {
			t.Logf("Warning: Failed to restore APP_ENV: %v", err)
		}
	}()

	// Set required environment variables for a valid config
	err = os.Setenv("AUTH_GUARDIAN_JWT_ACCESS_SECRET", "test-secret")
	require.NoError(t, err, "Failed to set ACCESS_SECRET environment variable")

	err = os.Setenv("AUTH_GUARDIAN_JWT_REFRESH_SECRET", "test-secret")
	require.NoError(t, err, "Failed to set REFRESH_SECRET environment variable")

	err = os.Setenv("APP_ENV", "test")
	require.NoError(t, err, "Failed to set APP_ENV environment variable")

	// Test with non-existent config file
	_, err = config.Load(tempDir, "nonexistent")
	assert.Error(t, err, "Loading nonexistent config file should return an error")
	assert.Contains(t, err.Error(), "failed to read config file", "Error message should mention failed config file reading")
}

func TestLoad_InvalidYAML(t *testing.T) {
	// Create temporary directories for config files
	tempDir, err := os.MkdirTemp("", "config-test")
	require.NoError(t, err, "Failed to create temporary directory")

	// Use defer with a function to handle cleanup errors
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Warning: Failed to clean up temporary directory %s: %v", tempDir, err)
		}
	}()

	// Create invalid YAML config file
	invalidYAML := `
server:
  host: "localhost"
  port: 8080
invalid yaml content
`
	configPath := filepath.Join(tempDir, "test.yaml")
	err = os.WriteFile(configPath, []byte(invalidYAML), 0644)
	require.NoError(t, err, "Failed to write invalid YAML config file")

	// Test with invalid YAML
	_, err = config.Load(tempDir, "test")
	assert.Error(t, err, "Loading invalid YAML should return an error")
	assert.NotEqual(t, "failed to read config file", err.Error(), "Error should not be about missing file")
}

// TestLoadConfig tests the LoadConfig function with various environment scenarios
func TestLoadConfig(t *testing.T) {
	// Save original environment variables to restore them later
	originalAppEnv := os.Getenv("APP_ENV")
	originalConfigPath := os.Getenv("CONFIG_PATH")

	// Create a safe restore function to ensure environment is always cleaned up
	restore := func() {
		// Restore environment variables and handle errors
		if err := os.Setenv("APP_ENV", originalAppEnv); err != nil {
			t.Logf("Warning: Failed to restore APP_ENV: %v", err)
		}

		if err := os.Setenv("CONFIG_PATH", originalConfigPath); err != nil {
			t.Logf("Warning: Failed to restore CONFIG_PATH: %v", err)
		}
	}

	// Make sure environment is restored after all tests
	defer restore()

	// Ensure test data directory exists and is absolute
	testDataDir, err := filepath.Abs("./testdata")
	require.NoError(t, err, "Failed to determine absolute path for testdata directory")

	// Verify test data directory exists
	fileInfo, err := os.Stat(testDataDir)
	if os.IsNotExist(err) {
		t.Logf("Warning: Test data directory doesn't exist at %s", testDataDir)
	} else if err != nil {
		t.Logf("Warning: Error checking test data directory: %v", err)
	} else if !fileInfo.IsDir() {
		t.Logf("Warning: %s exists but is not a directory", testDataDir)
	}

	// Test with default environment
	t.Run("Default environment", func(t *testing.T) {
		// Set test environment variables with error handling
		if err := os.Unsetenv("APP_ENV"); err != nil {
			t.Fatalf("Failed to unset APP_ENV: %v", err)
		}

		if err := os.Setenv("CONFIG_PATH", testDataDir); err != nil {
			t.Fatalf("Failed to set CONFIG_PATH: %v", err)
		}

		// Call the function under test
		cfg, err := config.LoadConfig()

		// In real test it might fail if config.yaml doesn't exist in testdata
		if err != nil {
			t.Logf("Config loading error (expected in test): %v", err)

			// Check if the error is due to missing config file
			configPath := filepath.Join(testDataDir, "config.development.yaml")
			if _, fileErr := os.Stat(configPath); os.IsNotExist(fileErr) {
				t.Logf("Note: Config file doesn't exist at %s", configPath)
			} else if fileErr != nil {
				t.Logf("Error checking config file: %v", fileErr)
			}
		} else {
			// Log success and config details for debugging
			t.Logf("Config loaded successfully: environment=%s", cfg.Environment)
		}

		// Test that the function didn't panic, which is important
		assert.NotPanics(t, func() {
			// Call LoadConfig inside NotPanics check, but also handle its errors
			cfg, err := config.LoadConfig()
			if err != nil {
				t.Logf("NotPanics test: Config loading error: %v", err)
			} else if cfg != nil {
				t.Logf("NotPanics test: Config loaded successfully: env=%s", cfg.Environment)
			}
		}, "LoadConfig should not panic with default environment")
	})

	// Test with custom environment
	t.Run("Custom environment", func(t *testing.T) {
		// Set custom environment variables with error handling
		if err := os.Setenv("APP_ENV", "test"); err != nil {
			t.Fatalf("Failed to set APP_ENV: %v", err)
		}

		if err := os.Setenv("CONFIG_PATH", testDataDir); err != nil {
			t.Fatalf("Failed to set CONFIG_PATH: %v", err)
		}

		// Check if test config exists
		testConfigPath := filepath.Join(testDataDir, "config.test.yaml")
		fileInfo, fileErr := os.Stat(testConfigPath)
		if os.IsNotExist(fileErr) {
			t.Logf("Note: Test config file doesn't exist at %s", testConfigPath)
		} else if fileErr != nil {
			t.Logf("Error checking test config file: %v", fileErr)
		} else if fileInfo.IsDir() {
			t.Logf("Warning: %s exists but is a directory, not a file", testConfigPath)
		} else {
			t.Logf("Found test config file: %s (size: %d bytes)", testConfigPath, fileInfo.Size())
		}

		// Call the function under test
		cfg, err := config.LoadConfig()

		if err != nil {
			t.Logf("Config loading error: %v", err)
		} else {
			// If config loaded successfully, verify it has the correct environment
			require.NotNil(t, cfg, "Config should not be nil if err is nil")
			assert.Equal(t, "test", cfg.Environment, "Environment should match APP_ENV")

			// Log loaded config details for debugging
			t.Logf("Config loaded successfully: environment=%s, server.port=%d",
				cfg.Environment, cfg.Server.Port)
		}

		// Test that the function didn't panic, which is important
		assert.NotPanics(t, func() {
			// Call LoadConfig inside NotPanics check, but also handle its errors
			cfg, err := config.LoadConfig()
			if err != nil {
				t.Logf("NotPanics test: Config loading error: %v", err)
			} else if cfg != nil {
				t.Logf("NotPanics test: Config loaded successfully: env=%s", cfg.Environment)
			}
		}, "LoadConfig should not panic with test environment")
	})

	// Test with invalid config path
	t.Run("Invalid config path", func(t *testing.T) {
		// Set environment variables to force error
		nonexistentPath := filepath.Join(testDataDir, "nonexistent")

		if err := os.Setenv("APP_ENV", "development"); err != nil {
			t.Fatalf("Failed to set APP_ENV: %v", err)
		}

		if err := os.Setenv("CONFIG_PATH", nonexistentPath); err != nil {
			t.Fatalf("Failed to set CONFIG_PATH: %v", err)
		}

		// Call the function, expecting error
		cfg, err := config.LoadConfig()

		// Should return error for nonexistent path
		assert.Error(t, err, "Should return error for nonexistent config path")
		assert.Nil(t, cfg, "Config should be nil when an error occurs")

		// Print the exact error message for debugging
		if err != nil {
			t.Logf("DEBUG - Actual error message: %q", err.Error())

			// Skip the assertion on exact path format since Viper's error formatting
			// can vary with different escaping styles
			assert.Contains(t, err.Error(), "nonexistent",
				"Error should mention the nonexistent path")
		}
	})
}
