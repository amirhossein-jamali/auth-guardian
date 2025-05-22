package config

// Config represents the application configuration
type Config struct {
	Server      ServerConfig   `mapstructure:"server"`
	Database    DatabaseConfig `mapstructure:"database"`
	JWT         JWTConfig      `mapstructure:"jwt"`
	Logger      LoggerConfig   `mapstructure:"logger"`
	Redis       RedisConfig    `mapstructure:"redis"`
	Auth        AuthConfig     `mapstructure:"auth"`
	Metrics     MetricsConfig  `mapstructure:"metrics"`
	Security    SecurityConfig `mapstructure:"security"`
	Environment string         `mapstructure:"environment"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	ReadTimeout  int    `mapstructure:"readTimeout"`  // seconds
	WriteTimeout int    `mapstructure:"writeTimeout"` // seconds
	IdleTimeout  int    `mapstructure:"idleTimeout"`  // seconds
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	Driver          string `mapstructure:"driver"`
	Host            string `mapstructure:"host"`
	Port            string `mapstructure:"port"`
	Username        string `mapstructure:"username"`
	Password        string `mapstructure:"password"`
	Database        string `mapstructure:"database"`
	SSLMode         string `mapstructure:"sslMode"`
	MaxOpenConns    int    `mapstructure:"maxOpenConns"`
	MaxIdleConns    int    `mapstructure:"maxIdleConns"`
	ConnMaxLifetime int    `mapstructure:"connMaxLifetime"` // minutes
}

// JWTConfig contains JWT authentication settings
type JWTConfig struct {
	AccessSecret     string `mapstructure:"accessSecret"`
	RefreshSecret    string `mapstructure:"refreshSecret"`
	AccessTTL        int    `mapstructure:"accessTTL"`  // minutes
	RefreshTTL       int    `mapstructure:"refreshTTL"` // hours
	Issuer           string `mapstructure:"issuer"`
	Audience         string `mapstructure:"audience"`
	MaxConcurrent    int    `mapstructure:"maxConcurrent"`    // max concurrent sessions
	AllowedClockSkew int    `mapstructure:"allowedClockSkew"` // seconds
}

// LoggerConfig contains logging settings
type LoggerConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Output      string `mapstructure:"output"`
	TimeFormat  string `mapstructure:"timeFormat"`
	CallerInfo  bool   `mapstructure:"callerInfo"`
	EnableAudit bool   `mapstructure:"enableAudit"`
}

// RedisConfig contains Redis connection settings
type RedisConfig struct {
	Host      string `mapstructure:"host"`
	Port      string `mapstructure:"port"`
	Password  string `mapstructure:"password"`
	DB        int    `mapstructure:"db"`
	KeyPrefix string `mapstructure:"keyPrefix"`
}

// AuthConfig contains authentication and authorization settings
type AuthConfig struct {
	Argon2                  Argon2Config `mapstructure:"argon2"`                 // Argon2 password hashing configuration
	AccessTokenSecret       string       `mapstructure:"accessTokenSecret"`       // Secret for signing access tokens
	RefreshTokenSecret      string       `mapstructure:"refreshTokenSecret"`      // Secret for signing refresh tokens
	AccessTokenTTL          int          `mapstructure:"accessTokenTTL"`          // Access token lifetime in minutes
	RefreshTokenTTL         int          `mapstructure:"refreshTokenTTL"`         // Refresh token lifetime in hours
	MaxSessionsPerUser      int          `mapstructure:"maxSessionsPerUser"`      // Maximum number of concurrent sessions per user
	SessionInactivityTTL    int          `mapstructure:"sessionInactivityTTL"`    // Session inactivity timeout in days
	OperationTimeoutSeconds int          `mapstructure:"operationTimeoutSeconds"` // Timeout for operations in seconds
}

// Argon2Config contains configuration for Argon2 password hashing
type Argon2Config struct {
	Memory      uint32 `mapstructure:"memory"`      // Memory cost in KiB
	Iterations  uint32 `mapstructure:"iterations"`  // Time cost (number of iterations)
	Parallelism uint32 `mapstructure:"parallelism"` // Number of threads to use
	SaltLength  uint32 `mapstructure:"saltLength"`  // Length of salt in bytes
	KeyLength   uint32 `mapstructure:"keyLength"`   // Length of the generated key (hash) in bytes
}

// MetricsConfig contains metrics collection settings
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled"`   // Whether metrics collection is enabled
	Type      string `mapstructure:"type"`      // Type of metrics collector (prometheus, memory, noop)
	Namespace string `mapstructure:"namespace"` // Namespace for metrics collection
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	KnownIPs             []string `mapstructure:"knownIPs"`             // List of known safe IPs
	SuspiciousIPs        []string `mapstructure:"suspiciousIPs"`        // List of suspicious IPs
	SuspiciousUserAgents []string `mapstructure:"suspiciousUserAgents"` // List of suspicious user agent substrings
	EnableRiskEvaluation bool     `mapstructure:"enableRiskEvaluation"` // Whether risk evaluation is enabled
}
