package jwt

import (
	"regexp"
	"strconv"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/spf13/viper"
)

// Config holds JWT configuration parameters
type Config struct {
	AccessTokenSecret      string
	RefreshTokenSecret     string
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	Issuer                 string
}

// parseDurationWithDays parses a duration string with support for days (d)
// Examples: "1d", "7d", "30m", "1h", "24h", etc.
func parseDurationWithDays(durationStr string) (time.Duration, error) {
	// Check for day format (e.g., "7d")
	re := regexp.MustCompile(`^(\d+)d$`)
	matches := re.FindStringSubmatch(durationStr)

	if len(matches) == 2 {
		// Extract the number of days
		days, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, err
		}
		// Convert days to hours
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// Otherwise, use standard time.ParseDuration
	return time.ParseDuration(durationStr)
}

// NewConfig creates a new JWT configuration from viper config
func NewConfig(config *viper.Viper, logger logger.Logger) *Config {
	accessExpStr := config.GetString("jwt.accessTokenExpiration")
	refreshExpStr := config.GetString("jwt.refreshTokenExpiration")

	accessExp, err := parseDurationWithDays(accessExpStr)
	if err != nil {
		logger.Warn("Invalid access token expiration, using default 15m",
			model.NewField("configValue", accessExpStr),
			model.NewField("error", err.Error()))
		accessExp = 15 * time.Minute
	}

	refreshExp, err := parseDurationWithDays(refreshExpStr)
	if err != nil {
		logger.Warn("Invalid refresh token expiration, using default 7d",
			model.NewField("configValue", refreshExpStr),
			model.NewField("error", err.Error()))
		refreshExp = 7 * 24 * time.Hour
	}

	return &Config{
		AccessTokenSecret:      config.GetString("jwt.accessTokenSecret"),
		RefreshTokenSecret:     config.GetString("jwt.refreshTokenSecret"),
		AccessTokenExpiration:  accessExp,
		RefreshTokenExpiration: refreshExp,
		Issuer:                 config.GetString("jwt.issuer"),
	}
}
