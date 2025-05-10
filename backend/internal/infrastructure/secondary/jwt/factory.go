package jwt

import (
	"fmt"
	"sync"

	domainJWT "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/spf13/viper"
)

// Factory creates and manages JWT token service instances
type Factory struct {
	config        *Config
	logger        logger.Logger
	tokenService  domainJWT.TokenService
	serviceOnce   sync.Once
	validationErr error
}

// NewFactory creates a new JWT token service factory with validation
func NewFactory(config *viper.Viper, logger logger.Logger) (*Factory, error) {
	jwtConfig := NewConfig(config, logger)

	// Create factory
	factory := &Factory{
		config: jwtConfig,
		logger: logger,
	}

	// Validate configuration
	if err := factory.validateConfig(); err != nil {
		return factory, err
	}

	return factory, nil
}

// CreateTokenService creates a new domain TokenService implementation
// using lazy initialization pattern (singleton per factory instance)
func (f *Factory) CreateTokenService() domainJWT.TokenService {
	// Initialize service only once (thread-safe)
	f.serviceOnce.Do(func() {
		// Check if we have validation errors from initialization
		if f.validationErr != nil {
			f.logger.Error("Cannot create token service due to configuration errors",
				model.NewField("error", f.validationErr.Error()))
			// Return nil service which will cause panic if used
			// This is preferable to silently continuing with invalid config
			return
		}

		// Create the service
		f.tokenService = NewJWTTokenService(f.config, f.logger)
		f.logger.Debug("JWT token service created")
	})

	return f.tokenService
}

// Cleanup performs any necessary cleanup when shutting down
func (f *Factory) Cleanup() error {
	f.logger.Debug("Cleaning up JWT token service resources")
	// In Phase 1, there's nothing to clean up
	// This method will be expanded in future phases
	return nil
}

// validateConfig checks if the JWT configuration is valid
func (f *Factory) validateConfig() error {
	if f.config == nil {
		return fmt.Errorf("JWT configuration is nil")
	}

	// Check required settings
	if f.config.AccessTokenSecret == "" {
		f.validationErr = fmt.Errorf("JWT access token secret is not configured")
		f.logger.Error("JWT validation failed", model.NewField("error", f.validationErr.Error()))
		return f.validationErr
	}

	if f.config.RefreshTokenSecret == "" {
		f.validationErr = fmt.Errorf("JWT refresh token secret is not configured")
		f.logger.Error("JWT validation failed", model.NewField("error", f.validationErr.Error()))
		return f.validationErr
	}

	// Check recommended configuration
	if f.config.AccessTokenExpiration == 0 {
		f.logger.Warn("JWT access token expiration is set to 0, tokens will never expire")
	}

	if f.config.RefreshTokenExpiration == 0 {
		f.logger.Warn("JWT refresh token expiration is set to 0, tokens will never expire")
	}

	if f.config.AccessTokenSecret == f.config.RefreshTokenSecret {
		f.logger.Warn("Access and refresh token secrets are identical, consider using different secrets")
	}

	if f.config.Issuer == "" {
		f.logger.Warn("JWT issuer is not configured")
	}

	return nil
}

// GetConfig returns a copy of the current JWT configuration
// This prevents accidental modifications to the config
func (f *Factory) GetConfig() *Config {
	// Return a copy to prevent external modifications
	configCopy := *f.config
	return &configCopy
}
