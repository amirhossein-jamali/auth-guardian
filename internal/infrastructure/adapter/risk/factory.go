package risk

import (
	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/risk"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"

	"github.com/spf13/viper"
)

// Factory creates RiskEvaluator instances
type Factory struct {
	config       *viper.Viper
	logger       lport.Logger
	timeProvider tport.Provider
}

// NewFactory creates a new RiskEvaluator factory
func NewFactory(config *viper.Viper, logger lport.Logger, timeProvider tport.Provider) *Factory {
	return &Factory{
		config:       config,
		logger:       logger,
		timeProvider: timeProvider,
	}
}

// CreateBasicRiskEvaluator creates a BasicRiskEvaluator with configuration from viper
func (f *Factory) CreateBasicRiskEvaluator() risk.Evaluator {
	config := BasicRiskEvaluatorConfig{
		KnownIPs:         f.config.GetStringSlice("risk.known_ips"),
		SuspiciousIPs:    f.config.GetStringSlice("risk.suspicious_ips"),
		SuspiciousAgents: f.config.GetStringSlice("risk.suspicious_user_agents"),
	}

	return NewBasicRiskEvaluator(config, f.timeProvider, f.logger)
}

// CreateInMemoryRiskEvaluator creates an InMemoryRiskEvaluator for testing
func (f *Factory) CreateInMemoryRiskEvaluator() risk.Evaluator {
	// Default to low risk for test environments
	config := InMemoryRiskEvaluatorConfig{
		DefaultLevel: risk.Low,
	}

	return NewInMemoryRiskEvaluator(config, f.logger)
}

// CreateRiskEvaluator creates the appropriate RiskEvaluator based on environment
func (f *Factory) CreateRiskEvaluator() risk.Evaluator {
	// Use environment to determine which implementation to use
	env := f.config.GetString("environment")

	// For test and development environments, use the in-memory implementation
	if env == "test" || env == "development" {
		return f.CreateInMemoryRiskEvaluator()
	}

	// For production and staging, use the basic implementation
	return f.CreateBasicRiskEvaluator()
}
