package risk

import (
	"context"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/risk"
)

// InMemoryRiskEvaluator is a simple implementation for testing
type InMemoryRiskEvaluator struct {
	logger          lport.Logger
	defaultLevel    risk.Level
	ipOverrides     map[string]risk.Level
	userIDOverrides map[string]risk.Level
}

// InMemoryRiskEvaluatorConfig holds configuration for the InMemoryRiskEvaluator
type InMemoryRiskEvaluatorConfig struct {
	DefaultLevel    risk.Level
	IPOverrides     map[string]risk.Level // Specific risk levels for certain IPs
	UserIDOverrides map[string]risk.Level // Specific risk levels for certain user IDs
}

// NewInMemoryRiskEvaluator creates a new InMemoryRiskEvaluator
func NewInMemoryRiskEvaluator(config InMemoryRiskEvaluatorConfig, logger lport.Logger) risk.Evaluator {
	// Create default config if nil maps provided
	if config.IPOverrides == nil {
		config.IPOverrides = make(map[string]risk.Level)
	}

	if config.UserIDOverrides == nil {
		config.UserIDOverrides = make(map[string]risk.Level)
	}

	return &InMemoryRiskEvaluator{
		logger:          logger,
		defaultLevel:    config.DefaultLevel,
		ipOverrides:     config.IPOverrides,
		userIDOverrides: config.UserIDOverrides,
	}
}

// EvaluateLoginRisk returns a pre-configured risk level for testing purposes
func (r *InMemoryRiskEvaluator) EvaluateLoginRisk(ctx context.Context, factors risk.LoginRiskFactors) (risk.Level, error) {
	// First check if there's an override for this user ID
	if level, exists := r.userIDOverrides[factors.UserID]; exists {
		r.logger.Debug("Using user ID override for risk level", map[string]any{
			"userId":    factors.UserID,
			"riskLevel": level.String(),
		})
		return level, nil
	}

	// Then check if there's an override for this IP
	if level, exists := r.ipOverrides[factors.IP]; exists {
		r.logger.Debug("Using IP override for risk level", map[string]any{
			"ip":        factors.IP,
			"riskLevel": level.String(),
		})
		return level, nil
	}

	// Otherwise return the default level
	r.logger.Debug("Using default risk level", map[string]any{
		"riskLevel": r.defaultLevel.String(),
	})
	return r.defaultLevel, nil
}

// SetIPRiskLevel sets a risk level for a specific IP address
func (r *InMemoryRiskEvaluator) SetIPRiskLevel(ip string, level risk.Level) {
	r.ipOverrides[ip] = level
}

// SetUserIDRiskLevel sets a risk level for a specific user ID
func (r *InMemoryRiskEvaluator) SetUserIDRiskLevel(userID string, level risk.Level) {
	r.userIDOverrides[userID] = level
}

// ResetAllOverrides resets all configuration to default
func (r *InMemoryRiskEvaluator) ResetAllOverrides() {
	r.ipOverrides = make(map[string]risk.Level)
	r.userIDOverrides = make(map[string]risk.Level)
}
