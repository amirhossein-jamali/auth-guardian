package risk

import (
	"context"
	"net"
	"strings"
	"time"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/risk"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// BasicRiskEvaluator implements a simple risk evaluation strategy
type BasicRiskEvaluator struct {
	logger           lport.Logger
	timeProvider     tport.Provider
	knownIPs         map[string]bool // IPs that are known to be safe
	suspiciousIPs    map[string]bool // IPs that are known to be suspicious
	suspiciousAgents []string        // User agent strings that are suspicious
}

// BasicRiskEvaluatorConfig holds configuration for the BasicRiskEvaluator
type BasicRiskEvaluatorConfig struct {
	KnownIPs         []string // List of known safe IPs
	SuspiciousIPs    []string // List of suspicious IPs or IP ranges
	SuspiciousAgents []string // List of suspicious user agent substrings
}

// NewBasicRiskEvaluator creates a new BasicRiskEvaluator
func NewBasicRiskEvaluator(config BasicRiskEvaluatorConfig, timeProvider tport.Provider, logger lport.Logger) risk.Evaluator {
	// Convert slice of IPs to map for faster lookup
	knownIPs := make(map[string]bool)
	for _, ip := range config.KnownIPs {
		knownIPs[ip] = true
	}

	suspiciousIPs := make(map[string]bool)
	for _, ip := range config.SuspiciousIPs {
		suspiciousIPs[ip] = true
	}

	return &BasicRiskEvaluator{
		logger:           logger,
		timeProvider:     timeProvider,
		knownIPs:         knownIPs,
		suspiciousIPs:    suspiciousIPs,
		suspiciousAgents: config.SuspiciousAgents,
	}
}

// EvaluateLoginRisk assesses the risk level of a login attempt
func (r *BasicRiskEvaluator) EvaluateLoginRisk(ctx context.Context, factors risk.LoginRiskFactors) (risk.Level, error) {
	// Initialize risk score
	riskLevel := risk.Low

	// Check if the IP is known and safe
	if _, known := r.knownIPs[factors.IP]; known {
		// Known IPs have low risk by default
		return risk.Low, nil
	}

	// Check if the IP is in the suspicious list
	if _, suspicious := r.suspiciousIPs[factors.IP]; suspicious {
		// Return high risk immediately for suspicious IPs
		r.logger.Warn("Login attempt from suspicious IP", map[string]any{
			"ip":     factors.IP,
			"userId": factors.UserID,
		})
		return risk.High, nil
	}

	// Check for suspicious user agent
	userAgent := factors.UserAgent
	for _, suspiciousAgent := range r.suspiciousAgents {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(suspiciousAgent)) {
			r.logger.Warn("Login attempt with suspicious user agent", map[string]any{
				"userAgent": userAgent,
				"userId":    factors.UserID,
			})
			return risk.High, nil
		}
	}

	// Check for private IP (not inherently suspicious, but worth noting)
	if isPrivateIP(factors.IP) {
		// Private IPs are generally safer than public IPs
		return risk.Low, nil
	}

	// Check for unusual login time (outside normal business hours)
	loginTime := time.Unix(factors.Time, 0)
	hour := loginTime.Hour()
	if hour < 7 || hour > 22 { // Outside 7 AM - 10 PM
		riskLevel = risk.Medium
	}

	// Here you could add more sophisticated checks:
	// 1. Geo-location analysis (if provided)
	// 2. Previous login patterns
	// 3. Check against known compromised IPs database
	// 4. Check for rapid login attempts from different locations

	return riskLevel, nil
}

// isPrivateIP checks if an IP is from a private range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// Check for 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// Check for 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// Check for 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// Check for localhost
		if ip4[0] == 127 {
			return true
		}
	}

	// Check for IPv6 loopback
	if ip.String() == "::1" {
		return true
	}

	return false
}
