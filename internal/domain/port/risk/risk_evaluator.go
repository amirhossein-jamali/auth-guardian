package risk

import "context"

// Level represents the risk level of an operation
type Level int

const (
	Low Level = iota
	Medium
	High
	Critical
)

// String returns the string representation of Level
func (r Level) String() string {
	switch r {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

// LoginRiskFactors contains factors for evaluating login risk
type LoginRiskFactors struct {
	UserID      string
	IP          string
	UserAgent   string
	GeoLocation string // optional, can be derived from IP
	Time        int64  // operation timestamp
}

// Evaluator evaluates risk for security-sensitive operations
type Evaluator interface {
	// EvaluateLoginRisk assesses the risk level of a login attempt
	EvaluateLoginRisk(ctx context.Context, factors LoginRiskFactors) (Level, error)
}
