package time

import (
	"context"
	"time"
)

// Provider abstracts time operations for the domain and allows mocking in tests
type Provider interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	Until(t time.Time) time.Duration
	Add(t time.Time, d time.Duration) time.Time
	WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc)
	Sleep(d time.Duration)
	ParseDuration(s string) (Duration, error)
}

// Common time formats
const (
	DateFormat    = "2006-01-02"
	RFC3339Format = "2006-01-02T15:04:05Z07:00"
)
