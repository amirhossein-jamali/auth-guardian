package time

import (
	"context"
	"time"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// RealTimeProvider implements the Provider port with actual time
type RealTimeProvider struct{}

func NewRealTimeProvider() tport.Provider {
	return &RealTimeProvider{}
}

func (rtp *RealTimeProvider) Now() time.Time {
	return time.Now()
}

func (rtp *RealTimeProvider) Since(t time.Time) time.Duration {
	return time.Since(t)
}

func (rtp *RealTimeProvider) Until(t time.Time) time.Duration {
	return time.Until(t)
}

func (rtp *RealTimeProvider) Add(t time.Time, d time.Duration) time.Time {
	return t.Add(d)
}

func (rtp *RealTimeProvider) WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

func (rtp *RealTimeProvider) Sleep(d time.Duration) {
	time.Sleep(d)
}

func (rtp *RealTimeProvider) ParseDuration(s string) (tport.Duration, error) {
	d, err := time.ParseDuration(s)
	return tport.Duration(d), err
}
