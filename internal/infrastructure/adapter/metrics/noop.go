package metrics

import "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"

// NoopRecorder is a no-operation implementation of the MetricsRecorder port
// It doesn't record any metrics and is used when metrics collection is disabled
type NoopRecorder struct{}

// NewNoopRecorder creates a new no-operation metrics recorder
func NewNoopRecorder() *NoopRecorder {
	return &NoopRecorder{}
}

// IncCounter is a no-op implementation that does nothing
func (n *NoopRecorder) IncCounter(name string, tags map[string]string) {}

// ObserveHistogram is a no-op implementation that does nothing
func (n *NoopRecorder) ObserveHistogram(name string, value float64, tags map[string]string) {}

// SetGauge is a no-op implementation that does nothing
func (n *NoopRecorder) SetGauge(name string, value float64, tags map[string]string) {}

// Ensure NoopRecorder implements metrics.MetricsRecorder
var _ metrics.Recorder = (*NoopRecorder)(nil)
