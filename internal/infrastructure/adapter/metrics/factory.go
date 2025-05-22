package metrics

import (
	"strings"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"
)

// RecorderType defines the type of metrics recorder to use
type RecorderType string

const (
	// TypeMemory represents in-memory metrics recorder
	TypeMemory RecorderType = "memory"
	// TypePrometheus represents Prometheus metrics recorder
	TypePrometheus RecorderType = "prometheus"
	// TypeNoop represents no-operation metrics recorder
	TypeNoop RecorderType = "noop"
)

// Factory is responsible for creating MetricsRecorder instances
type Factory struct{}

// NewFactory creates a new metrics recorder factory
func NewFactory() *Factory {
	return &Factory{}
}

// Create creates a new MetricsRecorder based on the provided type and options
func (f *Factory) Create(recorderType RecorderType, options map[string]string) metrics.Recorder {
	switch strings.ToLower(string(recorderType)) {
	case string(TypePrometheus):
		namespace := options["namespace"]
		if namespace == "" {
			namespace = "auth_guardian"
		}
		return NewPrometheusRecorder(namespace)
	case string(TypeMemory):
		return NewMemoryRecorder()
	case string(TypeNoop):
		fallthrough
	default:
		return NewNoopRecorder()
	}
}
