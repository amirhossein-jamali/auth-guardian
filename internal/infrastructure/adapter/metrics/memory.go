package metrics

import (
	"sync"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"
)

// MemoryRecorder is a simple in-memory implementation of the MetricsRecorder port
// primarily used for testing or environments where external metrics systems are not available
type MemoryRecorder struct {
	counters   map[string]map[string]float64
	histograms map[string]map[string][]float64
	gauges     map[string]map[string]float64
	mu         sync.RWMutex
}

// NewMemoryRecorder creates a new in-memory metrics recorder
func NewMemoryRecorder() *MemoryRecorder {
	return &MemoryRecorder{
		counters:   make(map[string]map[string]float64),
		histograms: make(map[string]map[string][]float64),
		gauges:     make(map[string]map[string]float64),
	}
}

// IncCounter increments a counter metric
func (m *MemoryRecorder) IncCounter(name string, tags map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tagKey := formatTagsKey(tags)
	if _, exists := m.counters[name]; !exists {
		m.counters[name] = make(map[string]float64)
	}
	m.counters[name][tagKey]++
}

// ObserveHistogram records a value in a histogram metric
func (m *MemoryRecorder) ObserveHistogram(name string, value float64, tags map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tagKey := formatTagsKey(tags)
	if _, exists := m.histograms[name]; !exists {
		m.histograms[name] = make(map[string][]float64)
	}
	m.histograms[name][tagKey] = append(m.histograms[name][tagKey], value)
}

// SetGauge sets a gauge metric to a value
func (m *MemoryRecorder) SetGauge(name string, value float64, tags map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tagKey := formatTagsKey(tags)
	if _, exists := m.gauges[name]; !exists {
		m.gauges[name] = make(map[string]float64)
	}
	m.gauges[name][tagKey] = value
}

// GetCounter returns the current value of a counter
func (m *MemoryRecorder) GetCounter(name string, tags map[string]string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tagKey := formatTagsKey(tags)
	if counters, exists := m.counters[name]; exists {
		return counters[tagKey]
	}
	return 0
}

// GetHistogramValues returns all recorded values for a histogram
func (m *MemoryRecorder) GetHistogramValues(name string, tags map[string]string) []float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tagKey := formatTagsKey(tags)
	if histograms, exists := m.histograms[name]; exists {
		if values, exists := histograms[tagKey]; exists {
			// Return a copy to prevent modification
			result := make([]float64, len(values))
			copy(result, values)
			return result
		}
	}
	return []float64{}
}

// GetGauge returns the current value of a gauge
func (m *MemoryRecorder) GetGauge(name string, tags map[string]string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tagKey := formatTagsKey(tags)
	if gauges, exists := m.gauges[name]; exists {
		return gauges[tagKey]
	}
	return 0
}

// formatTagsKey creates a string key from tags map
func formatTagsKey(tags map[string]string) string {
	if len(tags) == 0 {
		return "default"
	}

	// For simplicity, we're just concatenating keys and values
	// In a real implementation, you'd want to use a more robust serialization
	var result string
	for k, v := range tags {
		result += k + ":" + v + ";"
	}
	return result
}

// Ensure MemoryRecorder implements metrics.MetricsRecorder
var _ metrics.Recorder = (*MemoryRecorder)(nil)
