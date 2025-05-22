package metrics

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusRecorder implements the MetricsRecorder port using Prometheus
type PrometheusRecorder struct {
	namespace  string
	counters   map[string]*prometheus.CounterVec
	histograms map[string]*prometheus.HistogramVec
	gauges     map[string]*prometheus.GaugeVec
}

// NewPrometheusRecorder creates a new Prometheus metrics recorder
func NewPrometheusRecorder(namespace string) *PrometheusRecorder {
	return &PrometheusRecorder{
		namespace:  namespace,
		counters:   make(map[string]*prometheus.CounterVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
	}
}

// getOrCreateCounter returns an existing counter or creates a new one
func (p *PrometheusRecorder) getOrCreateCounter(name string) *prometheus.CounterVec {
	if counter, exists := p.counters[name]; exists {
		return counter
	}

	counter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: p.namespace,
			Name:      name,
		},
		[]string{},
	)
	p.counters[name] = counter
	return counter
}

// getOrCreateHistogram returns an existing histogram or creates a new one
func (p *PrometheusRecorder) getOrCreateHistogram(name string) *prometheus.HistogramVec {
	if histogram, exists := p.histograms[name]; exists {
		return histogram
	}

	histogram := promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: p.namespace,
			Name:      name,
			Buckets:   prometheus.DefBuckets,
		},
		[]string{},
	)
	p.histograms[name] = histogram
	return histogram
}

// getOrCreateGauge returns an existing gauge or creates a new one
func (p *PrometheusRecorder) getOrCreateGauge(name string) *prometheus.GaugeVec {
	if gauge, exists := p.gauges[name]; exists {
		return gauge
	}

	gauge := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: p.namespace,
			Name:      name,
		},
		[]string{},
	)
	p.gauges[name] = gauge
	return gauge
}

// IncCounter increments a counter metric
func (p *PrometheusRecorder) IncCounter(name string, tags map[string]string) {
	counter := p.getOrCreateCounter(name)
	if len(tags) == 0 {
		counter.WithLabelValues().Inc()
	} else {
		counter.With(transformTags(tags)).Inc()
	}
}

// ObserveHistogram records a value in a histogram metric
func (p *PrometheusRecorder) ObserveHistogram(name string, value float64, tags map[string]string) {
	histogram := p.getOrCreateHistogram(name)
	if len(tags) == 0 {
		histogram.WithLabelValues().Observe(value)
	} else {
		histogram.With(transformTags(tags)).Observe(value)
	}
}

// SetGauge sets a gauge metric to a value
func (p *PrometheusRecorder) SetGauge(name string, value float64, tags map[string]string) {
	gauge := p.getOrCreateGauge(name)
	if len(tags) == 0 {
		gauge.WithLabelValues().Set(value)
	} else {
		gauge.With(transformTags(tags)).Set(value)
	}
}

// transformTags converts a map of tags to Prometheus labels format
func transformTags(tags map[string]string) prometheus.Labels {
	if len(tags) == 0 {
		return prometheus.Labels{}
	}

	labels := make(prometheus.Labels)
	for k, v := range tags {
		labels[k] = v
	}
	return labels
}

// Ensure PrometheusRecorder implements metrics.MetricsRecorder
var _ metrics.Recorder = (*PrometheusRecorder)(nil)
