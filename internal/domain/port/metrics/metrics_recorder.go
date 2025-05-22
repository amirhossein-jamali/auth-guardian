package metrics

// Recorder defines interface for recording application metrics
type Recorder interface {
	// IncCounter increments a counter metric
	IncCounter(name string, tags map[string]string)
	// ObserveHistogram records a value in a histogram metric
	ObserveHistogram(name string, value float64, tags map[string]string)
	// SetGauge sets a gauge metric to a value
	SetGauge(name string, value float64, tags map[string]string)
}
