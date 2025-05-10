package cache

// Factory provides methods to create cache services
type Factory interface {
	// CreateRateLimiter creates a rate limiter implementation
	CreateRateLimiter() RateLimiter

	// Close closes any connections created by the factory
	Close() error
}
