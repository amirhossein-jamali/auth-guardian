package storage

import (
	"context"
	"time"
)

// KeyValueStore defines the interface for basic key-value storage operations
type KeyValueStore interface {
	// Set stores a value with associated key and expiration time
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	// Get retrieves a value by key
	Get(ctx context.Context, key string) (string, error)
	// Delete removes keys from storage
	Delete(ctx context.Context, keys ...string) (int64, error)
	// Exists checks if keys exist in storage
	Exists(ctx context.Context, keys ...string) (bool, error)
}
