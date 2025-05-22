package repository

import (
	"context"
)

// ContextChecker provides a method to check if context is still valid
type ContextChecker interface {
	CheckContext(ctx context.Context) error
}

// DefaultContextChecker is the default implementation of ContextChecker
type DefaultContextChecker struct{}

// CheckContext checks if the context is still valid
func (c *DefaultContextChecker) CheckContext(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
