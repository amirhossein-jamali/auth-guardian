package logger

import "github.com/amirhossein-jamali/auth-guardian/pkg/logger/model"

// Field is a type alias for model.Field for convenience
type Field = model.Field

// NewField creates a new logging field
var NewField = model.NewField

// Logger provides a unified interface for logging throughout the application
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	With(fields ...Field) Logger
}
