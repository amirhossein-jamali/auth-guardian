package logger

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
)

// Logger defines interface for logging operations in domain
type Logger interface {
	Debug(message string, fields ...model.Field)
	Info(message string, fields ...model.Field)
	Warn(message string, fields ...model.Field)
	Error(message string, fields ...model.Field)
	Fatal(message string, fields ...model.Field)
	With(fields ...model.Field) Logger
}
