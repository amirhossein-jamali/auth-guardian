package logger

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
)

// WithRequestID domain-specific helper functions
func WithRequestID(logger Logger, requestID string) Logger {
	return logger.With(model.NewField("request_id", requestID))
}

func WithUserID(logger Logger, userID string) Logger {
	return logger.With(model.NewField("user_id", userID))
}
