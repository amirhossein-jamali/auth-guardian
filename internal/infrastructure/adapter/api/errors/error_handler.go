package errors

import (
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
)

// ErrorResponse represents the error response format
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// HTTPError maps domain errors to HTTP status codes and messages
func HTTPError(err error) (int, *ErrorResponse) {
	// Use the domain error's CodeError function to get the HTTP status code
	statusCode := domainErr.CodeError(err)

	// Use the domain error's UserFriendlyMessage function to get a user-friendly error message
	message := domainErr.UserFriendlyMessage(err)

	// Map domain errors to error codes for the API response
	var errorCode string
	switch err {
	case domainErr.ErrInvalidCredentials:
		errorCode = "invalid_credentials"
	case domainErr.ErrTokenExpired, domainErr.ErrExpiredToken:
		errorCode = "token_expired"
	case domainErr.ErrInvalidToken:
		errorCode = "invalid_token"
	case domainErr.ErrEmailAlreadyExists:
		errorCode = "email_exists"
	case domainErr.ErrUserNotFound:
		errorCode = "user_not_found"
	case domainErr.ErrInactiveUser, domainErr.ErrUserDeactivated:
		errorCode = "inactive_user"
	case domainErr.ErrInvalidEmail:
		errorCode = "invalid_email"
	case domainErr.ErrInvalidPassword, domainErr.ErrPasswordTooWeak:
		errorCode = "invalid_password"
	case domainErr.ErrInvalidFirstName:
		errorCode = "invalid_first_name"
	case domainErr.ErrInvalidLastName:
		errorCode = "invalid_last_name"
	case domainErr.ErrSessionNotFound:
		errorCode = "session_not_found"
	case domainErr.ErrTooManySessions, domainErr.ErrMaxSessionsReached:
		errorCode = "too_many_sessions"
	case domainErr.ErrInternalServer:
		errorCode = "internal_error"
	case domainErr.ErrTokenGenerationFailed:
		errorCode = "token_generation_failed"
	default:
		if domainErr.IsAuthorizationError(err) {
			errorCode = "forbidden"
		} else if domainErr.IsValidationError(err) {
			errorCode = "validation_error"
		} else {
			errorCode = "unknown_error"
		}
	}

	return statusCode, &ErrorResponse{
		Error: message,
		Code:  errorCode,
	}
}
