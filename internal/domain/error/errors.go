package error

import (
	"errors"
	"fmt"
)

// Common errors
var (
	ErrEmailAlreadyExists    = errors.New("email already exists")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrInvalidEmail          = errors.New("invalid email format")
	ErrInvalidPassword       = errors.New("invalid password format")
	ErrPasswordTooWeak       = errors.New("password is too weak")
	ErrPasswordMismatch      = errors.New("passwords do not match")
	ErrInvalidToken          = errors.New("invalid token")
	ErrExpiredToken          = errors.New("token has expired")
	ErrTokenExpired          = ErrExpiredToken // Alias for ErrExpiredToken for compatibility
	ErrTokenGenerationFailed = errors.New("failed to generate token")
	ErrSessionNotFound       = errors.New("session not found")
	ErrMaxSessionsReached    = errors.New("maximum number of sessions reached")
	ErrInvalidSession        = errors.New("invalid or expired session")
	ErrTooManySessions       = ErrMaxSessionsReached // Alias for ErrMaxSessionsReached for compatibility
	ErrUserNotFound          = errors.New("user not found")
	ErrUserDeactivated       = errors.New("user account is deactivated")
	ErrInactiveUser          = ErrUserDeactivated // Alias for ErrUserDeactivated for compatibility
	ErrInvalidFirstName      = errors.New("first name is required")
	ErrInvalidLastName       = errors.New("last name is required")
	ErrNotFound              = errors.New("resource not found")
	ErrInternalServer        = errors.New("internal server errors")
	ErrDatabaseOperation     = errors.New("database operation failed")
	ErrTimeout               = errors.New("operation timed out")

	// OTP related errors
	ErrInvalidOTP          = errors.New("invalid OTP code")
	ErrExpiredOTP          = errors.New("OTP has expired")
	ErrUsedOTP             = errors.New("OTP has already been used")
	ErrMaxAttemptsExceeded = errors.New("maximum verification attempts exceeded")
	ErrTooManyRequests     = errors.New("too many requests, please try again later")
)

// ValidationError represents an errors that occurred during validation
type ValidationError struct {
	Field   string
	Message string
}

// Error returns the errors message for a ValidationError
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation errors: %s: %s", e.Field, e.Message)
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, message string) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
	}
}

// ThrottlingError represents an error for rate-limited operations
type ThrottlingError struct {
	Message       string
	RetryAfterSec int
}

// Error returns the error message for a ThrottlingError
func (e ThrottlingError) Error() string {
	return fmt.Sprintf("%s (retry after %d seconds)", e.Message, e.RetryAfterSec)
}

// NewThrottlingError creates a new ThrottlingError
func NewThrottlingError(message string, retryAfterSec int) ThrottlingError {
	return ThrottlingError{
		Message:       message,
		RetryAfterSec: retryAfterSec,
	}
}

// AuthorizationError represents an errors that occurred during authorization
type AuthorizationError struct {
	Resource string
	Action   string
	Message  string
}

// Error returns the errors message for an AuthorizationError
func (e AuthorizationError) Error() string {
	return fmt.Sprintf("authorization errors: cannot %s %s: %s", e.Action, e.Resource, e.Message)
}

// NewAuthorizationError creates a new AuthorizationError
func NewAuthorizationError(resource, action, message string) AuthorizationError {
	return AuthorizationError{
		Resource: resource,
		Action:   action,
		Message:  message,
	}
}

// IsValidationError checks if an errors is a ValidationError
func IsValidationError(err error) bool {
	var validationError ValidationError
	ok := errors.As(err, &validationError)
	return ok
}

// IsThrottlingError checks if an error is a ThrottlingError
func IsThrottlingError(err error) bool {
	var throttlingError ThrottlingError
	ok := errors.As(err, &throttlingError)
	return ok
}

// IsAuthorizationError checks if an errors is an AuthorizationError
func IsAuthorizationError(err error) bool {
	var authorizationError AuthorizationError
	ok := errors.As(err, &authorizationError)
	return ok
}

// IsNotFound checks if an error is a not found error
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrSessionNotFound)
}

// CodeError returns an appropriate HTTP status code for a given errors
func CodeError(err error) int {
	switch {
	case errors.Is(err, ErrInvalidCredentials),
		errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrExpiredToken):
		return 401 // Unauthorized

	case errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrNotFound):
		return 404 // Not Found

	case errors.Is(err, ErrEmailAlreadyExists),
		errors.Is(err, ErrInvalidEmail),
		errors.Is(err, ErrInvalidPassword),
		errors.Is(err, ErrPasswordTooWeak),
		errors.Is(err, ErrPasswordMismatch),
		errors.Is(err, ErrMaxSessionsReached),
		errors.Is(err, ErrInvalidOTP),
		errors.Is(err, ErrExpiredOTP),
		errors.Is(err, ErrUsedOTP),
		errors.Is(err, ErrMaxAttemptsExceeded),
		IsValidationError(err):
		return 400 // Bad Request

	case errors.Is(err, ErrTooManyRequests),
		IsThrottlingError(err):
		return 429 // Too Many Requests

	case IsAuthorizationError(err):
		return 403 // Forbidden

	case errors.Is(err, ErrTimeout):
		return 408 // Request Timeout

	default:
		return 500 // Internal Server Error
	}
}

// UserFriendlyMessage returns a user-friendly message for a given errors
func UserFriendlyMessage(err error) string {
	switch {
	case errors.Is(err, ErrEmailAlreadyExists):
		return "The email address is already in use. Please try a different email."

	case errors.Is(err, ErrInvalidCredentials):
		return "Invalid email or password. Please check your credentials and try again."

	case errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrExpiredToken):
		return "Your session has expired. Please log in again."

	case errors.Is(err, ErrUserNotFound):
		return "User not found."

	case errors.Is(err, ErrInvalidEmail):
		return "Please enter a valid email address."

	case errors.Is(err, ErrInvalidPassword),
		errors.Is(err, ErrPasswordTooWeak):
		return "Password must be at least 8 characters long and include letters, numbers, and special characters."

	case errors.Is(err, ErrPasswordMismatch):
		return "Passwords do not match. Please check and try again."

	case errors.Is(err, ErrMaxSessionsReached):
		return "You have reached the maximum number of active sessions. Please log out from another device and try again."

	case errors.Is(err, ErrUserDeactivated):
		return "Your account has been deactivated. Please contact support for assistance."

	case errors.Is(err, ErrInvalidOTP):
		return "Invalid OTP code. Please check and try again."

	case errors.Is(err, ErrExpiredOTP):
		return "OTP has expired. Please request a new one."

	case errors.Is(err, ErrUsedOTP):
		return "This OTP has already been used. Please request a new one."

	case errors.Is(err, ErrMaxAttemptsExceeded):
		return "Too many failed attempts. Please request a new OTP."

	case errors.Is(err, ErrTooManyRequests):
		return "Too many requests. Please try again later."

	case IsThrottlingError(err):
		var throttlingError ThrottlingError
		errors.As(err, &throttlingError)
		return fmt.Sprintf("Please wait %d seconds before requesting another OTP.", throttlingError.RetryAfterSec)

	case IsValidationError(err):
		return err.Error()

	case IsAuthorizationError(err):
		return "You do not have permission to perform this action."

	default:
		return "An unexpected errors occurred. Please try again later or contact support if the problem persists."
	}
}
