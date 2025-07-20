package tests

import (
	"errors"
	"testing"

	domainerror "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
)

func TestValidationError(t *testing.T) {
	// Test creation of ValidationError
	validationErr := domainerror.NewValidationError("email", "must be a valid email")

	// Test if fields are correctly set
	if validationErr.Field != "email" {
		t.Errorf("Expected field to be 'email', got '%s'", validationErr.Field)
	}

	if validationErr.Message != "must be a valid email" {
		t.Errorf("Expected message to be 'must be a valid email', got '%s'", validationErr.Message)
	}

	// Test Error() method
	expectedErrMsg := "validation errors: email: must be a valid email"
	if validationErr.Error() != expectedErrMsg {
		t.Errorf("Expected errors message to be '%s', got '%s'", expectedErrMsg, validationErr.Error())
	}

	// Test IsValidationError function
	if !domainerror.IsValidationError(validationErr) {
		t.Error("IsValidationError failed to identify a ValidationError")
	}

	// Test with a non-validation errors
	regularErr := errors.New("regular errors")
	if domainerror.IsValidationError(regularErr) {
		t.Error("IsValidationError incorrectly identified a regular errors as ValidationError")
	}
}

func TestAuthorizationError(t *testing.T) {
	// Test creation of AuthorizationError
	authErr := domainerror.NewAuthorizationError("user", "delete", "insufficient permissions")

	// Test if fields are correctly set
	if authErr.Resource != "user" {
		t.Errorf("Expected resource to be 'user', got '%s'", authErr.Resource)
	}

	if authErr.Action != "delete" {
		t.Errorf("Expected action to be 'delete', got '%s'", authErr.Action)
	}

	if authErr.Message != "insufficient permissions" {
		t.Errorf("Expected message to be 'insufficient permissions', got '%s'", authErr.Message)
	}

	// Test Error() method
	expectedErrMsg := "authorization errors: cannot delete user: insufficient permissions"
	if authErr.Error() != expectedErrMsg {
		t.Errorf("Expected errors message to be '%s', got '%s'", expectedErrMsg, authErr.Error())
	}

	// Test IsAuthorizationError function
	if !domainerror.IsAuthorizationError(authErr) {
		t.Error("IsAuthorizationError failed to identify an AuthorizationError")
	}

	// Test with a non-authorization errors
	regularErr := errors.New("regular errors")
	if domainerror.IsAuthorizationError(regularErr) {
		t.Error("IsAuthorizationError incorrectly identified a regular errors as AuthorizationError")
	}
}

func TestCodeError(t *testing.T) {
	// Set up test cases
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"ErrInvalidCredentials", domainerror.ErrInvalidCredentials, 401},
		{"ErrInvalidToken", domainerror.ErrInvalidToken, 401},
		{"ErrExpiredToken", domainerror.ErrExpiredToken, 401},
		{"ErrSessionNotFound", domainerror.ErrSessionNotFound, 404},
		{"ErrUserNotFound", domainerror.ErrUserNotFound, 404},
		{"ErrEmailAlreadyExists", domainerror.ErrEmailAlreadyExists, 400},
		{"ErrInvalidEmail", domainerror.ErrInvalidEmail, 400},
		{"ErrInvalidPassword", domainerror.ErrInvalidPassword, 400},
		{"ErrPasswordTooWeak", domainerror.ErrPasswordTooWeak, 400},
		{"ErrPasswordMismatch", domainerror.ErrPasswordMismatch, 400},
		{"ErrMaxSessionsReached", domainerror.ErrMaxSessionsReached, 400},
		{"ValidationError", domainerror.NewValidationError("field", "message"), 400},
		{"AuthorizationError", domainerror.NewAuthorizationError("resource", "action", "message"), 403},
		{"ErrTimeout", domainerror.ErrTimeout, 408},
		{"ErrInternalServer", domainerror.ErrInternalServer, 500},
		{"Unknown errors", errors.New("unknown errors"), 500},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := domainerror.CodeError(tc.err)
			if status != tc.expectedStatus {
				t.Errorf("Expected status code %d for errors %v, got %d", tc.expectedStatus, tc.err, status)
			}
		})
	}
}

func TestUserFriendlyMessage(t *testing.T) {
	// Set up test cases
	testCases := []struct {
		name            string
		err             error
		expectedMessage string
	}{
		{"ErrEmailAlreadyExists", domainerror.ErrEmailAlreadyExists, "The email address is already in use. Please try a different email."},
		{"ErrInvalidCredentials", domainerror.ErrInvalidCredentials, "Invalid email or password. Please check your credentials and try again."},
		{"ErrInvalidToken", domainerror.ErrInvalidToken, "Your session has expired. Please log in again."},
		{"ErrExpiredToken", domainerror.ErrExpiredToken, "Your session has expired. Please log in again."},
		{"ErrUserNotFound", domainerror.ErrUserNotFound, "User not found."},
		{"ErrInvalidEmail", domainerror.ErrInvalidEmail, "Please enter a valid email address."},
		{"ErrInvalidPassword", domainerror.ErrInvalidPassword, "Password must be at least 8 characters long and include letters, numbers, and special characters."},
		{"ErrPasswordTooWeak", domainerror.ErrPasswordTooWeak, "Password must be at least 8 characters long and include letters, numbers, and special characters."},
		{"ErrPasswordMismatch", domainerror.ErrPasswordMismatch, "Passwords do not match. Please check and try again."},
		{"ErrMaxSessionsReached", domainerror.ErrMaxSessionsReached, "You have reached the maximum number of active sessions. Please log out from another device and try again."},
		{"ErrUserDeactivated", domainerror.ErrUserDeactivated, "Your account has been deactivated. Please contact support for assistance."},
		{"ValidationError", domainerror.NewValidationError("email", "must be a valid email"), "validation errors: email: must be a valid email"},
		{"AuthorizationError", domainerror.NewAuthorizationError("user", "delete", "insufficient permissions"), "You do not have permission to perform this action."},
		{"Unknown errors", errors.New("unknown errors"), "An unexpected errors occurred. Please try again later or contact support if the problem persists."},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := domainerror.UserFriendlyMessage(tc.err)
			if message != tc.expectedMessage {
				t.Errorf("Expected message '%s' for errors %v, got '%s'", tc.expectedMessage, tc.err, message)
			}
		})
	}
}

func TestErrorAliases(t *testing.T) {
	// Test errors aliases to ensure they're the same instance
	if !errors.Is(domainerror.ErrExpiredToken, domainerror.ErrTokenExpired) {
		t.Error("ErrTokenExpired and ErrExpiredToken should be the same errors instance")
	}

	if !errors.Is(domainerror.ErrMaxSessionsReached, domainerror.ErrTooManySessions) {
		t.Error("ErrTooManySessions and ErrMaxSessionsReached should be the same errors instance")
	}

	if !errors.Is(domainerror.ErrUserDeactivated, domainerror.ErrInactiveUser) {
		t.Error("ErrInactiveUser and ErrUserDeactivated should be the same errors instance")
	}
}
