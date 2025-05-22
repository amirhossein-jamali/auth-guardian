package tests

import (
	"testing"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
	"github.com/stretchr/testify/assert"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected error
	}{
		{"Valid email", "user@example.com", nil},
		{"Invalid email", "invalid-email", domainErr.ErrInvalidEmail},
		{"Empty email", "", domainErr.ErrInvalidEmail},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validator.ValidateEmail(test.email)
			assert.Equal(t, test.expected, err)
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected error
	}{
		{"Valid password", "Password123", nil},
		{"Empty password", "", domainErr.NewValidationError("password", "password is required")},
		{"Weak password", "password", domainErr.ErrPasswordTooWeak},
		{"Too short password", "Pw1", domainErr.ErrPasswordTooWeak},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validator.ValidatePassword(test.password)

			if test.expected == nil {
				assert.Nil(t, err)
			} else if _, ok := test.expected.(domainErr.ValidationError); ok {
				// For ValidationError type, just check if the error is of same type
				assert.True(t, domainErr.IsValidationError(err))
			} else {
				// For other errors, compare directly
				assert.Equal(t, test.expected, err)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		nameValue string
		expected  error
	}{
		{"Valid first name", "firstName", "John", nil},
		{"Valid last name", "lastName", "Doe", nil},
		{"Empty first name", "firstName", "", domainErr.NewValidationError("firstName", "firstName is required")},
		{"Empty last name", "lastName", "", domainErr.NewValidationError("lastName", "lastName is required")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validator.ValidateName(test.fieldName, test.nameValue)

			if test.expected == nil {
				assert.Nil(t, err)
			} else {
				// Check error type
				assert.True(t, domainErr.IsValidationError(err))
			}
		})
	}
}

func TestValidateID(t *testing.T) {
	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	invalidUUID := "invalid-uuid"

	tests := []struct {
		name      string
		fieldName string
		id        string
		expected  error
	}{
		{"Valid ID", "userID", validUUID, nil},
		{"Invalid ID", "userID", invalidUUID, domainErr.NewValidationError("userID", "userID is invalid")},
		{"Empty ID", "userID", "", domainErr.NewValidationError("userID", "userID is invalid")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validator.ValidateID(test.fieldName, test.id)

			if test.expected == nil {
				assert.Nil(t, err)
			} else {
				// Check error type
				assert.True(t, domainErr.IsValidationError(err))
			}
		})
	}
}

func TestValidateRefreshToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		isErr bool
	}{
		{"Valid token", "valid-token", false},
		{"Empty token", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validator.ValidateRefreshToken(test.token)

			if test.isErr {
				assert.Error(t, err)
				assert.True(t, domainErr.IsValidationError(err))
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateExpiresAt(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		isErr     bool
	}{
		{"Valid expires at", 1620000000, false},
		{"Zero value", 0, true},
		{"Negative value", -1, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validator.ValidateExpiresAt(test.expiresAt)

			if test.isErr {
				assert.Error(t, err)
				assert.True(t, domainErr.IsValidationError(err))
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
