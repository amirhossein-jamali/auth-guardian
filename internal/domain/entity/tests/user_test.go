package tests

import (
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	mocks "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	"github.com/stretchr/testify/assert"
)

func TestNewUser(t *testing.T) {
	// Arrange
	id := entity.ID("user-123")
	email := "test@example.com"
	phoneNumber := "+989123456789" // Added phone number
	firstName := "John"
	lastName := "Doe"

	fixedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create mock time provider using mockery
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(fixedTime)

	// Act
	user := entity.NewUser(id, email, phoneNumber, firstName, lastName, mockTimeProvider)

	// Assert
	assert.Equal(t, id, user.ID, "User ID should match the provided ID")
	assert.Equal(t, email, user.Email, "Email should match the provided email")
	assert.Equal(t, phoneNumber, user.PhoneNumber, "PhoneNumber should match the provided phoneNumber")
	assert.Equal(t, firstName, user.FirstName, "FirstName should match the provided firstName")
	assert.Equal(t, lastName, user.LastName, "LastName should match the provided lastName")
	assert.True(t, user.IsActive, "New user should be active by default")
	assert.Equal(t, fixedTime, user.CreatedAt, "CreatedAt should match the current time")
	assert.Equal(t, fixedTime, user.UpdatedAt, "UpdatedAt should match the current time")

	mockTimeProvider.AssertExpectations(t)
}

func TestUser_SetPassword(t *testing.T) {
	// Arrange
	fixedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	initialTime := time.Date(2022, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create mock time provider using mockery
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(fixedTime)

	user := &entity.User{
		ID:        entity.ID("user-123"),
		CreatedAt: initialTime,
		UpdatedAt: initialTime,
	}

	hashedPassword := "hashed_password_123"

	// Act
	user.SetPassword(hashedPassword, mockTimeProvider)

	// Assert
	assert.Equal(t, hashedPassword, user.PasswordHash, "PasswordHash should be updated")
	assert.Equal(t, fixedTime, user.UpdatedAt, "UpdatedAt should be updated to current time")
	assert.Equal(t, initialTime, user.CreatedAt, "CreatedAt should remain unchanged")

	mockTimeProvider.AssertExpectations(t)
}
