package tests

import (
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	mocks "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	"github.com/stretchr/testify/assert"
)

func TestNewOTP(t *testing.T) {
	// Setup
	mockTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(mockTime)

	id := entity.ID("test-id")
	phoneNumber := "+989123456789"
	code := "123456"
	expirySeconds := 300

	// Execute
	otp := entity.NewOTP(id, phoneNumber, code, expirySeconds, mockTimeProvider)

	// Assert
	assert.Equal(t, id, otp.ID)
	assert.Equal(t, phoneNumber, otp.PhoneNumber)
	assert.Equal(t, code, otp.Code)
	assert.Equal(t, mockTime, otp.CreatedAt)
	assert.Equal(t, mockTime.Add(time.Duration(expirySeconds)*time.Second), otp.ExpiresAt)
	assert.False(t, otp.IsUsed)
	assert.Equal(t, 0, otp.AttemptCount)

	// Verify that the mock was called as expected
	mockTimeProvider.AssertExpectations(t)
}

func TestOTP_IsExpired(t *testing.T) {
	// Setup
	id := entity.ID("test-id")
	phoneNumber := "+989123456789"
	code := "123456"
	expirySeconds := 300

	// Case 1: Not expired
	creationTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(creationTime)
	otp := entity.NewOTP(id, phoneNumber, code, expirySeconds, mockTimeProvider)

	// Check 2 minutes later (should not be expired)
	checkTime := creationTime.Add(2 * time.Minute)
	checkMockProvider := new(mocks.MockProvider)
	checkMockProvider.On("Now").Return(checkTime)
	assert.False(t, otp.IsExpired(checkMockProvider))
	checkMockProvider.AssertExpectations(t)

	// Case 2: Expired
	// Check 6 minutes later (should be expired)
	expiredTime := creationTime.Add(6 * time.Minute)
	expiredMockProvider := new(mocks.MockProvider)
	expiredMockProvider.On("Now").Return(expiredTime)
	assert.True(t, otp.IsExpired(expiredMockProvider))
	expiredMockProvider.AssertExpectations(t)

	// Verify that the mock was called as expected
	mockTimeProvider.AssertExpectations(t)
}

func TestOTP_MarkAsUsed(t *testing.T) {
	// Setup
	currentTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(currentTime).Times(2)

	id := entity.ID("test-id")
	phoneNumber := "+989123456789"
	code := "123456"
	expirySeconds := 300

	// Execute
	otp := entity.NewOTP(id, phoneNumber, code, expirySeconds, mockTimeProvider)
	otp.MarkAsUsed(mockTimeProvider)

	// Assert
	assert.True(t, otp.IsUsed)
	assert.Equal(t, currentTime, otp.ExpiresAt) // Should have expired immediately

	// Verify that the mock was called as expected
	mockTimeProvider.AssertExpectations(t)
}

func TestOTP_IncrementAttempt(t *testing.T) {
	// Setup
	now := time.Now()
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(now)

	id := entity.ID("test-id")
	phoneNumber := "+989123456789"
	code := "123456"
	expirySeconds := 300

	// Execute
	otp := entity.NewOTP(id, phoneNumber, code, expirySeconds, mockTimeProvider)
	assert.Equal(t, 0, otp.AttemptCount)

	otp.IncrementAttempt()
	assert.Equal(t, 1, otp.AttemptCount)

	otp.IncrementAttempt()
	assert.Equal(t, 2, otp.AttemptCount)

	// Verify that the mock was called as expected
	mockTimeProvider.AssertExpectations(t)
}

func TestOTP_HasExceededMaxAttempts(t *testing.T) {
	// Setup
	now := time.Now()
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(now)

	id := entity.ID("test-id")
	phoneNumber := "+989123456789"
	code := "123456"
	expirySeconds := 300
	maxAttempts := 3

	// Execute
	otp := entity.NewOTP(id, phoneNumber, code, expirySeconds, mockTimeProvider)

	// Should not have exceeded yet
	assert.False(t, otp.HasExceededMaxAttempts(maxAttempts))

	otp.IncrementAttempt() // 1
	assert.False(t, otp.HasExceededMaxAttempts(maxAttempts))

	otp.IncrementAttempt() // 2
	assert.False(t, otp.HasExceededMaxAttempts(maxAttempts))

	otp.IncrementAttempt() // 3
	assert.True(t, otp.HasExceededMaxAttempts(maxAttempts))

	otp.IncrementAttempt() // 4
	assert.True(t, otp.HasExceededMaxAttempts(maxAttempts))

	// Verify that the mock was called as expected
	mockTimeProvider.AssertExpectations(t)
}

func TestOTP_Validate(t *testing.T) {
	// Setup
	currentTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	mockTimeProvider := new(mocks.MockProvider)
	mockTimeProvider.On("Now").Return(currentTime).Times(4)

	id := entity.ID("test-id")
	phoneNumber := "+989123456789"
	code := "123456"
	wrongCode := "654321"
	expirySeconds := 300
	maxAttempts := 3

	// Create OTP
	otp := entity.NewOTP(id, phoneNumber, code, expirySeconds, mockTimeProvider)

	// Test cases
	// 1. Valid code
	assert.True(t, otp.Validate(code, maxAttempts, mockTimeProvider))

	// 2. Invalid code
	assert.False(t, otp.Validate(wrongCode, maxAttempts, mockTimeProvider))

	// 3. Expired OTP
	expiredMockProvider := new(mocks.MockProvider)
	expiredTime := currentTime.Add(time.Duration(expirySeconds+10) * time.Second)
	expiredMockProvider.On("Now").Return(expiredTime)
	assert.False(t, otp.Validate(code, maxAttempts, expiredMockProvider))
	expiredMockProvider.AssertExpectations(t)

	// 4. Used OTP
	usedOtpMockProvider := new(mocks.MockProvider)
	usedOtpMockProvider.On("Now").Return(currentTime).Times(2)
	otpUsed := entity.NewOTP(id, phoneNumber, code, expirySeconds, usedOtpMockProvider)
	otpUsed.MarkAsUsed(usedOtpMockProvider)
	assert.False(t, otpUsed.Validate(code, maxAttempts, usedOtpMockProvider))
	usedOtpMockProvider.AssertExpectations(t)

	// 5. Exceeded max attempts
	otp.AttemptCount = maxAttempts
	assert.False(t, otp.Validate(code, maxAttempts, mockTimeProvider))

	// Verify that the mock was called as expected
	mockTimeProvider.AssertExpectations(t)
}
