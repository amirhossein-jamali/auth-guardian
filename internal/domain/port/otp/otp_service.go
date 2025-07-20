package otp

import "context"

// OTPService defines interface for OTP generation and sending
type OTPService interface {
	// Generate generates a new OTP code with the specified length
	Generate(length int) string
	// Send sends an OTP code to the specified phone number
	Send(ctx context.Context, phoneNumber, code string) error
}
