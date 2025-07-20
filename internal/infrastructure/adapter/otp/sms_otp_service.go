package otp

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/otp"
)

// SMSOTPService implements OTPService for sending OTP via SMS
type SMSOTPService struct {
	provider string
	apiKey   string
}

// NewSMSOTPService creates a new SMS-based OTP service
func NewSMSOTPService(provider string) otp.OTPService {
	return &SMSOTPService{
		provider: provider,
	}
}

// Generate generates a new OTP code with the specified length
func (s *SMSOTPService) Generate(length int) string {
	const digits = "0123456789"
	result := make([]byte, length)
	
	for i := 0; i < length; i++ {
		// Generate cryptographically secure random number
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			// In case of error, fallback to less secure but functional method
			result[i] = digits[int(time.Now().UnixNano()%int64(len(digits)))]
			continue
		}
		
		// Use the random number to select a digit
		result[i] = digits[num.Int64()]
	}
	
	return string(result)
}

// Send sends an OTP code to the specified phone number
func (s *SMSOTPService) Send(ctx context.Context, phoneNumber, code string) error {
	// For now, this is a placeholder implementation
	// In a real application, this would integrate with an SMS provider API
	
	// If provider is set to "mock", just log instead of sending
	if s.provider == "mock" {
		fmt.Printf("MOCK SMS: Sending OTP %s to %s\n", code, phoneNumber)
		return nil
	}
	
	// For demonstration purposes, we'll just return success
	// In a real implementation, we would:
	// 1. Format the message
	// 2. Call the SMS provider API
	// 3. Handle errors and retries
	fmt.Printf("Sending OTP %s to %s via %s\n", code, phoneNumber, s.provider)
	
	return nil
} 