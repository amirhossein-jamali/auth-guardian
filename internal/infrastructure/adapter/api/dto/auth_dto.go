package dto

// RegisterRequest represents the data needed for user registration
// swagger:model
type RegisterRequest struct {
	Email       string `json:"email" binding:"omitempty,email"` // Email is now optional
	Password    string `json:"password" binding:"required,min=8"`
	FirstName   string `json:"first_name" binding:"required"`
	LastName    string `json:"last_name" binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required"` // Phone number is now required
	OTPCode     string `json:"otp_code" binding:"required"`     // OTP code is required
}

// RegisterWithOTPRequest represents data for combined OTP verification and registration
// swagger:model
type RegisterWithOTPRequest struct {
	Email       string `json:"email" binding:"omitempty,email"` // Email is optional
	Password    string `json:"password" binding:"required,min=8"`
	FirstName   string `json:"first_name" binding:"required"`
	LastName    string `json:"last_name" binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required"`
	Code        string `json:"code" binding:"required"` // OTP code to verify
}

// RegisterResponse represents the response data after successful registration
// swagger:model
type RegisterResponse struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	PhoneNumber  string `json:"phone_number"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LoginRequest represents the data needed for user login
// swagger:model
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the response data after successful login
// swagger:model
type LoginResponse struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// RefreshTokenRequest represents the data needed for token refresh
// swagger:model
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshTokenResponse represents the response data after successful token refresh
// swagger:model
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LogoutRequest represents the data needed for logout
// swagger:model
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutOtherRequest represents the data needed for logging out other sessions
// swagger:model
type LogoutOtherRequest struct {
	CurrentRefreshToken string `json:"current_refresh_token" binding:"required"`
}

// RequestOTPRequest represents the data needed for requesting an OTP
// swagger:model
type RequestOTPRequest struct {
	PhoneNumber string `json:"phone_number" binding:"required"`
}

// RequestOTPResponse represents the response data after successful OTP request
// swagger:model
type RequestOTPResponse struct {
	ExpiresIn int    `json:"expires_in"` // seconds until expiry
	Message   string `json:"message"`
}

// VerifyOTPRequest represents the data needed for verifying an OTP
// swagger:model
type VerifyOTPRequest struct {
	PhoneNumber string `json:"phone_number" binding:"required"`
	Code        string `json:"code" binding:"required"`
}

// VerifyOTPResponse represents the response data after successful OTP verification
// swagger:model
type VerifyOTPResponse struct {
	UserID       string `json:"user_id"`
	PhoneNumber  string `json:"phone_number"`
	IsNewUser    bool   `json:"is_new_user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}
