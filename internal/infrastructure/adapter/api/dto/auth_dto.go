package dto

// RegisterRequest represents the data needed for user registration
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// RegisterResponse represents the response data after successful registration
type RegisterResponse struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LoginRequest represents the data needed for user login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the response data after successful login
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
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshTokenResponse represents the response data after successful token refresh
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LogoutRequest represents the data needed for logout
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutOtherRequest represents the data needed for logging out other sessions
type LogoutOtherRequest struct {
	CurrentRefreshToken string `json:"current_refresh_token" binding:"required"`
}
