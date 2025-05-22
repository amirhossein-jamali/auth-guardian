package dto

// UserResponse represents the user data returned in API responses
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IsActive  bool   `json:"is_active"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// UpdateUserRequest represents the data needed for updating a user profile
type UpdateUserRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}
