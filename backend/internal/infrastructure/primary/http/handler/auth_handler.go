package handler

import (
	"errors"
	"net/http"

	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/service"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	authService *service.AuthService
	logger      logger.Logger
}

// NewAuthHandler creates a new instance of AuthHandler
func NewAuthHandler(authService *service.AuthService, logger logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

// RegisterRequest represents the user registration payload
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

// Register handles user registration requests
func (h *AuthHandler) Register(c *gin.Context) {
	var input RegisterRequest

	// Parse and validate request body
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Warn("Invalid registration request", model.NewField("error", err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Processing registration request", model.NewField("email", input.Email))

	// Call domain service
	result, err := h.authService.Register(c.Request.Context(), service.RegisterInput{
		Email:     input.Email,
		Password:  input.Password,
		FirstName: input.FirstName,
		LastName:  input.LastName,
	})

	// Handle errors
	if err != nil {
		statusCode := http.StatusInternalServerError
		errorMsg := "Registration failed"

		// Map domain errors to appropriate HTTP status codes
		if errors.Is(err, domainError.ErrEmailAlreadyExists) {
			statusCode = http.StatusConflict
			errorMsg = err.Error()
		} else if errors.Is(err, domainError.ErrInvalidCredentials) {
			statusCode = http.StatusBadRequest
			errorMsg = err.Error()
		}

		h.logger.Error("Registration failed",
			model.NewField("email", input.Email),
			model.NewField("error", err.Error()))
		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	h.logger.Info("User registered successfully",
		model.NewField("userId", result.User.ID.String()),
		model.NewField("email", result.User.Email.Value()))

	// Return success response
	c.JSON(http.StatusCreated, gin.H{
		"user": result.User,
		"tokens": gin.H{
			"access_token":  result.TokenPair.AccessToken,
			"refresh_token": result.TokenPair.RefreshToken,
		},
	})
}

// LoginRequest represents the user login payload
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login handles user login requests
func (h *AuthHandler) Login(c *gin.Context) {
	var input LoginRequest

	// Parse and validate request body
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Warn("Invalid login request", model.NewField("error", err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Processing login request", model.NewField("email", input.Email))

	// Call domain service
	result, err := h.authService.Login(c.Request.Context(), service.LoginInput{
		Email:    input.Email,
		Password: input.Password,
	})

	// Handle errors
	if err != nil {
		statusCode := http.StatusUnauthorized
		errorMsg := "Invalid credentials"

		if !errors.Is(err, domainError.ErrInvalidCredentials) {
			h.logger.Error("Login failed with unexpected error",
				model.NewField("email", input.Email),
				model.NewField("error", err.Error()))
		} else {
			h.logger.Warn("Login attempt with invalid credentials",
				model.NewField("email", input.Email))
		}

		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	h.logger.Info("User logged in successfully",
		model.NewField("userId", result.User.ID.String()),
		model.NewField("email", result.User.Email.Value()))

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"user": result.User,
		"tokens": gin.H{
			"access_token":  result.TokenPair.AccessToken,
			"refresh_token": result.TokenPair.RefreshToken,
		},
	})
}

// RefreshTokenRequest represents the token refresh payload
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshToken handles token refresh requests
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var input RefreshTokenRequest

	// Parse and validate request body
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Warn("Invalid refresh token request", model.NewField("error", err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Debug("Processing token refresh request")

	// Call domain service
	result, err := h.authService.RefreshToken(c.Request.Context(), service.RefreshTokenInput{
		RefreshToken: input.RefreshToken,
	})

	// Handle errors
	if err != nil {
		statusCode := http.StatusUnauthorized
		errorMsg := "Invalid or expired token"

		// Map domain errors to appropriate HTTP status codes
		if errors.Is(err, domainError.ErrSessionExpired) {
			errorMsg = "Session has expired, please login again"
		} else if errors.Is(err, domainError.ErrInternalServer) {
			statusCode = http.StatusInternalServerError
			errorMsg = "Failed to refresh token"
		}

		h.logger.Warn("Token refresh failed", model.NewField("error", err.Error()))
		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	h.logger.Info("Token refreshed successfully")

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"tokens": gin.H{
			"access_token":  result.TokenPair.AccessToken,
			"refresh_token": result.TokenPair.RefreshToken,
		},
	})
}

// LogoutRequest represents the logout payload
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Logout handles user logout requests
func (h *AuthHandler) Logout(c *gin.Context) {
	var input LogoutRequest

	// Parse and validate request body
	if err := c.ShouldBindJSON(&input); err != nil {
		h.logger.Warn("Invalid logout request", model.NewField("error", err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Extract access token from Authorization header
	token := extractBearerToken(c.GetHeader("Authorization"))

	// Get authenticated user ID for logging
	userID, _ := getUserIDFromContext(c)
	logFields := []model.Field{model.NewField("action", "logout")}
	if userID != "" {
		logFields = append(logFields, model.NewField("userId", userID))
	}

	h.logger.Info("Processing logout request", logFields...)

	// Call domain service
	err := h.authService.Logout(c.Request.Context(), service.LogoutInput{
		AccessToken:  token,
		RefreshToken: input.RefreshToken,
	})

	// Handle errors
	if err != nil {
		h.logger.Error("Logout failed", append(logFields, model.NewField("error", err.Error()))...)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	h.logger.Info("User logged out successfully", logFields...)

	// Return success response
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// GetSessions returns all active sessions for the current user
func (h *AuthHandler) GetSessions(c *gin.Context) {
	// Get user ID from context
	userID, ok := getUserIDFromContext(c)
	if !ok {
		h.logger.Warn("Attempt to access GetSessions without authorization")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	h.logger.Info("Fetching user sessions", model.NewField("userId", userID))

	// Call domain service
	sessions, err := h.authService.GetActiveSessions(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to fetch user sessions",
			model.NewField("userId", userID),
			model.NewField("error", err.Error()))

		statusCode := http.StatusInternalServerError
		errorMsg := "Failed to retrieve sessions"

		// Map domain errors to appropriate HTTP status codes
		if errors.Is(err, domainError.ErrInvalidID) {
			statusCode = http.StatusBadRequest
			errorMsg = err.Error()
		}

		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	h.logger.Info("Sessions retrieved successfully",
		model.NewField("userId", userID),
		model.NewField("sessionCount", len(sessions)))

	// Return success response
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// LogoutAll logs out the user from all devices
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	// Get user ID from context
	userID, ok := getUserIDFromContext(c)
	if !ok {
		h.logger.Warn("Attempt to access LogoutAll without authorization")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	h.logger.Info("Attempting to logout user from all devices", model.NewField("userId", userID))

	// Call domain service
	err := h.authService.LogoutAll(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to logout from all devices",
			model.NewField("userId", userID),
			model.NewField("error", err.Error()))

		statusCode := http.StatusInternalServerError
		errorMsg := "Failed to logout from all devices"

		// Map domain errors to appropriate HTTP status codes
		if errors.Is(err, domainError.ErrInvalidID) {
			statusCode = http.StatusBadRequest
			errorMsg = err.Error()
		}

		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	h.logger.Info("User logged out from all devices", model.NewField("userId", userID))

	// Return success response
	c.JSON(http.StatusOK, gin.H{"message": "Logged out from all devices successfully"})
}

// getUserIDFromContext safely extracts the user ID from the Gin context
func getUserIDFromContext(c *gin.Context) (string, bool) {
	userID, exists := c.Get("userID")
	if !exists {
		return "", false
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return "", false
	}

	return userIDStr, true
}

// extractBearerToken safely extracts the token from the Authorization header
func extractBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	return ""
}
