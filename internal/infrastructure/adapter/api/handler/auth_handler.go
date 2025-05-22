package handler

import (
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/dto"
	apiErrors "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/errors"
	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication related requests
type AuthHandler struct {
	registerUseCase     *auth.RegisterUseCase
	loginUseCase        *auth.LoginUseCase
	logoutUseCase       *auth.LogoutUseCase
	logoutAllUseCase    *auth.LogoutAllUseCase
	logoutOtherUseCase  *auth.LogoutOtherSessionsUseCase
	refreshTokenUseCase *auth.RefreshTokenUseCase
}

// NewAuthHandler creates a new instance of AuthHandler
func NewAuthHandler(
	registerUseCase *auth.RegisterUseCase,
	loginUseCase *auth.LoginUseCase,
	logoutUseCase *auth.LogoutUseCase,
	logoutAllUseCase *auth.LogoutAllUseCase,
	logoutOtherUseCase *auth.LogoutOtherSessionsUseCase,
	refreshTokenUseCase *auth.RefreshTokenUseCase,
) *AuthHandler {
	return &AuthHandler{
		registerUseCase:     registerUseCase,
		loginUseCase:        loginUseCase,
		logoutUseCase:       logoutUseCase,
		logoutAllUseCase:    logoutAllUseCase,
		logoutOtherUseCase:  logoutOtherUseCase,
		refreshTokenUseCase: refreshTokenUseCase,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Create a proper validation error using the domain function
		validationErr := domainErr.NewValidationError("request", "Invalid request format")
		status, errResponse := apiErrors.HTTPError(validationErr)
		c.JSON(status, errResponse)
		return
	}

	input := auth.RegisterInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		UserAgent: c.GetHeader("User-Agent"),
		IP:        c.ClientIP(),
	}

	result, err := h.registerUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusCreated, dto.RegisterResponse{
		UserID:       result.User.ID.String(),
		Email:        result.User.Email,
		FirstName:    result.User.FirstName,
		LastName:     result.User.LastName,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiErrors.ErrorResponse{
			Error: "Invalid request format",
			Code:  "invalid_request",
		})
		return
	}

	input := auth.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: c.GetHeader("User-Agent"),
		IP:        c.ClientIP(),
	}

	result, err := h.loginUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, dto.LoginResponse{
		UserID:       result.User.ID.String(),
		Email:        result.User.Email,
		FirstName:    result.User.FirstName,
		LastName:     result.User.LastName,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
	})
}

// RefreshToken handles refresh token requests
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiErrors.ErrorResponse{
			Error: "Invalid request format",
			Code:  "invalid_request",
		})
		return
	}

	input := auth.RefreshTokenInput{
		RefreshToken: req.RefreshToken,
		UserAgent:    c.GetHeader("User-Agent"),
		IP:           c.ClientIP(),
	}

	result, err := h.refreshTokenUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, dto.RefreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get refresh token from authorization header or request body
	var req dto.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// If JSON binding fails, check for query param
		refreshToken := c.Query("refresh_token")
		if refreshToken == "" {
			c.JSON(http.StatusBadRequest, apiErrors.ErrorResponse{
				Error: "Refresh token is required",
				Code:  "missing_refresh_token",
			})
			return
		}
		req.RefreshToken = refreshToken
	}

	// LogoutInput only requires the refresh token, not the user ID
	input := auth.LogoutInput{
		RefreshToken: req.RefreshToken,
	}

	if err := h.logoutUseCase.Execute(c.Request.Context(), input); err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// LogoutAll handles logging out all user sessions
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		// Create proper authorization error using the domain function
		err := domainErr.NewAuthorizationError("session", "logout", "User not authenticated")
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	// Convert userID from entity.ID to string for the use case
	input := auth.LogoutAllInput{
		UserID: userID.(entity.ID).String(),
	}

	if err := h.logoutAllUseCase.Execute(c.Request.Context(), input); err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out from all devices"})
}

// LogoutOtherSessions handles logging out all sessions except the current one
func (h *AuthHandler) LogoutOtherSessions(c *gin.Context) {
	var req dto.LogoutOtherRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// If JSON binding fails, check for query param
		refreshToken := c.Query("current_refresh_token")
		if refreshToken == "" {
			c.JSON(http.StatusBadRequest, apiErrors.ErrorResponse{
				Error: "Current refresh token is required",
				Code:  "missing_refresh_token",
			})
			return
		}
		req.CurrentRefreshToken = refreshToken
	}

	// LogoutOtherSessionsInput requires the refresh token, not the user ID
	input := auth.LogoutOtherSessionsInput{
		RefreshToken: req.CurrentRefreshToken,
		UserAgent:    c.GetHeader("User-Agent"),
		IP:           c.ClientIP(),
	}

	if err := h.logoutOtherUseCase.Execute(c.Request.Context(), input); err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out from other devices"})
}
