package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
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
	requestOTPUseCase   *auth.RequestOTPUseCase
	verifyOTPUseCase    *auth.VerifyOTPUseCase

	// Direct dependencies instead of reflection
	otpRepo      repository.OTPRepository
	timeProvider tport.Provider
}

// NewAuthHandler creates a new instance of AuthHandler
func NewAuthHandler(
	registerUseCase *auth.RegisterUseCase,
	loginUseCase *auth.LoginUseCase,
	logoutUseCase *auth.LogoutUseCase,
	logoutAllUseCase *auth.LogoutAllUseCase,
	logoutOtherUseCase *auth.LogoutOtherSessionsUseCase,
	refreshTokenUseCase *auth.RefreshTokenUseCase,
	requestOTPUseCase *auth.RequestOTPUseCase,
	verifyOTPUseCase *auth.VerifyOTPUseCase,
	otpRepo repository.OTPRepository,
	timeProvider tport.Provider,
) *AuthHandler {
	return &AuthHandler{
		registerUseCase:     registerUseCase,
		loginUseCase:        loginUseCase,
		logoutUseCase:       logoutUseCase,
		logoutAllUseCase:    logoutAllUseCase,
		logoutOtherUseCase:  logoutOtherUseCase,
		refreshTokenUseCase: refreshTokenUseCase,
		requestOTPUseCase:   requestOTPUseCase,
		verifyOTPUseCase:    verifyOTPUseCase,
		otpRepo:             otpRepo,
		timeProvider:        timeProvider,
	}
}

// Register handles user registration
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterRequest true "User registration data"
// @Success 201 {object} dto.RegisterResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 409 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Create a proper validation errors using the domain function
		validationErr := domainErr.NewValidationError("request", "Invalid request format")
		status, errResponse := apiErrors.HTTPError(validationErr)
		c.JSON(status, errResponse)
		return
	}

	input := auth.RegisterInput{
		Email:       req.Email,
		Password:    req.Password,
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		UserAgent:   c.GetHeader("User-Agent"),
		IP:          c.ClientIP(),
		PhoneNumber: req.PhoneNumber,
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
		PhoneNumber:  result.User.PhoneNumber,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
	})
}

// Login handles user authentication
// @Summary User login
// @Description Authenticate a user and receive access and refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "User login credentials"
// @Success 200 {object} dto.LoginResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/login [post]
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
// @Summary Refresh access token
// @Description Get a new access token using a valid refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} dto.RefreshTokenResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/refresh [post]
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
// @Summary Logout user
// @Description Invalidate the current user session
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LogoutRequest true "Logout request with refresh token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/logout [post]
// @Security ApiKeyAuth
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
// @Summary Logout from all devices
// @Description Invalidate all active sessions for the current user
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/logout-all [post]
// @Security ApiKeyAuth
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		// Create proper authorization errors using the domain function
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
// @Summary Logout from other devices
// @Description Invalidate all sessions except the current one
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LogoutOtherRequest true "Current session refresh token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/logout-others [post]
// @Security ApiKeyAuth
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

// RequestOTP handles OTP request generation
// @Summary Request OTP
// @Description Request a one-time password for authentication
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RequestOTPRequest true "Email address for OTP"
// @Success 200 {object} dto.RequestOTPResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 429 {object} errors.ErrorResponse "Too many requests"
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/request-otp [post]
func (h *AuthHandler) RequestOTP(c *gin.Context) {
	var req dto.RequestOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErr := domainErr.NewValidationError("request", "Invalid request format")
		status, errResponse := apiErrors.HTTPError(validationErr)
		c.JSON(status, errResponse)
		return
	}

	input := auth.RequestOTPInput{
		PhoneNumber: req.PhoneNumber,
		IP:          c.ClientIP(),
	}

	result, err := h.requestOTPUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, dto.RequestOTPResponse{
		ExpiresIn: result.ExpiresIn,
		Message:   result.Message,
	})
}

// VerifyOTP handles OTP verification
// @Summary Verify OTP
// @Description Verify a one-time password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.VerifyOTPRequest true "OTP verification data"
// @Success 200 {object} dto.VerifyOTPResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse "Invalid OTP"
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/verify-otp [post]
func (h *AuthHandler) VerifyOTP(c *gin.Context) {
	var req dto.VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErr := domainErr.NewValidationError("request", "Invalid request format")
		status, errResponse := apiErrors.HTTPError(validationErr)
		c.JSON(status, errResponse)
		return
	}

	input := auth.VerifyOTPInput{
		PhoneNumber: req.PhoneNumber,
		Code:        req.Code,
		UserAgent:   c.GetHeader("User-Agent"),
		IP:          c.ClientIP(),
	}

	result, err := h.verifyOTPUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, dto.VerifyOTPResponse{
		UserID:       result.User.ID.String(),
		PhoneNumber:  result.User.PhoneNumber,
		IsNewUser:    result.IsNewUser,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
	})
}

// RegisterWithOTP handles registration with OTP verification
// @Summary Register with OTP
// @Description Register a new user with OTP verification
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterWithOTPRequest true "Registration data with OTP"
// @Success 201 {object} dto.RegisterResponse
// @Failure 400 {object} errors.ErrorResponse
// @Failure 401 {object} errors.ErrorResponse "Invalid OTP"
// @Failure 409 {object} errors.ErrorResponse "User already exists"
// @Failure 500 {object} errors.ErrorResponse
// @Router /auth/register-with-otp [post]
func (h *AuthHandler) RegisterWithOTP(c *gin.Context) {
	// Add panic recovery to prevent server crashes
	defer func() {
		if r := recover(); r != nil {
			c.Set("log_error", map[string]any{
				"stage": "registration",
				"error": fmt.Sprintf("Panic recovered: %v", r),
			})
			c.JSON(http.StatusInternalServerError, gin.H{"errors": "Internal server error", "code": "server_error"})
		}
	}()

	var req dto.RegisterWithOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Create a proper validation errors using the domain function
		validationErr := domainErr.NewValidationError("request", "Invalid request format")
		status, errResponse := apiErrors.HTTPError(validationErr)
		c.JSON(status, errResponse)
		return
	}

	// Log the incoming request (without sensitive data)
	c.Set("log_info", map[string]any{
		"handler": "RegisterWithOTP",
		"phone":   req.PhoneNumber,
		"email":   req.Email,
	})

	// Step 1: Verify OTP directly from the OTP repository instead of using verifyOTPUseCase
	// This avoids creating a user during OTP verification
	if h.otpRepo == nil {
		c.Set("log_error", map[string]any{
			"stage": "OTP verification",
			"error": "OTP repository is not initialized",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"errors": "Internal server error", "code": "server_error"})
		return
	}

	// Get the OTP record
	otp, err := h.otpRepo.GetByPhoneNumber(c.Request.Context(), req.PhoneNumber)
	if err != nil {
		c.Set("log_error", map[string]any{
			"stage": "OTP verification",
			"error": "Failed to get OTP: " + err.Error(),
		})
		status, errResponse := apiErrors.HTTPError(domainErr.ErrInvalidOTP)
		c.JSON(status, errResponse)
		return
	}

	if h.timeProvider == nil {
		c.Set("log_error", map[string]any{
			"stage": "OTP verification",
			"error": "Time provider is not initialized",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"errors": "Internal server error", "code": "server_error"})
		return
	}

	// Validate OTP
	maxAttempts := 3 // Default max attempts
	if !otp.Validate(req.Code, maxAttempts, h.timeProvider) {
		// Update attempt count
		otp.IncrementAttempt()
		if updateErr := h.otpRepo.Update(c.Request.Context(), otp); updateErr != nil {
			c.Set("log_error", map[string]any{
				"stage": "OTP verification",
				"error": "Failed to update OTP attempts: " + updateErr.Error(),
			})
			// Continue anyway as this is not critical
		}

		var errToReturn error
		if otp.IsExpired(h.timeProvider) {
			errToReturn = domainErr.ErrExpiredOTP
		} else if otp.IsUsed {
			errToReturn = domainErr.ErrUsedOTP
		} else if otp.HasExceededMaxAttempts(maxAttempts) {
			errToReturn = domainErr.ErrMaxAttemptsExceeded
		} else {
			errToReturn = domainErr.ErrInvalidOTP
		}

		status, errResponse := apiErrors.HTTPError(errToReturn)
		c.JSON(status, errResponse)
		return
	}

	// Mark OTP as used
	otp.MarkAsUsed(h.timeProvider)
	if err := h.otpRepo.Update(c.Request.Context(), otp); err != nil {
		c.Set("log_error", map[string]any{
			"stage": "OTP verification",
			"error": "Failed to mark OTP as used: " + err.Error(),
		})
		// Continue anyway as this is not critical
	}

	// Step 2: If OTP is valid, proceed with registration
	registerInput := auth.RegisterInput{
		Email:             req.Email,
		Password:          req.Password,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		UserAgent:         c.GetHeader("User-Agent"),
		IP:                c.ClientIP(),
		PhoneNumber:       req.PhoneNumber,
		SkipOTPValidation: true, // Skip OTP validation in register use case since we've already validated it
		OTPCode:           req.Code,
	}

	registerResult, err := h.registerUseCase.Execute(c.Request.Context(), registerInput)
	if err != nil {
		// Add specific error handling for common errors
		errStr := err.Error()
		errType := "unknown"

		if errors.Is(err, domainErr.ErrEmailAlreadyExists) {
			errType = "email_exists"
		} else if domainErr.IsValidationError(err) {
			errType = "validation"
		}

		// Add more detail to the log
		c.Set("log_error", map[string]any{
			"stage": "registration",
			"error": errStr,
			"type":  errType,
		})

		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusCreated, dto.RegisterResponse{
		UserID:       registerResult.User.ID.String(),
		Email:        registerResult.User.Email,
		FirstName:    registerResult.User.FirstName,
		LastName:     registerResult.User.LastName,
		PhoneNumber:  registerResult.User.PhoneNumber,
		AccessToken:  registerResult.AccessToken,
		RefreshToken: registerResult.RefreshToken,
		ExpiresAt:    registerResult.ExpiresAt,
	})
}
