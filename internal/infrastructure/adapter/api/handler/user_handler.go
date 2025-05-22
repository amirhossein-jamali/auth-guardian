package handler

import (
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/user"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/dto"
	apiErrors "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/errors"
	"github.com/gin-gonic/gin"
)

// UserHandler handles user related requests
type UserHandler struct {
	getUserUseCase       *user.GetUserUseCase
	updateProfileUseCase *user.UpdateProfileUseCase
}

// NewUserHandler creates a new instance of UserHandler
func NewUserHandler(
	getUserUseCase *user.GetUserUseCase,
	updateProfileUseCase *user.UpdateProfileUseCase,
) *UserHandler {
	return &UserHandler{
		getUserUseCase:       getUserUseCase,
		updateProfileUseCase: updateProfileUseCase,
	}
}

// GetCurrentUser returns the current user's profile
func (h *UserHandler) GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, apiErrors.ErrorResponse{
			Error: "User not authenticated",
			Code:  "unauthorized",
		})
		return
	}

	input := user.GetUserInput{
		UserID: userID.(entity.ID).String(),
	}

	result, err := h.getUserUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, dto.UserResponse{
		ID:        result.User.ID.String(),
		Email:     result.User.Email,
		FirstName: result.User.FirstName,
		LastName:  result.User.LastName,
		IsActive:  result.User.IsActive,
		CreatedAt: result.User.CreatedAt.Unix(),
		UpdatedAt: result.User.UpdatedAt.Unix(),
	})
}

// UpdateCurrentUser updates the current user's profile
func (h *UserHandler) UpdateCurrentUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, apiErrors.ErrorResponse{
			Error: "User not authenticated",
			Code:  "unauthorized",
		})
		return
	}

	var req dto.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiErrors.ErrorResponse{
			Error: "Invalid request format",
			Code:  "invalid_request",
		})
		return
	}

	input := user.UpdateProfileInput{
		UserID: userID.(entity.ID).String(),
		IP:     c.ClientIP(),
	}

	// Only include fields that are provided in the request
	if req.FirstName != "" {
		input.FirstName = req.FirstName
	}

	if req.LastName != "" {
		input.LastName = req.LastName
	}

	if req.Email != "" {
		input.Email = req.Email
	}

	result, err := h.updateProfileUseCase.Execute(c.Request.Context(), input)
	if err != nil {
		status, errResponse := apiErrors.HTTPError(err)
		c.JSON(status, errResponse)
		return
	}

	c.JSON(http.StatusOK, dto.UserResponse{
		ID:        result.User.ID.String(),
		Email:     result.User.Email,
		FirstName: result.User.FirstName,
		LastName:  result.User.LastName,
		IsActive:  result.User.IsActive,
		CreatedAt: result.User.CreatedAt.Unix(),
		UpdatedAt: result.User.UpdatedAt.Unix(),
	})
}
