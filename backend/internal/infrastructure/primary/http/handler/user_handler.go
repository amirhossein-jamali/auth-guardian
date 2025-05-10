package handler

import (
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/service"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	authService *service.AuthService
	logger      logger.Logger
}

func NewUserHandler(authService *service.AuthService, logger logger.Logger) *UserHandler {
	return &UserHandler{
		authService: authService,
		logger:      logger,
	}
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	// User should come from the auth middleware in context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.authService.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	// User ID should come from the auth middleware in context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var input struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Implement update profile logic in AuthService if needed
	// For now, we'll assume it exists
	user, err := h.authService.UpdateUserProfile(c.Request.Context(), userID.(string), input.FirstName, input.LastName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}
