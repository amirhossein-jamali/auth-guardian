package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/user"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/dto"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/handler"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	// Import mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
)

// setupUserRouter creates a test router with the user handler
func setupUserRouter(userHandler *handler.UserHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Setup routes similar to the actual application
	api := router.Group("/api")
	{
		// Add auth middleware mock to set userID in context
		userGroup := api.Group("/user")
		userGroup.Use(func(c *gin.Context) {
			// This middleware sets a userID in the context to simulate authentication
			c.Set("userID", entity.NewID("123e4567-e89b-12d3-a456-426614174000"))
			c.Next()
		})
		{
			userGroup.GET("/profile", userHandler.GetCurrentUser)
			userGroup.PUT("/profile", userHandler.UpdateCurrentUser)
		}
	}

	return router
}

// setupUserTest creates all necessary mocks and components for testing user handler
func setupUserTest(t *testing.T) (
	*gin.Engine,
	*handler.UserHandler,
	*mockRepo.MockUserRepository,
	*mockTime.MockTimeProvider,
	*mockLogger.MockLogger,
	*mockLogger.MockAuditLogger,
) {
	// Create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)
	auditLogger := mockLogger.NewMockAuditLogger(t)

	// Setup default behavior for logger to avoid unnecessary mocking
	logger.EXPECT().Debug(mock.Anything, mock.Anything).Maybe().Return()
	logger.EXPECT().Info(mock.Anything, mock.Anything).Maybe().Return()
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Maybe().Return()
	logger.EXPECT().Error(mock.Anything, mock.Anything).Maybe().Return()

	// Setup audit logger default behavior
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)

	// Setup time provider default behavior - more lenient
	now := time.Now()
	timeProvider.EXPECT().Now().Maybe().Return(now)
	timeProvider.EXPECT().Since(mock.Anything).Maybe().Return(100 * time.Millisecond)

	// Create use cases
	getUserUseCase := user.NewGetUserUseCase(
		userRepo,
		logger,
		timeProvider,
	)

	updateProfileUseCase := user.NewUpdateProfileUseCase(
		userRepo,
		timeProvider,
		logger,
		auditLogger,
	)

	// Create User handler
	userHandler := handler.NewUserHandler(
		getUserUseCase,
		updateProfileUseCase,
	)

	// Create router with user handler
	router := setupUserRouter(userHandler)

	return router, userHandler, userRepo, timeProvider, logger, auditLogger
}

// Helper function to make HTTP requests specific for user handler tests
func performUserRequest(router *gin.Engine, method, path string, body interface{}) (*httptest.ResponseRecorder, error) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w, nil
}

// Tests for GetCurrentUser endpoint
func TestGetCurrentUser(t *testing.T) {
	// Arrange
	router, _, userRepo, _, _, _ := setupUserTest(t)
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()

	// Create mock user
	mockUser := &entity.User{
		ID:        entity.NewID(userID),
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Setup expectations - just mock the GetByID call
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(mockUser, nil)

	// Act
	w, err := performUserRequest(router, "GET", "/api/user/profile", nil)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	var response dto.UserResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, userID, response.ID)
	assert.Equal(t, "test@example.com", response.Email)
	assert.Equal(t, "John", response.FirstName)
	assert.Equal(t, "Doe", response.LastName)
	assert.True(t, response.IsActive)
}

func TestGetCurrentUser_UserNotFound(t *testing.T) {
	// Arrange
	router, _, userRepo, _, _, _ := setupUserTest(t)
	userID := "123e4567-e89b-12d3-a456-426614174000"

	// Setup expectations - just mock the GetByID call
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(nil, nil)

	// Act
	w, err := performUserRequest(router, "GET", "/api/user/profile", nil)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, w.Code)

	var errResponse map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &errResponse)
	require.NoError(t, err)
	assert.Equal(t, "user_not_found", errResponse["code"])
}

// Tests for UpdateCurrentUser endpoint
func TestUpdateCurrentUser(t *testing.T) {
	// Arrange
	router, _, userRepo, _, _, _ := setupUserTest(t)
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()

	// Create mock user (before update)
	currentUser := &entity.User{
		ID:        entity.NewID(userID),
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: now.Add(-24 * time.Hour), // Created yesterday
		UpdatedAt: now.Add(-24 * time.Hour),
	}

	// Request body
	updateRequest := dto.UpdateUserRequest{
		Email:     "newemail@example.com",
		FirstName: "Jane",
		LastName:  "Smith",
	}

	// Setup minimal expectations
	// Get user by ID
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(currentUser, nil)

	// Check if email exists
	userRepo.EXPECT().EmailExists(mock.Anything, "newemail@example.com").Return(false, nil)

	// Update user - use a simpler matcher
	userRepo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)

	// Act
	w, err := performUserRequest(router, "PUT", "/api/user/profile", updateRequest)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	var response dto.UserResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, userID, response.ID)
	assert.Equal(t, "newemail@example.com", response.Email)
	assert.Equal(t, "Jane", response.FirstName)
	assert.Equal(t, "Smith", response.LastName)
	assert.True(t, response.IsActive)
}

func TestUpdateCurrentUser_InvalidRequest(t *testing.T) {
	// Arrange
	router, _, _, _, _, _ := setupUserTest(t)

	// Act - send an invalid JSON
	req, _ := http.NewRequest("PUT", "/api/user/profile", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateCurrentUser_EmailAlreadyExists(t *testing.T) {
	// Arrange
	router, _, userRepo, _, _, _ := setupUserTest(t)
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()

	// Create mock user
	currentUser := &entity.User{
		ID:        entity.NewID(userID),
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Request body with just email update
	updateRequest := dto.UpdateUserRequest{
		Email: "existing@example.com",
	}

	// Minimal mocks
	// Get user by ID
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(currentUser, nil)

	// Email exists check returns true - already taken
	userRepo.EXPECT().EmailExists(mock.Anything, "existing@example.com").Return(true, nil)

	// Act
	w, err := performUserRequest(router, "PUT", "/api/user/profile", updateRequest)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, w.Code) // The actual status code from the handler is 400

	var errResponse map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &errResponse)
	require.NoError(t, err)
	assert.Equal(t, "email_exists", errResponse["code"]) // The actual error code from the handler
}

func TestUpdateCurrentUser_NoChanges(t *testing.T) {
	// Arrange
	router, _, userRepo, _, _, _ := setupUserTest(t)
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()

	// Create mock user
	currentUser := &entity.User{
		ID:        entity.NewID(userID),
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Request body with same values as current user
	updateRequest := dto.UpdateUserRequest{
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
	}

	// Minimal mocks
	// Get user by ID
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(currentUser, nil)

	// Act
	w, err := performUserRequest(router, "PUT", "/api/user/profile", updateRequest)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	var response dto.UserResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, userID, response.ID)
	assert.Equal(t, "test@example.com", response.Email)
	assert.Equal(t, "John", response.FirstName)
	assert.Equal(t, "Doe", response.LastName)
}
