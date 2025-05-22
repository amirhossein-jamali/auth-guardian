package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/dto"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/handler"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	// Import mocks
	mockIdGen "github.com/amirhossein-jamali/auth-guardian/mocks/port/idgenerator"
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockMetrics "github.com/amirhossein-jamali/auth-guardian/mocks/port/metrics"
	mockPassword "github.com/amirhossein-jamali/auth-guardian/mocks/port/password"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockRisk "github.com/amirhossein-jamali/auth-guardian/mocks/port/risk"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"
)

// Mock session creator for testing
type mockSessionCreator struct {
	mock.Mock
}

func (m *mockSessionCreator) CreateSession(ctx context.Context, userID entity.ID, refreshToken string, userAgent, ip string, expiresAt int64) error {
	args := m.Called(ctx, userID, refreshToken, userAgent, ip, expiresAt)
	return args.Error(0)
}

// setupRouter creates a test router with the auth handler
func setupRouter(authHandler *handler.AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Setup routes similar to the actual application
	api := router.Group("/api")
	{
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/register", authHandler.Register)
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/refresh", authHandler.RefreshToken)
			authGroup.POST("/logout", authHandler.Logout)
			authGroup.POST("/logout-all", authHandler.LogoutAll)
			authGroup.POST("/logout-others", authHandler.LogoutOtherSessions)
		}
	}

	return router
}

// setupTest creates all necessary mocks and components for testing
func setupTest(t *testing.T) (
	*gin.Engine,
	*handler.AuthHandler,
	*mockRepo.MockUserRepository,
	*mockRepo.MockAuthSessionRepository,
	*mockToken.MockTokenService,
	*mockPassword.MockPasswordHasher,
	*mockTime.MockTimeProvider,
	*mockLogger.MockLogger,
	*mockIdGen.MockIDGenerator,
	*mockMetrics.MockMetricsRecorder,
	*mockRisk.MockRiskEvaluator,
	*mockLogger.MockAuditLogger,
	*mockSessionCreator,
) {
	// Create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	tokenService := mockToken.NewMockTokenService(t)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	metricsRecorder := mockMetrics.NewMockMetricsRecorder(t)
	riskEvaluator := mockRisk.NewMockRiskEvaluator(t)
	auditLogger := mockLogger.NewMockAuditLogger(t)
	sessionCreator := new(mockSessionCreator)

	// Setup default behavior for logger to avoid unnecessary mocking
	logger.EXPECT().Debug(mock.Anything, mock.Anything).Maybe().Return()
	logger.EXPECT().Info(mock.Anything, mock.Anything).Maybe().Return()
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Maybe().Return()
	logger.EXPECT().Error(mock.Anything, mock.Anything).Maybe().Return()

	// Setup audit logger default behavior
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)

	// Setup metrics recorder default behavior
	metricsRecorder.EXPECT().IncCounter(mock.Anything, mock.Anything).Maybe().Return()
	metricsRecorder.EXPECT().ObserveHistogram(mock.Anything, mock.Anything, mock.Anything).Maybe().Return()

	// Setup time provider default behavior
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Maybe()
	timeProvider.EXPECT().Since(mock.Anything).Return(100 * time.Millisecond).Maybe()

	// Setup auth session repository default behavior
	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, mock.Anything, mock.Anything).Return(int64(2), nil).Maybe()

	// Create use cases
	registerUseCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Create LoginUseCase with optional params using functional options pattern
	loginUseCase := auth.NewLoginUseCase(
		userRepo,
		authSessionRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		timeProvider,
		logger,
		5, // maxSessions
		auth.WithMetricsRecorder(metricsRecorder),
		auth.WithRiskEvaluator(riskEvaluator),
		auth.WithAuditLogger(auditLogger),
	)

	logoutUseCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	logoutAllUseCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	logoutOtherUseCase := auth.NewLogoutOtherSessionsUseCase(
		authSessionRepo,
		tokenService,
		logger,
		timeProvider,
		auditLogger,
	)

	refreshTokenUseCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Create Auth handler
	authHandler := handler.NewAuthHandler(
		registerUseCase,
		loginUseCase,
		logoutUseCase,
		logoutAllUseCase,
		logoutOtherUseCase,
		refreshTokenUseCase,
	)

	// Create router with auth handler
	router := setupRouter(authHandler)

	return router, authHandler, userRepo, authSessionRepo, tokenService, passwordHasher, timeProvider, logger,
		idGenerator, metricsRecorder, riskEvaluator, auditLogger, sessionCreator
}

// Helper function to make HTTP requests and parse responses
func performRequest(router *gin.Engine, method, path string, body interface{}) (*httptest.ResponseRecorder, error) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	req, err := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "integration-test-agent")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w, nil
}

// Helper function to make authenticated HTTP requests with user ID in context
func performAuthenticatedRequest(router *gin.Engine, method, path string, body interface{}, userID entity.ID) (*httptest.ResponseRecorder, error) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	req, err := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "integration-test-agent")

	// Create a new gin context with the request and response recorder
	w := httptest.NewRecorder()

	// Create a new router with authentication middleware
	authRouter := gin.New()
	authRouter.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})

	// Copy all routes from the original router to the auth router
	for _, routeInfo := range router.Routes() {
		authRouter.Handle(routeInfo.Method, routeInfo.Path, routeInfo.HandlerFunc)
	}

	authRouter.ServeHTTP(w, req)
	return w, nil
}

func TestRegister(t *testing.T) {
	// Setup
	router, _, userRepo, _, tokenService, passwordHasher, timeProvider, _,
		idGenerator, _, _, _, sessionCreator := setupTest(t)

	// Mock time provider
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Maybe()

	// Mock ID generator
	userId := "test-user-id"
	idGenerator.EXPECT().GenerateID().Return(userId).Maybe()

	// Mock repository calls
	userRepo.EXPECT().EmailExists(mock.Anything, "test@example.com").Return(false, nil)
	userRepo.EXPECT().Create(mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)

	// Mock session creator
	sessionCreator.On("CreateSession", mock.Anything, mock.AnythingOfType("entity.ID"),
		mock.AnythingOfType("string"), mock.AnythingOfType("string"),
		mock.AnythingOfType("string"), mock.AnythingOfType("int64")).Return(nil)

	// Mock token generation
	tokenService.EXPECT().GenerateTokens(mock.AnythingOfType("string")).
		Return("test-access-token", "test-refresh-token", now.Unix()+3600, nil)

	// Mock password hashing
	passwordHasher.EXPECT().HashPassword(mock.AnythingOfType("string")).Return("hashed-password", nil)

	// Create request body
	reqBody := dto.RegisterRequest{
		Email:     "test@example.com",
		Password:  "Password123!",
		FirstName: "Test",
		LastName:  "User",
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/register", reqBody)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, http.StatusCreated, resp.Code)

	// Parse response body
	var responseBody dto.RegisterResponse
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify response data
	assert.NotEmpty(t, responseBody.UserID)
	assert.Equal(t, reqBody.Email, responseBody.Email)
	assert.Equal(t, reqBody.FirstName, responseBody.FirstName)
	assert.Equal(t, reqBody.LastName, responseBody.LastName)
	assert.Equal(t, "test-access-token", responseBody.AccessToken)
	assert.Equal(t, "test-refresh-token", responseBody.RefreshToken)
	assert.Equal(t, now.Unix()+3600, responseBody.ExpiresAt)
}

func TestLogin(t *testing.T) {
	// Setup
	router, _, userRepo, authSessionRepo, tokenService, passwordHasher, timeProvider, _,
		_, _, riskEvaluator, auditLogger, sessionCreator := setupTest(t)

	// Mock time provider
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Maybe()
	timeProvider.EXPECT().Since(mock.Anything).Return(100 * time.Millisecond).Maybe()

	// Prepare test data
	testUser := &entity.User{
		ID:           entity.ID("test-user-id"),
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		FirstName:    "Test",
		LastName:     "User",
		IsActive:     true,
	}

	// Mock repository calls
	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)
	authSessionRepo.EXPECT().CountByUserID(mock.Anything, entity.ID("test-user-id")).Return(int64(0), nil).Maybe()
	authSessionRepo.EXPECT().EnsureSessionLimit(mock.Anything, entity.ID("test-user-id"), int64(5)).Return(nil).Maybe()

	// Mock session creator
	sessionCreator.On("CreateSession", mock.Anything, mock.AnythingOfType("entity.ID"),
		mock.AnythingOfType("string"), mock.AnythingOfType("string"),
		mock.AnythingOfType("string"), mock.AnythingOfType("int64")).Return(nil)

	// Mock password verification
	passwordHasher.EXPECT().VerifyPassword(mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(true, nil)

	// Mock token generation
	tokenService.EXPECT().GenerateTokens(mock.AnythingOfType("string")).
		Return("test-access-token", "test-refresh-token", now.Unix()+3600, nil)

	// Mock risk evaluation
	riskEvaluator.EXPECT().EvaluateLoginRisk(mock.Anything, mock.Anything).Return(0.0, nil).Maybe()

	// Mock audit logging
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, "user_login", mock.Anything).Return(nil).Maybe()

	// Create request body
	reqBody := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "Password123!",
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/login", reqBody)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var responseBody dto.LoginResponse
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify response data
	assert.Equal(t, testUser.ID.String(), responseBody.UserID)
	assert.Equal(t, testUser.Email, responseBody.Email)
	assert.Equal(t, testUser.FirstName, responseBody.FirstName)
	assert.Equal(t, testUser.LastName, responseBody.LastName)
	assert.Equal(t, "test-access-token", responseBody.AccessToken)
	assert.Equal(t, "test-refresh-token", responseBody.RefreshToken)
	assert.Equal(t, now.Unix()+3600, responseBody.ExpiresAt)
}

func TestRefreshToken(t *testing.T) {
	// Setup
	router, _, _, authSessionRepo, tokenService, _, timeProvider, _, _, _, _, _, _ := setupTest(t)

	// Mock time provider
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Maybe()

	// Prepare test data
	userID := entity.ID("test-user-id")
	refreshToken := "test-refresh-token"

	testSession := &entity.AuthSession{
		ID:           entity.ID("test-session-id"),
		UserID:       userID,
		RefreshToken: refreshToken,
		UserAgent:    "integration-test-agent",
		IP:           "127.0.0.1",
		ExpiresAt:    now.Add(24 * time.Hour),
	}

	// Mock repository calls
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, refreshToken).Return(testSession, nil)
	authSessionRepo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*entity.AuthSession")).Return(nil)

	// Mock token generation
	tokenService.EXPECT().GenerateTokens(mock.AnythingOfType("string")).
		Return("new-access-token", "new-refresh-token", now.Unix()+3600, nil)

	// Create request body
	reqBody := dto.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/refresh", reqBody)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var responseBody dto.RefreshTokenResponse
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify response data
	assert.Equal(t, "new-access-token", responseBody.AccessToken)
	assert.Equal(t, "new-refresh-token", responseBody.RefreshToken)
	assert.Equal(t, now.Unix()+3600, responseBody.ExpiresAt)
}

func TestLogout(t *testing.T) {
	// Setup
	router, _, _, authSessionRepo, _, _, _, _, _, _, _, _, _ := setupTest(t)

	// Prepare test data
	refreshToken := "test-refresh-token"

	// Mock repository calls
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, refreshToken).Return(&entity.AuthSession{
		ID:           "test-session-id",
		UserID:       "test-user-id",
		RefreshToken: refreshToken,
	}, nil)
	authSessionRepo.EXPECT().DeleteByID(mock.Anything, entity.ID("test-session-id")).Return(nil)

	// Create request body
	reqBody := dto.LogoutRequest{
		RefreshToken: refreshToken,
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/logout", reqBody)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify response data
	assert.Equal(t, "Successfully logged out", responseBody["message"])
}

func TestLogoutAll(t *testing.T) {
	// Setup
	router, _, _, authSessionRepo, _, _, _, _, _, _, _, _, _ := setupTest(t)

	// Mock repository calls
	authSessionRepo.EXPECT().DeleteAllByUserID(mock.Anything, entity.ID("test-user-id")).Return(nil)

	// Use the authenticated request helper
	resp, err := performAuthenticatedRequest(router, "POST", "/api/auth/logout-all", nil, "test-user-id")
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify response data
	assert.Equal(t, "Successfully logged out from all devices", responseBody["message"])
}

func TestLogoutOtherSessions(t *testing.T) {
	// Setup
	router, _, _, authSessionRepo, _, _, timeProvider, _, _, _, _, auditLogger, _ := setupTest(t)

	// Mock time provider
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Maybe()

	// Prepare test data
	currentRefreshToken := "current-refresh-token"

	// Mock repository calls
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, currentRefreshToken).Return(&entity.AuthSession{
		ID:           "current-session-id",
		UserID:       "test-user-id",
		RefreshToken: currentRefreshToken,
	}, nil)

	// Use DeleteAllExcept instead of individual DeleteByID calls
	authSessionRepo.EXPECT().DeleteAllExcept(mock.Anything, entity.ID("test-user-id"), entity.ID("current-session-id")).Return(int64(2), nil)

	// Mock audit logging
	auditLogger.EXPECT().LogSecurityEvent(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Create request body
	reqBody := dto.LogoutOtherRequest{
		CurrentRefreshToken: currentRefreshToken,
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/logout-others", reqBody)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify response data
	assert.Equal(t, "Successfully logged out from other devices", responseBody["message"])
}

func TestRegister_ValidationError(t *testing.T) {
	// Setup
	router, _, _, _, _, _, _, _, _, _, _, _, _ := setupTest(t)

	// Create an invalid request body (missing required fields)
	reqBody := dto.RegisterRequest{
		Email: "invalid-email", // Invalid email format
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/register", reqBody)
	require.NoError(t, err)

	// Verify response status (should be 400 Bad Request)
	assert.Equal(t, http.StatusBadRequest, resp.Code)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify error response
	assert.Contains(t, responseBody, "error")
	assert.Contains(t, responseBody, "code")
}

func TestLogin_InvalidCredentials(t *testing.T) {
	// Setup
	router, _, userRepo, _, _, passwordHasher, timeProvider, _, _, _, _, _, _ := setupTest(t)

	// Mock time provider
	now := time.Now()
	timeProvider.EXPECT().Now().Return(now).Maybe()

	// Prepare test data
	testUser := &entity.User{
		ID:           entity.ID("test-user-id"),
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		FirstName:    "Test",
		LastName:     "User",
		IsActive:     true,
	}

	// Mock repository calls
	userRepo.EXPECT().GetByEmail(mock.Anything, "test@example.com").Return(testUser, nil)

	// Mock password verification (returns false for invalid password)
	passwordHasher.EXPECT().VerifyPassword(mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(false, nil)

	// Create request body
	reqBody := dto.LoginRequest{
		Email:    "test@example.com",
		Password: "WrongPassword123!",
	}

	// Perform request
	resp, err := performRequest(router, "POST", "/api/auth/login", reqBody)
	require.NoError(t, err)

	// Verify response status (should be 401 Unauthorized)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)

	// Parse response body
	var responseBody map[string]any
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	require.NoError(t, err)

	// Verify error response
	assert.Contains(t, responseBody, "error")
	assert.Contains(t, responseBody, "code")
	assert.Equal(t, "invalid_credentials", responseBody["code"])
	assert.Equal(t, "Invalid email or password. Please check your credentials and try again.", responseBody["error"])
}
