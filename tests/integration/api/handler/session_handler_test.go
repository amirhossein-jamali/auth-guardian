package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/session"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/api/handler"
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupSessionRouter(sessionHandler *handler.SessionHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())

	api := router.Group("/api")
	{
		sessionsGroup := api.Group("/sessions")
		{
			sessionsGroup.GET("", sessionHandler.GetUserSessions)
		}
	}

	return router
}

func performAuthenticatedRequestWithRefreshToken(router *gin.Engine, method, path string, userID string, refreshToken string) (*httptest.ResponseRecorder, error) {
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "integration-test-agent")
	if refreshToken != "" {
		req.Header.Set("X-Refresh-Token", refreshToken)
	}

	// Create a new gin context with the request and response recorder
	w := httptest.NewRecorder()

	// Create a new router with middleware that sets user ID in context
	authRouter := gin.New()
	authRouter.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Next()
	})

	// Copy all routes from the original router to the auth router
	for _, routeInfo := range router.Routes() {
		authRouter.Handle(routeInfo.Method, routeInfo.Path, routeInfo.HandlerFunc)
	}

	authRouter.ServeHTTP(w, req)
	return w, nil
}

func TestGetUserSessions(t *testing.T) {

	// Test cases
	t.Run("Success - with active sessions", func(t *testing.T) {
		// Create new mocks specific for this test
		testAuthSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
		testLogger := mockLogger.NewMockLogger(t)

		// Setup default behaviors
		testLogger.EXPECT().Debug(mock.Anything, mock.Anything).Maybe().Return()
		testLogger.EXPECT().Info(mock.Anything, mock.Anything).Maybe().Return()
		testLogger.EXPECT().Warn(mock.Anything, mock.Anything).Maybe().Return()
		testLogger.EXPECT().Error(mock.Anything, mock.Anything).Maybe().Return()

		// Create use case with test-specific mocks
		testGetSessionsUseCase := session.NewGetSessionsUseCase(
			testAuthSessionRepo,
			testLogger,
		)

		// Create handler with test-specific use case
		testSessionHandler := handler.NewSessionHandler(testGetSessionsUseCase)

		// Create router with test-specific handler
		testRouter := setupSessionRouter(testSessionHandler)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		refreshToken := "valid-refresh-token"
		now := time.Now()

		// Create test sessions
		session1 := &entity.AuthSession{
			ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174001"),
			UserID:         entity.NewID(userID),
			RefreshToken:   "token1",
			UserAgent:      "Chrome on Windows",
			IP:             "192.168.1.1",
			ExpiresAt:      now.Add(24 * time.Hour),
			LastActivityAt: now,
			CreatedAt:      now.Add(-24 * time.Hour),
			UpdatedAt:      now,
		}

		session2 := &entity.AuthSession{
			ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174002"),
			UserID:         entity.NewID(userID),
			RefreshToken:   refreshToken, // This is the current session
			UserAgent:      "Firefox on Mac",
			IP:             "192.168.1.2",
			ExpiresAt:      now.Add(24 * time.Hour),
			LastActivityAt: now,
			CreatedAt:      now.Add(-1 * time.Hour),
			UpdatedAt:      now,
		}

		sessions := []*entity.AuthSession{session1, session2}

		// Setup expectations
		testAuthSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(sessions, nil)
		testAuthSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, refreshToken).Return(session2, nil)

		// Perform request
		w, err := performAuthenticatedRequestWithRefreshToken(
			testRouter,
			http.MethodGet,
			"/api/sessions",
			userID,
			refreshToken,
		)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response structure
		var response handler.SessionsListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		// Should have two sessions
		require.Len(t, response.Sessions, 2)

		// Verify that one session is marked as current
		currentSessions := 0
		for _, s := range response.Sessions {
			if s.Current {
				currentSessions++
				assert.Equal(t, session2.ID.String(), s.SessionID)
			}
		}
		assert.Equal(t, 1, currentSessions, "Exactly one session should be marked as current")
	})

	t.Run("Success - no current token", func(t *testing.T) {
		// Create new mocks specific for this test
		testAuthSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
		testLogger := mockLogger.NewMockLogger(t)

		// Setup default behaviors
		testLogger.EXPECT().Debug(mock.Anything, mock.Anything).Maybe().Return()
		testLogger.EXPECT().Info(mock.Anything, mock.Anything).Maybe().Return()
		testLogger.EXPECT().Warn(mock.Anything, mock.Anything).Maybe().Return()
		testLogger.EXPECT().Error(mock.Anything, mock.Anything).Maybe().Return()

		// Create use case with test-specific mocks
		testGetSessionsUseCase := session.NewGetSessionsUseCase(
			testAuthSessionRepo,
			testLogger,
		)

		// Create handler with test-specific use case
		testSessionHandler := handler.NewSessionHandler(testGetSessionsUseCase)

		// Create router with test-specific handler
		testRouter := setupSessionRouter(testSessionHandler)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		now := time.Now()

		// Create test sessions
		session1 := &entity.AuthSession{
			ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174001"),
			UserID:         entity.NewID(userID),
			RefreshToken:   "token1",
			UserAgent:      "Chrome on Windows",
			IP:             "192.168.1.1",
			ExpiresAt:      now.Add(24 * time.Hour),
			LastActivityAt: now,
			CreatedAt:      now.Add(-24 * time.Hour),
			UpdatedAt:      now,
		}

		sessions := []*entity.AuthSession{session1}

		// Setup expectations
		testAuthSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(sessions, nil)
		// No GetByRefreshToken call since no refresh token is provided

		// Perform request without refresh token
		w, err := performAuthenticatedRequestWithRefreshToken(
			testRouter,
			http.MethodGet,
			"/api/sessions",
			userID,
			"", // no refresh token
		)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response structure
		var response handler.SessionsListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		// Should have one session
		assert.Len(t, response.Sessions, 1)

		// No sessions should be marked as current
		for _, s := range response.Sessions {
			assert.False(t, s.Current)
		}
	})

	t.Run("Unauthorized - no user ID in context", func(t *testing.T) {
		// Create new mocks specific for this test
		testAuthSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
		testLogger := mockLogger.NewMockLogger(t)

		// Create use case with test-specific mocks
		testGetSessionsUseCase := session.NewGetSessionsUseCase(
			testAuthSessionRepo,
			testLogger,
		)

		// Create handler with test-specific use case
		testSessionHandler := handler.NewSessionHandler(testGetSessionsUseCase)

		// Create router with test-specific handler
		testRouter := setupSessionRouter(testSessionHandler)

		// Create a request without authentication
		req, err := http.NewRequest(http.MethodGet, "/api/sessions", nil)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		testRouter.ServeHTTP(w, req)

		// Should return unauthorized
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Error - repository error", func(t *testing.T) {
		// Create new mocks specific for this test
		testAuthSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
		testLogger := mockLogger.NewMockLogger(t)

		// Create use case with test-specific mocks
		testGetSessionsUseCase := session.NewGetSessionsUseCase(
			testAuthSessionRepo,
			testLogger,
		)

		// Create handler with test-specific use case
		testSessionHandler := handler.NewSessionHandler(testGetSessionsUseCase)

		// Create router with test-specific handler
		testRouter := setupSessionRouter(testSessionHandler)

		userID := "123e4567-e89b-12d3-a456-426614174000"

		// Setup expectations - repository returns error
		repoError := fmt.Errorf("database error")

		// Strict call order expectations
		testAuthSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(nil, repoError)

		// Expect logger to record error - use Once() to ensure it's called exactly once
		testLogger.EXPECT().Error("Failed to get sessions for user", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["userId"] == userID && data["error"] == repoError.Error()
		})).Return().Once()

		// Perform request
		w, err := performAuthenticatedRequestWithRefreshToken(
			testRouter,
			http.MethodGet,
			"/api/sessions",
			userID,
			"",
		)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		// Verify HTTP response body indicates an error
		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Contains(t, response, "error")
	})
}
