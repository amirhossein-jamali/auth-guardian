package handler

import (
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/session"
	"github.com/gin-gonic/gin"
)

// SessionResponse represents the response for session endpoints
// swagger:model
type SessionResponse struct {
	SessionID    string `json:"session_id"`
	UserAgent    string `json:"user_agent"`
	IP           string `json:"ip"`
	LastActivity string `json:"last_activity"`
	CreatedAt    string `json:"created_at"`
	Current      bool   `json:"current"`
}

// SessionsListResponse represents the response for listing sessions
// swagger:model
type SessionsListResponse struct {
	Sessions []SessionResponse `json:"sessions"`
}

// SessionHandler handles session-related HTTP requests
type SessionHandler struct {
	getSessionsUseCase *session.GetSessionsUseCase
}

// NewSessionHandler creates a new instance of SessionHandler
func NewSessionHandler(getSessionsUseCase *session.GetSessionsUseCase) *SessionHandler {
	return &SessionHandler{
		getSessionsUseCase: getSessionsUseCase,
	}
}

// GetUserSessions gets all active sessions for the current user
// @Summary Get user sessions
// @Description Get all active sessions for the current user
// @Tags sessions
// @Accept json
// @Produce json
// @Success 200 {object} SessionsListResponse
// @Failure 401 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /sessions [get]
// @Security ApiKeyAuth
func (h *SessionHandler) GetUserSessions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"errors": "Unauthorized"})
		return
	}

	// Get refresh token from header
	refreshToken := c.GetHeader("X-Refresh-Token")

	// Call use case
	result, err := h.getSessionsUseCase.Execute(c.Request.Context(), session.GetSessionsInput{
		UserID:       userID.(string),
		CurrentToken: refreshToken,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"errors": "Failed to get sessions"})
		return
	}

	// Convert to response format
	response := SessionsListResponse{
		Sessions: make([]SessionResponse, 0, len(result.Sessions)),
	}

	for _, s := range result.Sessions {
		response.Sessions = append(response.Sessions, SessionResponse{
			SessionID:    s.SessionID,
			UserAgent:    s.UserAgent,
			IP:           s.IP,
			LastActivity: s.LastActivity.Format("2006-01-02T15:04:05Z07:00"),
			CreatedAt:    s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Current:      s.Current,
		})
	}

	c.JSON(http.StatusOK, response)
}
