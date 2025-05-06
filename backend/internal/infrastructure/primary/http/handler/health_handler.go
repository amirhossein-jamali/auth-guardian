package handler

import (
	"net/http"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database"
	"github.com/gin-gonic/gin"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	dbManager database.DBManager
	logger    logger.Logger
	startTime time.Time
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(dbManager database.DBManager, logger logger.Logger) *HealthHandler {
	return &HealthHandler{
		dbManager: dbManager,
		logger:    logger,
		startTime: time.Now(),
	}
}

// HealthStatus represents the health check response
type HealthStatus struct {
	Status    string `json:"status"`
	Database  string `json:"database"`
	Uptime    string `json:"uptime"`
	Timestamp string `json:"timestamp"`
}

// HandleHealthCheck handles GET /health requests
func (h *HealthHandler) HandleHealthCheck(c *gin.Context) {
	// Check database health
	dbStatus := "up"
	if err := h.dbManager.HealthCheck(c.Request.Context()); err != nil {
		h.logger.Error("Database health check failed", model.NewField("error", err.Error()))
		dbStatus = "down"
	}

	// Calculate uptime
	uptime := time.Since(h.startTime)

	// Determine overall status
	status := "ok"
	if dbStatus != "up" {
		status = "degraded"
		c.Status(http.StatusServiceUnavailable)
	} else {
		c.Status(http.StatusOK)
	}

	response := HealthStatus{
		Status:    status,
		Database:  dbStatus,
		Uptime:    uptime.String(),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	c.JSON(c.Writer.Status(), response)
}
