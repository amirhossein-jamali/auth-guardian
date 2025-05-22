package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// FileAuditLogger implements the AuditLogger interface by writing to a file
type FileAuditLogger struct {
	timeSource    tport.Provider
	filePath      string
	mu            sync.Mutex
	regularLogger lport.Logger
}

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	RequestID string         `json:"request_id,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	IP        string         `json:"ip,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// NewFileAuditLogger creates a new file-based audit logger
func NewFileAuditLogger(timeSource tport.Provider, logDir string, regularLogger lport.Logger) lport.AuditLogger {
	// Ensure the log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		panic(fmt.Sprintf("failed to create audit log directory: %v", err))
	}

	// Create log file path with current date using timeSource
	currentDate := timeSource.Now().Format(tport.DateFormat)
	filePath := filepath.Join(logDir, fmt.Sprintf("audit-%s.log", currentDate))

	return &FileAuditLogger{
		timeSource:    timeSource,
		filePath:      filePath,
		regularLogger: regularLogger,
	}
}

// LogSecurityEvent logs a security-related event with metadata
func (l *FileAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error {
	// Extract common fields from metadata
	userID := extractUserID(metadata)
	ip, _ := metadata["ip"].(string)
	requestID := extractRequestID(ctx)

	// Create a clean copy of metadata without extracted fields
	metadataCopy := cleanMetadata(metadata, []string{"userId", "user_id", "ip"})

	// Create timestamp using timeSource
	timestamp := l.timeSource.Now().Format(tport.RFC3339Format)

	// Create the log entry
	entry := AuditLogEntry{
		Timestamp: timestamp,
		EventType: eventType,
		RequestID: requestID,
		UserID:    userID,
		IP:        ip,
		Metadata:  metadataCopy,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		l.regularLogger.Error("Failed to marshal audit log entry", map[string]any{
			"error": err.Error(),
			"event": eventType,
		})
		return err
	}

	// Append newline for readability
	jsonData = append(jsonData, '\n')

	// Write to file (with mutex to prevent race conditions)
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if we need to rotate the log file (if date has changed)
	l.checkRotateFile()

	// Open the file in append mode
	file, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		l.regularLogger.Error("Failed to open audit log file", map[string]any{
			"error":    err.Error(),
			"filePath": l.filePath,
		})
		return err
	}
	defer file.Close()

	// Write the log entry
	if _, err := file.Write(jsonData); err != nil {
		l.regularLogger.Error("Failed to write to audit log", map[string]any{
			"error":    err.Error(),
			"filePath": l.filePath,
		})
		return err
	}

	return nil
}

// Flush ensures all buffered logs are written to their destination
func (l *FileAuditLogger) Flush() error {
	// For file logger, there's no in-memory buffering, so nothing to do
	// If we added buffering in the future, we would flush it here
	return nil
}

// checkRotateFile checks if we need to rotate the log file based on the current date
func (l *FileAuditLogger) checkRotateFile() {
	// Get the current date using timeSource
	currentDate := l.timeSource.Now().Format(tport.DateFormat)
	expectedFilePath := filepath.Join(filepath.Dir(l.filePath), fmt.Sprintf("audit-%s.log", currentDate))

	// If the file path doesn't match the expected one, update it
	if l.filePath != expectedFilePath {
		l.filePath = expectedFilePath
	}
}
