package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	lport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// FileLogger implements the Logger interface by writing to a file
type FileLogger struct {
	timeSource tport.Provider
	level      lport.LogLevel
	filePath   string
	mu         sync.Mutex
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// NewFileLogger creates a new file-based logger
func NewFileLogger(timeSource tport.Provider, logDir string, level lport.LogLevel) lport.Logger {
	// Ensure the log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		panic(fmt.Sprintf("failed to create log directory: %v", err))
	}

	// Create log file path with current date using timeSource
	currentDate := timeSource.Now().Format(tport.DateFormat)
	filePath := filepath.Join(logDir, fmt.Sprintf("app-%s.log", currentDate))

	return &FileLogger{
		timeSource: timeSource,
		level:      level,
		filePath:   filePath,
	}
}

// SetLevel sets the minimum log level to output
func (l *FileLogger) SetLevel(level lport.LogLevel) {
	l.level = level
}

// GetLevel gets the current log level
func (l *FileLogger) GetLevel() lport.LogLevel {
	return l.level
}

// levelToString converts LogLevel to string representation
func levelToString(level lport.LogLevel) string {
	switch level {
	case lport.LogLevelDebug:
		return "DEBUG"
	case lport.LogLevelInfo:
		return "INFO"
	case lport.LogLevelWarn:
		return "WARN"
	case lport.LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// write writes a log entry to the file
func (l *FileLogger) write(level lport.LogLevel, message string, fields map[string]any) error {
	if level < l.level {
		return nil // Skip logs below current level
	}

	// Create the log entry
	entry := LogEntry{
		Timestamp: l.timeSource.Now().Format(tport.RFC3339Format),
		Level:     levelToString(level),
		Message:   message,
		Fields:    fields,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		// Can't log this error since we're inside the logger
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
		return err
	}
	defer file.Close()

	// Write the log entry
	_, err = file.Write(jsonData)
	return err
}

// Debug logs debug messages
func (l *FileLogger) Debug(message string, fields map[string]any) {
	_ = l.write(lport.LogLevelDebug, message, fields)
}

// Info logs informational messages
func (l *FileLogger) Info(message string, fields map[string]any) {
	_ = l.write(lport.LogLevelInfo, message, fields)
}

// Warn logs warning messages
func (l *FileLogger) Warn(message string, fields map[string]any) {
	_ = l.write(lport.LogLevelWarn, message, fields)
}

// Error logs error messages
func (l *FileLogger) Error(message string, fields map[string]any) {
	_ = l.write(lport.LogLevelError, message, fields)
}

// Flush ensures all buffered logs are written to their destination
func (l *FileLogger) Flush() error {
	// FileLogger writes directly to file without buffering, so there's nothing to flush
	return nil
}

// checkRotateFile checks if we need to rotate the log file based on the current date
func (l *FileLogger) checkRotateFile() {
	// Get the current date using timeSource
	currentDate := l.timeSource.Now().Format(tport.DateFormat)
	expectedFilePath := filepath.Join(filepath.Dir(l.filePath), fmt.Sprintf("app-%s.log", currentDate))

	// If the file path doesn't match the expected one, update it
	if l.filePath != expectedFilePath {
		l.filePath = expectedFilePath
	}
}
