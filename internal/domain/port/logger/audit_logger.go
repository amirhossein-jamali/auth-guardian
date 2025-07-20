package logger

import "context"

// AuditEvent represents a security-related event
type AuditEvent struct {
	Action     string                 // The action being performed (e.g., "login", "otp.request")
	TargetType string                 // The type of the target resource (e.g., "user", "otp")
	TargetID   string                 // The identifier of the target
	UserID     string                 // Optional: The ID of the user performing the action (if authenticated)
	IP         string                 // The IP address where the action originated
	UserAgent  string                 // Optional: User agent information
	Success    bool                   // Whether the action was successful
	Metadata   map[string]interface{} // Additional contextual information
}

// AuditLogger defines interface for security audit logging
type AuditLogger interface {
	// LogSecurityEvent logs a security-related event with metadata
	LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error

	// Log records an audit event with structured data
	Log(ctx context.Context, event AuditEvent) error

	// Flush ensures all buffered logs are written to their destination
	// Useful during application shutdown to prevent log loss
	Flush() error
}
