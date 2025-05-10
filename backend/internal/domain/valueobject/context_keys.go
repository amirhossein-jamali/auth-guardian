package valueobject

// ContextKey is a custom type for context keys to avoid collisions
type ContextKey string

// Context keys
const (
	UserAgentContextKey ContextKey = "user_agent"
	IPContextKey        ContextKey = "ip"
)
