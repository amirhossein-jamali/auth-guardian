package model

// Field represents a key-value pair for structured logging
type Field struct {
	Key   string
	Value any
}

// NewField creates a new logging field
func NewField(key string, value any) Field {
	return Field{
		Key:   key,
		Value: value,
	}
}
