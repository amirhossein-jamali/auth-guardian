package model

// Field represents a log field with key and value
type Field struct {
	Key   string
	Value any
}

// NewField creates a new log field
func NewField(key string, value any) Field {
	return Field{
		Key:   key,
		Value: value,
	}
}
