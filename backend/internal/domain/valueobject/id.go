package valueobject

import (
	"encoding/json"
	"fmt"
)

// ID represents a unique identifier for domain entities
type ID string

// String returns the string representation of the ID
func (id *ID) String() string {
	return string(*id)
}

// ParseID creates an ID from a string value
func ParseID(idStr string) (ID, error) {
	if idStr == "" {
		return "", fmt.Errorf("ID cannot be empty")
	}
	return ID(idStr), nil
}

// MarshalJSON implements json.Marshaler
func (id *ID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (id *ID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("invalid ID format: %w", err)
	}
	*id = ID(s)
	return nil
}
