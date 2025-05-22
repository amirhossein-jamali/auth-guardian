package entity

// ID represents a unique identifier in the domain
type ID string

// NewID creates a new ID with the given string value
func NewID(id string) ID {
	return ID(id)
}

// String returns the string representation of the ID
func (id ID) String() string {
	return string(id)
}
