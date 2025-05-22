package idgenerator

// IDGenerator is responsible for generating unique IDs
type IDGenerator interface {
	// GenerateID generates a new unique ID
	GenerateID() string
}
