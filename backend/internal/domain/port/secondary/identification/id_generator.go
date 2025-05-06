package identification

import "github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"

// IDGenerator is a port for generating unique IDs
type IDGenerator interface {
	// GenerateID generates a new unique ID
	GenerateID() valueobject.ID
}
