package identification

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/identification"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/google/uuid"
)

// UUIDGenerator implements the identification.IDGenerator port using google/uuid
type UUIDGenerator struct{}

// NewUUIDGenerator creates a new UUIDGenerator
func NewUUIDGenerator() identification.IDGenerator {
	return &UUIDGenerator{}
}

// GenerateID generates a new UUID
func (g *UUIDGenerator) GenerateID() valueobject.ID {
	return valueobject.ID(uuid.New().String())
}
