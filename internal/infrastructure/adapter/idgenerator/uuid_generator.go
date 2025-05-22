package idgenerator

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/idgenerator"

	"github.com/google/uuid"
)

// UUIDGenerator implements the IDGenerator interface using UUID library
type UUIDGenerator struct{}

// NewUUIDGenerator creates a new UUIDGenerator
func NewUUIDGenerator() idgenerator.IDGenerator {
	return &UUIDGenerator{}
}

// GenerateID generates a new unique ID using UUID v4
func (g *UUIDGenerator) GenerateID() string {
	return uuid.New().String()
}
