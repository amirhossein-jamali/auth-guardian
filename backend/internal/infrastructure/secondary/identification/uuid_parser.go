package identification

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/identification"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/google/uuid"
)

// UUIDParser implements the identification.IDParser port
type UUIDParser struct{}

// NewUUIDParser creates a new UUIDParser
func NewUUIDParser() identification.IDParser {
	return &UUIDParser{}
}

// ParseID parses a string into a UUID
func (p *UUIDParser) ParseID(idStr string) (valueobject.ID, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return "", err
	}
	return valueobject.ID(id.String()), nil
}
