package tests

import (
	"testing"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/stretchr/testify/assert"
)

func TestNewID(t *testing.T) {
	// Arrange
	idStr := "test-id-123"

	// Act
	id := entity.NewID(idStr)

	// Assert
	assert.Equal(t, entity.ID(idStr), id, "NewID should create an ID with the given string value")
}

func TestID_String(t *testing.T) {
	// Arrange
	idStr := "test-id-456"
	id := entity.ID(idStr)

	// Act
	result := id.String()

	// Assert
	assert.Equal(t, idStr, result, "String method should return the string representation of the ID")
}
