package mapper

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database/model"
)

// UserMapperInterface defines methods for mapping between domain and infrastructure layers
type UserMapperInterface interface {
	// Entity <-> DTO
	FromEntity(user *entity.User) UserDTO
	ToEntity(dto UserDTO) (*entity.User, error)

	// Model <-> DTO
	FromModel(model model.User) UserDTO
	ToModel(dto UserDTO) model.User
}
