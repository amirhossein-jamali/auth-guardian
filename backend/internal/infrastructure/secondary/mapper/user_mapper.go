package mapper

import (
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	dbModel "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database/model"
)

// UserDTO is a data transfer object between domain and infrastructure layers
type UserDTO struct {
	ID           string
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserMapper handles conversions between domain entities and database models
type UserMapper struct {
	logger logger.Logger
}

// Ensure UserMapper implements UserMapperInterface
var _ UserMapperInterface = (*UserMapper)(nil)

// NewUserMapper creates a new instance of UserMapper
func NewUserMapper(logger logger.Logger) *UserMapper {
	return &UserMapper{
		logger: logger,
	}
}

// FromEntity creates a UserDTO from a domain entity
func (m *UserMapper) FromEntity(user *entity.User) UserDTO {
	if user == nil {
		m.logger.Warn("Attempting to map nil user entity")
		return UserDTO{}
	}

	return UserDTO{
		ID:           user.ID.String(),
		Email:        user.Email.Value(),
		PasswordHash: user.PasswordHash,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

// ToEntity converts a UserDTO to a domain entity
func (m *UserMapper) ToEntity(dto UserDTO) (*entity.User, error) {
	// Create ID from string based on ID implementation
	id := valueobject.ID(dto.ID)

	// Parse email
	email, err := valueobject.NewEmail(dto.Email)
	if err != nil {
		m.logger.Error("Failed to parse user email",
			model.NewField("email", dto.Email),
			model.NewField("error", err.Error()))
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	return &entity.User{
		ID:           id,
		Email:        *email,
		PasswordHash: dto.PasswordHash,
		FirstName:    dto.FirstName,
		LastName:     dto.LastName,
		CreatedAt:    dto.CreatedAt,
		UpdatedAt:    dto.UpdatedAt,
	}, nil
}

// FromModel creates a UserDTO from a database model
func (m *UserMapper) FromModel(dbUser dbModel.User) UserDTO {
	return UserDTO{
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		PasswordHash: dbUser.PasswordHash,
		FirstName:    dbUser.FirstName,
		LastName:     dbUser.LastName,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
	}
}

// ToModel converts a UserDTO to a database model
func (m *UserMapper) ToModel(dto UserDTO) dbModel.User {
	return dbModel.User{
		ID:           dto.ID,
		Email:        dto.Email,
		PasswordHash: dto.PasswordHash,
		FirstName:    dto.FirstName,
		LastName:     dto.LastName,
		CreatedAt:    dto.CreatedAt,
		UpdatedAt:    dto.UpdatedAt,
	}
}
