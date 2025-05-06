package entity

import (
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
)

type User struct {
	ID           valueobject.ID    `json:"id"`
	Email        valueobject.Email `json:"email"`
	PasswordHash string            `json:"-"`
	FirstName    string            `json:"first_name"`
	LastName     string            `json:"last_name"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

func NewUser(idGenerator func() valueobject.ID, email valueobject.Email, firstName, lastName, passwordHash string) *User {
	now := time.Now()
	return &User{
		ID:           idGenerator(),
		Email:        email,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}
