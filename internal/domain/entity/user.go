package entity

import (
	"time"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

type User struct {
	ID           ID
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func NewUser(id ID, email, firstName, lastName string, timeProvider tport.Provider) *User {
	now := timeProvider.Now()
	return &User{
		ID:        id,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (u *User) SetPassword(hashedPassword string, timeProvider tport.Provider) {
	u.PasswordHash = hashedPassword
	u.UpdatedAt = timeProvider.Now()
}
