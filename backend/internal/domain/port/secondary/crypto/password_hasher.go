package crypto

type PasswordHasher interface {
	HashPassword(password string) (string, error)
	ComparePasswords(hashedPassword, plainPassword string) error
}
