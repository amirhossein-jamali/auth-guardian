package password

// Hasher handles password hashing operations
type Hasher interface {
	// HashPassword hashes a password
	HashPassword(password string) (string, error)
	// VerifyPassword checks if a password matches a hash
	VerifyPassword(hashedPassword, password string) (bool, error)
}
