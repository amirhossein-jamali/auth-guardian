package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	cryptoPort "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/crypto"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Hasher implements the PasswordHasher interface with Argon2id
type Argon2Hasher struct {
	params Argon2Params
}

// NewArgon2Hasher creates a new instance of Argon2Hasher with recommended parameters
func NewArgon2Hasher() cryptoPort.PasswordHasher {
	return &Argon2Hasher{
		params: Argon2Params{
			Memory:      64 * 1024, // 64MB
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

// HashPassword hashes a password using Argon2id
func (h *Argon2Hasher) HashPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash the password
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.params.Iterations,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.Memory,
		h.params.Iterations,
		h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encodedHash, nil
}

// ComparePasswords compares a hashed password with a plain password
func (h *Argon2Hasher) ComparePasswords(hashedPassword, plainPassword string) error {
	// Parse the hash string
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 {
		return errors.New("invalid hash format")
	}

	// Check the algorithm and version
	if parts[1] != "argon2id" {
		return errors.New("incompatible hash algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return errors.New("invalid hash version")
	}
	if version != argon2.Version {
		return errors.New("incompatible hash version")
	}

	// Parse the parameters
	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return errors.New("invalid hash parameters")
	}

	// Decode the salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("invalid salt encoding")
	}

	// Decode the hash
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("invalid hash encoding")
	}
	keyLength := uint32(len(decodedHash))

	// Compute the hash of the provided password
	computedHash := argon2.IDKey(
		[]byte(plainPassword),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	// Compare the computed hash with the stored hash
	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(decodedHash, computedHash) == 1 {
		return nil
	}

	return errors.New("invalid password")
}
