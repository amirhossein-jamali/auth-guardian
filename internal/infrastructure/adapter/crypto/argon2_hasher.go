package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/password"
	"golang.org/x/crypto/argon2"
)

// Argon2Params defines the parameters for the Argon2id algorithm
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Argon2Hasher implements the PasswordHasher port using Argon2id algorithm
type Argon2Hasher struct {
	params Argon2Params
}

// NewArgon2Hasher creates a new instance of Argon2Hasher with recommended parameters
func NewArgon2Hasher() *Argon2Hasher {
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

// WithParams sets custom parameters for the Argon2id algorithm
func (h *Argon2Hasher) WithParams(params Argon2Params) *Argon2Hasher {
	h.params = params
	return h
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

// VerifyPassword checks if a password matches a hash
func (h *Argon2Hasher) VerifyPassword(hashedPassword, password string) (bool, error) {
	// Parse the hash string
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	// Check the algorithm and version
	if parts[1] != "argon2id" {
		return false, errors.New("incompatible hash algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, errors.New("invalid hash version")
	}
	if version != argon2.Version {
		return false, errors.New("incompatible hash version")
	}

	// Parse the parameters
	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, errors.New("invalid hash parameters")
	}

	// Decode the salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}

	// Decode the hash
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}
	keyLength := uint32(len(decodedHash))

	// Compute the hash of the provided password
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	// Compare the computed hash with the stored hash
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// Ensure Argon2Hasher implements password.PasswordHasher
var _ password.Hasher = (*Argon2Hasher)(nil)
