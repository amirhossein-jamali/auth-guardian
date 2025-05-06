package crypto

// Argon2Params defines the parameters for Argon2 hashing
type Argon2Params struct {
	Memory      uint32 // Memory usage in KiB
	Iterations  uint32 // Number of iterations
	Parallelism uint8  // Degree of parallelism
	SaltLength  uint32 // Salt length in bytes
	KeyLength   uint32 // Hash length in bytes
}
