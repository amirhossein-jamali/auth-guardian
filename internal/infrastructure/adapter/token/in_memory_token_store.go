package token

import (
	"errors"
	"sync"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
)

// Entry represents a stored token with metadata
type Entry struct {
	UserID    string
	ExpiresAt int64
	Revoked   bool
}

// InMemoryTokenStore implements token.TokenStore using in-memory storage
// This is intended for development and testing purposes only
type InMemoryTokenStore struct {
	tokens          map[string]Entry
	mutex           sync.RWMutex
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewInMemoryTokenStore creates a new InMemoryTokenStore
func NewInMemoryTokenStore() token.TokenStore {
	store := &InMemoryTokenStore{
		tokens:          make(map[string]Entry),
		cleanupInterval: 1 * time.Hour,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup of expired tokens
	go store.startCleanupTask()

	return store
}

// StoreToken stores a token with its associated user ID and expiration time
func (s *InMemoryTokenStore) StoreToken(tokenID string, userID string, expiresAt int64) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.tokens[tokenID] = Entry{
		UserID:    userID,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	return nil
}

// GetUserIDByToken retrieves the user ID associated with a token
func (s *InMemoryTokenStore) GetUserIDByToken(tokenID string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.tokens[tokenID]
	if !exists {
		return "", errors.New("token not found")
	}

	// Check if token is expired
	if entry.ExpiresAt < time.Now().Unix() {
		return "", errors.New("token expired")
	}

	return entry.UserID, nil
}

// RevokeToken marks a token as revoked
func (s *InMemoryTokenStore) RevokeToken(tokenID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry, exists := s.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	entry.Revoked = true
	s.tokens[tokenID] = entry

	return nil
}

// IsTokenRevoked checks if a token is revoked
func (s *InMemoryTokenStore) IsTokenRevoked(tokenID string) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.tokens[tokenID]
	if !exists {
		return false, errors.New("token not found")
	}

	return entry.Revoked, nil
}

// startCleanupTask runs periodic cleanup of expired tokens
func (s *InMemoryTokenStore) startCleanupTask() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

// cleanup removes expired tokens from the store
func (s *InMemoryTokenStore) cleanup() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now().Unix()
	for id, t := range s.tokens {
		if t.ExpiresAt < now {
			delete(s.tokens, id)
		}
	}
}

// Stop stops the cleanup goroutine
func (s *InMemoryTokenStore) Stop() {
	close(s.stopCleanup)
}
