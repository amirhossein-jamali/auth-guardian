package token

import (
	"context"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/storage"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
)

// Constants for Redis key prefixes
const (
	// KeyPrefix is the prefix for token storage
	KeyPrefix = "token:"
	// RevokedTokenKeyPrefix is the prefix for revoked tokens
	RevokedTokenKeyPrefix = "revoked_token:"
)

// RedisTokenStore implements token.TokenStore using a key-value store
type RedisTokenStore struct {
	store storage.KeyValueStore
	ctx   context.Context
}

// NewRedisTokenStore creates a new RedisTokenStore
func NewRedisTokenStore(store storage.KeyValueStore) token.TokenStore {
	return &RedisTokenStore{
		store: store,
		ctx:   context.Background(),
	}
}

// StoreToken stores a token with its associated user ID and expiration time
func (s *RedisTokenStore) StoreToken(tokenID string, userID string, expiresAt int64) error {
	key := fmt.Sprintf("%s%s", KeyPrefix, tokenID)
	expiration := time.Until(time.Unix(expiresAt, 0))

	// Store the token with the user ID as value
	return s.store.Set(s.ctx, key, userID, expiration)
}

// GetUserIDByToken retrieves the user ID associated with a token
func (s *RedisTokenStore) GetUserIDByToken(tokenID string) (string, error) {
	key := fmt.Sprintf("%s%s", KeyPrefix, tokenID)

	// Get the user ID from the store
	userID, err := s.store.Get(s.ctx, key)
	if err != nil {
		return "", err
	}

	return userID, nil
}

// RevokeToken marks a token as revoked
func (s *RedisTokenStore) RevokeToken(tokenID string) error {
	// First check if the token exists
	tokenKey := fmt.Sprintf("%s%s", KeyPrefix, tokenID)
	userID, err := s.store.Get(s.ctx, tokenKey)
	if err != nil {
		return err
	}

	// Get token TTL from Redis to maintain the same expiration
	// This is simplified for now - in a real implementation, you'd get the TTL
	// For simplicity, we're using a fixed expiration of 30 days
	expiration := 30 * 24 * time.Hour

	// Set the revoked flag
	revokedKey := fmt.Sprintf("%s%s", RevokedTokenKeyPrefix, tokenID)
	if err := s.store.Set(s.ctx, revokedKey, userID, expiration); err != nil {
		return err
	}

	return nil
}

// IsTokenRevoked checks if a token is revoked
func (s *RedisTokenStore) IsTokenRevoked(tokenID string) (bool, error) {
	key := fmt.Sprintf("%s%s", RevokedTokenKeyPrefix, tokenID)

	// Check if the revoked key exists
	exists, err := s.store.Exists(s.ctx, key)
	if err != nil {
		return false, err
	}

	return exists, nil
}
