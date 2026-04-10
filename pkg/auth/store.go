package auth

import (
	"time"
)

// Store defines the interface for persisting authentication data.
// Implementations can be in-memory (default) or persistent (SQLite).
type Store interface {
	// Team operations.
	SaveTeam(team *TeamInfo) error
	GetTeam(name string) (*TeamInfo, error)
	ListTeams() ([]TeamInfo, error)
	DeleteTeam(name string) error

	// Token revocation operations.
	SaveRevokedToken(tokenID string, expiresAt time.Time) error
	IsTokenRevoked(tokenID string) (bool, error)
	RemoveRevokedToken(tokenID string) error
	CleanupExpiredRevocations() (int, error)
	CountRevokedTokens() (int, error)

	// Close releases any resources held by the store.
	Close() error
}

// MemoryStore implements Store using in-memory maps.
// This is the default, zero-persistence backend.
type MemoryStore struct {
	teams         map[string]*TeamInfo
	revokedTokens map[string]time.Time
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		teams:         make(map[string]*TeamInfo),
		revokedTokens: make(map[string]time.Time),
	}
}

// SaveTeam saves a team to memory.
func (s *MemoryStore) SaveTeam(team *TeamInfo) error {
	// Copy to prevent external modification.
	teamCopy := *team
	s.teams[team.Name] = &teamCopy
	return nil
}

// GetTeam retrieves a team from memory.
func (s *MemoryStore) GetTeam(name string) (*TeamInfo, error) {
	team, ok := s.teams[name]
	if !ok {
		return nil, ErrTeamNotFound
	}
	// Return a copy to prevent external modification.
	teamCopy := *team
	return &teamCopy, nil
}

// ListTeams returns all teams from memory.
func (s *MemoryStore) ListTeams() ([]TeamInfo, error) {
	teams := make([]TeamInfo, 0, len(s.teams))
	for _, team := range s.teams {
		teams = append(teams, *team)
	}
	return teams, nil
}

// DeleteTeam removes a team from memory.
func (s *MemoryStore) DeleteTeam(name string) error {
	delete(s.teams, name)
	return nil
}

// SaveRevokedToken saves a revoked token to memory.
func (s *MemoryStore) SaveRevokedToken(tokenID string, expiresAt time.Time) error {
	s.revokedTokens[tokenID] = expiresAt
	return nil
}

// IsTokenRevoked checks if a token is revoked.
func (s *MemoryStore) IsTokenRevoked(tokenID string) (bool, error) {
	_, revoked := s.revokedTokens[tokenID]
	return revoked, nil
}

// RemoveRevokedToken removes a token from the revocation list.
func (s *MemoryStore) RemoveRevokedToken(tokenID string) error {
	delete(s.revokedTokens, tokenID)
	return nil
}

// CleanupExpiredRevocations removes expired revocation entries.
func (s *MemoryStore) CleanupExpiredRevocations() (int, error) {
	now := time.Now()
	cleaned := 0

	for tokenID, expiresAt := range s.revokedTokens {
		// Skip permanent revocations (zero time).
		if expiresAt.IsZero() {
			continue
		}
		// Remove if the token would have expired by now.
		if now.After(expiresAt) {
			delete(s.revokedTokens, tokenID)
			cleaned++
		}
	}

	return cleaned, nil
}

// CountRevokedTokens returns the number of revoked tokens.
func (s *MemoryStore) CountRevokedTokens() (int, error) {
	return len(s.revokedTokens), nil
}

// Close is a no-op for memory store.
func (s *MemoryStore) Close() error {
	return nil
}
