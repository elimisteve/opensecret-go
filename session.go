package opensecret

import (
	"sync"

	"github.com/google/uuid"
)

// SessionManager provides thread-safe session management
type SessionManager struct {
	session *SessionState
	tokens  *TokenPair
	apiKey  string
	mu      sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// NewSessionManagerWithAPIKey creates a new session manager with an API key
func NewSessionManagerWithAPIKey(apiKey string) *SessionManager {
	return &SessionManager{
		apiKey: apiKey,
	}
}

// SetSession sets the session state
func (m *SessionManager) SetSession(sessionID uuid.UUID, sessionKey [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = &SessionState{
		SessionID:  sessionID,
		SessionKey: sessionKey,
	}
}

// GetSession returns a copy of the current session state
func (m *SessionManager) GetSession() *SessionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.session.Clone()
}

// ClearSession clears the session state
func (m *SessionManager) ClearSession() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = nil
}

// SetTokens sets the token pair
func (m *SessionManager) SetTokens(accessToken string, refreshToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}

// GetTokens returns a copy of the current token pair
func (m *SessionManager) GetTokens() *TokenPair {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokens.Clone()
}

// GetAccessToken returns the current access token
func (m *SessionManager) GetAccessToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tokens == nil {
		return ""
	}
	return m.tokens.AccessToken
}

// GetRefreshToken returns the current refresh token
func (m *SessionManager) GetRefreshToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tokens == nil {
		return ""
	}
	return m.tokens.RefreshToken
}

// UpdateAccessToken updates only the access token
func (m *SessionManager) UpdateAccessToken(accessToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens == nil {
		return NewAuthenticationError("no tokens to update", nil)
	}
	m.tokens.AccessToken = accessToken
	return nil
}

// ClearTokens clears the token pair
func (m *SessionManager) ClearTokens() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = nil
}

// SetAPIKey sets the API key
func (m *SessionManager) SetAPIKey(apiKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apiKey = apiKey
}

// GetAPIKey returns the current API key
func (m *SessionManager) GetAPIKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.apiKey
}

// ClearAPIKey clears the API key
func (m *SessionManager) ClearAPIKey() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apiKey = ""
}

// ClearAll clears all session data
func (m *SessionManager) ClearAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = nil
	m.tokens = nil
	m.apiKey = ""
}
