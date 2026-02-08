package opensecret

import (
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestSessionManagement(t *testing.T) {
	manager := NewSessionManager()

	// Initially empty
	if session := manager.GetSession(); session != nil {
		t.Error("Session should initially be nil")
	}

	// Set session
	sessionID := uuid.New()
	sessionKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	manager.SetSession(sessionID, sessionKey)

	// Retrieve session
	session := manager.GetSession()
	if session == nil {
		t.Fatal("Session should not be nil after setting")
	}

	if session.SessionID != sessionID {
		t.Errorf("SessionID = %v, want %v", session.SessionID, sessionID)
	}

	if session.SessionKey != sessionKey {
		t.Errorf("SessionKey mismatch")
	}

	// Clear session
	manager.ClearSession()
	if session := manager.GetSession(); session != nil {
		t.Error("Session should be nil after clearing")
	}
}

func TestTokenManagement(t *testing.T) {
	manager := NewSessionManager()

	// Initially empty
	if tokens := manager.GetTokens(); tokens != nil {
		t.Error("Tokens should initially be nil")
	}

	// Set tokens
	manager.SetTokens("access", "refresh")

	// Retrieve tokens
	tokens := manager.GetTokens()
	if tokens == nil {
		t.Fatal("Tokens should not be nil after setting")
	}

	if tokens.AccessToken != "access" {
		t.Errorf("AccessToken = %q, want %q", tokens.AccessToken, "access")
	}

	if tokens.RefreshToken != "refresh" {
		t.Errorf("RefreshToken = %q, want %q", tokens.RefreshToken, "refresh")
	}

	// Update access token
	if err := manager.UpdateAccessToken("new_access"); err != nil {
		t.Fatalf("UpdateAccessToken failed: %v", err)
	}

	if accessToken := manager.GetAccessToken(); accessToken != "new_access" {
		t.Errorf("AccessToken = %q, want %q", accessToken, "new_access")
	}

	// Clear tokens
	manager.ClearTokens()
	if tokens := manager.GetTokens(); tokens != nil {
		t.Error("Tokens should be nil after clearing")
	}
}

func TestAPIKeyManagement(t *testing.T) {
	manager := NewSessionManager()

	// Initially empty
	if apiKey := manager.GetAPIKey(); apiKey != "" {
		t.Error("API key should initially be empty")
	}

	// Set API key
	manager.SetAPIKey("test-api-key")

	if apiKey := manager.GetAPIKey(); apiKey != "test-api-key" {
		t.Errorf("APIKey = %q, want %q", apiKey, "test-api-key")
	}

	// Clear API key
	manager.ClearAPIKey()
	if apiKey := manager.GetAPIKey(); apiKey != "" {
		t.Error("API key should be empty after clearing")
	}
}

func TestNewSessionManagerWithAPIKey(t *testing.T) {
	manager := NewSessionManagerWithAPIKey("initial-key")

	if apiKey := manager.GetAPIKey(); apiKey != "initial-key" {
		t.Errorf("APIKey = %q, want %q", apiKey, "initial-key")
	}
}

func TestClearAll(t *testing.T) {
	manager := NewSessionManager()

	// Set everything
	manager.SetSession(uuid.New(), [32]byte{})
	manager.SetTokens("access", "refresh")
	manager.SetAPIKey("api-key")

	// Clear all
	manager.ClearAll()

	if session := manager.GetSession(); session != nil {
		t.Error("Session should be nil after ClearAll")
	}

	if tokens := manager.GetTokens(); tokens != nil {
		t.Error("Tokens should be nil after ClearAll")
	}

	if apiKey := manager.GetAPIKey(); apiKey != "" {
		t.Error("API key should be empty after ClearAll")
	}
}

func TestUpdateAccessTokenNoTokens(t *testing.T) {
	manager := NewSessionManager()

	err := manager.UpdateAccessToken("new_access")
	if err == nil {
		t.Error("UpdateAccessToken should fail when no tokens exist")
	}
}

func TestConcurrentAccess(t *testing.T) {
	manager := NewSessionManager()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			manager.SetSession(uuid.New(), [32]byte{byte(i)})
			manager.SetTokens("access", "refresh")
			manager.SetAPIKey("api-key")
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.GetSession()
			_ = manager.GetTokens()
			_ = manager.GetAccessToken()
			_ = manager.GetRefreshToken()
			_ = manager.GetAPIKey()
		}()
	}

	wg.Wait()

	// Should not panic or deadlock
}

func TestSessionClone(t *testing.T) {
	original := &SessionState{
		SessionID:  uuid.New(),
		SessionKey: [32]byte{1, 2, 3},
	}

	clone := original.Clone()

	// Modify original
	original.SessionKey[0] = 99

	// Clone should be unaffected
	if clone.SessionKey[0] == 99 {
		t.Error("Clone should not be affected by changes to original")
	}
}

func TestTokenPairClone(t *testing.T) {
	original := &TokenPair{
		AccessToken:  "access",
		RefreshToken: "refresh",
	}

	clone := original.Clone()

	// Modify original
	original.AccessToken = "modified"

	// Clone should be unaffected
	if clone.AccessToken == "modified" {
		t.Error("Clone should not be affected by changes to original")
	}
}

func TestNilClone(t *testing.T) {
	var session *SessionState
	if session.Clone() != nil {
		t.Error("Clone of nil should be nil")
	}

	var tokens *TokenPair
	if tokens.Clone() != nil {
		t.Error("Clone of nil should be nil")
	}
}
