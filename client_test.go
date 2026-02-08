package opensecret

import (
	"strings"
	"testing"
)

func TestClientCreation(t *testing.T) {
	client := NewClient("http://localhost:3000")

	if client.baseURL != "http://localhost:3000" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "http://localhost:3000")
	}

	if !client.useMockAttestation {
		t.Error("useMockAttestation should be true for localhost")
	}
}

func TestClientCreationWithTrailingSlash(t *testing.T) {
	client := NewClient("http://localhost:3000/")

	if client.baseURL != "http://localhost:3000" {
		t.Errorf("baseURL = %q, want %q (trailing slash should be trimmed)", client.baseURL, "http://localhost:3000")
	}
}

func TestClientCreationProduction(t *testing.T) {
	client := NewClient("https://enclave.example.com")

	if client.useMockAttestation {
		t.Error("useMockAttestation should be false for production URLs")
	}
}

func TestClientWithAPIKey(t *testing.T) {
	client := NewClientWithAPIKey("http://localhost:3000", "test-api-key")

	if apiKey := client.sessionManager.GetAPIKey(); apiKey != "test-api-key" {
		t.Errorf("APIKey = %q, want %q", apiKey, "test-api-key")
	}
}

func TestSetClearAPIKey(t *testing.T) {
	client := NewClient("http://localhost:3000")

	client.SetAPIKey("my-api-key")
	if apiKey := client.sessionManager.GetAPIKey(); apiKey != "my-api-key" {
		t.Errorf("APIKey = %q, want %q", apiKey, "my-api-key")
	}

	client.ClearAPIKey()
	if apiKey := client.sessionManager.GetAPIKey(); apiKey != "" {
		t.Errorf("APIKey = %q, want empty", apiKey)
	}
}

func TestGetSessionIDNoSession(t *testing.T) {
	client := NewClient("http://localhost:3000")

	_, err := client.GetSessionID()
	if err != ErrSession {
		t.Errorf("GetSessionID error = %v, want ErrSession", err)
	}
}

func TestMockModeDetection(t *testing.T) {
	tests := []struct {
		url      string
		wantMock bool
	}{
		{"http://localhost:3000", true},
		{"http://127.0.0.1:3000", true},
		{"https://localhost:3000", true},
		{"https://127.0.0.1:3000", true},
		{"https://enclave.example.com", false},
		{"https://api.opensecret.cloud", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			client := NewClient(tt.url)
			if client.useMockAttestation != tt.wantMock {
				t.Errorf("useMockAttestation = %v, want %v", client.useMockAttestation, tt.wantMock)
			}
		})
	}
}

func TestURLNormalization(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://localhost:3000", "http://localhost:3000"},
		{"http://localhost:3000/", "http://localhost:3000"},
		{"http://localhost:3000//", "http://localhost:3000/"},
		{"https://api.example.com/", "https://api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			client := NewClient(tt.input)
			if client.baseURL != tt.want {
				t.Errorf("baseURL = %q, want %q", client.baseURL, tt.want)
			}
		})
	}
}

func TestGetAccessTokenNoSession(t *testing.T) {
	client := NewClient("http://localhost:3000")

	token := client.GetAccessToken()
	if token != "" {
		t.Errorf("GetAccessToken = %q, want empty", token)
	}
}

func TestGetRefreshTokenNoSession(t *testing.T) {
	client := NewClient("http://localhost:3000")

	token := client.GetRefreshTokenValue()
	if token != "" {
		t.Errorf("GetRefreshTokenValue = %q, want empty", token)
	}
}

func TestBoolPtr(t *testing.T) {
	truePtr := boolPtr(true)
	falsePtr := boolPtr(false)

	if *truePtr != true {
		t.Error("boolPtr(true) should return pointer to true")
	}

	if *falsePtr != false {
		t.Error("boolPtr(false) should return pointer to false")
	}
}

func TestEmbeddingInputMarshal(t *testing.T) {
	// Test single string
	single := NewSingleEmbeddingInput("hello")
	data, err := single.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if string(data) != `"hello"` {
		t.Errorf("MarshalJSON = %s, want %q", data, `"hello"`)
	}

	// Test multiple strings
	multiple := NewMultipleEmbeddingInput([]string{"hello", "world"})
	data, err = multiple.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if string(data) != `["hello","world"]` {
		t.Errorf("MarshalJSON = %s, want %s", data, `["hello","world"]`)
	}
}

func TestEmbeddingInputUnmarshal(t *testing.T) {
	// Test single string
	var single EmbeddingInput
	err := single.UnmarshalJSON([]byte(`"hello"`))
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if single.Single == nil || *single.Single != "hello" {
		t.Errorf("UnmarshalJSON single = %v, want 'hello'", single.Single)
	}

	// Test multiple strings
	var multiple EmbeddingInput
	err = multiple.UnmarshalJSON([]byte(`["hello","world"]`))
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if len(multiple.Multiple) != 2 || multiple.Multiple[0] != "hello" || multiple.Multiple[1] != "world" {
		t.Errorf("UnmarshalJSON multiple = %v, want [hello, world]", multiple.Multiple)
	}
}

func TestAPIErrorFormat(t *testing.T) {
	err := NewAPIError(404, "Not Found")

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("Error should contain status code: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "Not Found") {
		t.Errorf("Error should contain message: %s", err.Error())
	}
}

func TestErrorTypeWrapping(t *testing.T) {
	cause := NewAPIError(500, "Server Error")
	err := NewSessionError("session failed", cause)

	if err.Type != ErrTypeSession {
		t.Errorf("Error type = %v, want ErrTypeSession", err.Type)
	}

	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}

	if !strings.Contains(err.Error(), "session failed") {
		t.Errorf("Error should contain message: %s", err.Error())
	}

	if !strings.Contains(err.Error(), "Server Error") {
		t.Errorf("Error should contain cause: %s", err.Error())
	}
}

func TestErrorWithoutCause(t *testing.T) {
	err := NewSessionError("simple error", nil)

	if err.Unwrap() != nil {
		t.Error("Unwrap should return nil for error without cause")
	}

	if err.Error() != "simple error" {
		t.Errorf("Error = %q, want %q", err.Error(), "simple error")
	}
}
