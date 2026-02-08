package opensecret

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SessionState represents the current session state
type SessionState struct {
	SessionID  uuid.UUID
	SessionKey [32]byte
}

// Clone creates a copy of the session state
func (s *SessionState) Clone() *SessionState {
	if s == nil {
		return nil
	}
	return &SessionState{
		SessionID:  s.SessionID,
		SessionKey: s.SessionKey,
	}
}

// TokenPair holds access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// Clone creates a copy of the token pair
func (t *TokenPair) Clone() *TokenPair {
	if t == nil {
		return nil
	}
	return &TokenPair{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
}

// EncryptedRequest represents an encrypted API request
type EncryptedRequest struct {
	Encrypted string `json:"encrypted"`
}

// EncryptedResponse represents an encrypted API response
type EncryptedResponse struct {
	Encrypted string `json:"encrypted"`
}

// AttestationResponse represents the attestation document response
type AttestationResponse struct {
	AttestationDocument string `json:"attestation_document"`
}

// KeyExchangeRequest represents a key exchange request
type KeyExchangeRequest struct {
	ClientPublicKey string `json:"client_public_key"`
	Nonce           string `json:"nonce"`
}

// KeyExchangeResponse represents a key exchange response
type KeyExchangeResponse struct {
	EncryptedSessionKey string `json:"encrypted_session_key"`
	SessionID           string `json:"session_id"`
}

// LoginCredentials represents login credentials
type LoginCredentials struct {
	Email    *string   `json:"email,omitempty"`
	ID       *uuid.UUID `json:"id,omitempty"`
	Password string    `json:"password"`
	ClientID uuid.UUID `json:"client_id"`
}

// RegisterCredentials represents registration credentials
type RegisterCredentials struct {
	Email    *string   `json:"email,omitempty"`
	Name     *string   `json:"name,omitempty"`
	Password string    `json:"password"`
	ClientID uuid.UUID `json:"client_id"`
}

// LoginResponse represents a login/register response
type LoginResponse struct {
	ID           uuid.UUID `json:"id"`
	Email        *string   `json:"email,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse represents a token refresh response
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// LoginMethod represents the method used to log in
type LoginMethod string

const (
	LoginMethodEmail  LoginMethod = "email"
	LoginMethodGithub LoginMethod = "github"
	LoginMethodGoogle LoginMethod = "google"
	LoginMethodApple  LoginMethod = "apple"
	LoginMethodGuest  LoginMethod = "guest"
)

// AppUser represents a user profile
type AppUser struct {
	ID            uuid.UUID   `json:"id"`
	Name          *string     `json:"name,omitempty"`
	Email         *string     `json:"email,omitempty"`
	EmailVerified bool        `json:"email_verified"`
	LoginMethod   LoginMethod `json:"login_method"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// UserResponse wraps an AppUser
type UserResponse struct {
	User AppUser `json:"user"`
}

// KVListItem represents a key-value storage item
type KVListItem struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// KeyOptions represents key derivation options
type KeyOptions struct {
	PrivateKeyDerivationPath  *string `json:"private_key_derivation_path,omitempty"`
	SeedPhraseDerivationPath  *string `json:"seed_phrase_derivation_path,omitempty"`
}

// PrivateKeyResponse represents a private key response
type PrivateKeyResponse struct {
	Mnemonic string `json:"mnemonic"`
}

// PrivateKeyBytesResponse represents a private key bytes response
type PrivateKeyBytesResponse struct {
	PrivateKey string `json:"private_key"` // Hex encoded
}

// SigningAlgorithm represents a signing algorithm
type SigningAlgorithm string

const (
	SigningAlgorithmSchnorr SigningAlgorithm = "schnorr"
	SigningAlgorithmEcdsa   SigningAlgorithm = "ecdsa"
)

// SignMessageRequest represents a sign message request
type SignMessageRequest struct {
	MessageBase64 string            `json:"message_base64"`
	Algorithm     SigningAlgorithm  `json:"algorithm"`
	KeyOptions    *SigningKeyOptions `json:"key_options,omitempty"`
}

// SigningKeyOptions represents key options for signing
type SigningKeyOptions struct {
	PrivateKeyDerivationPath *string `json:"private_key_derivation_path,omitempty"`
	SeedPhraseDerivationPath *string `json:"seed_phrase_derivation_path,omitempty"`
}

// SignMessageResponse represents a sign message response
type SignMessageResponse struct {
	Signature   string `json:"signature"`    // Base64 encoded
	MessageHash string `json:"message_hash"` // Hex encoded
}

// PublicKeyResponse represents a public key response
type PublicKeyResponse struct {
	PublicKey string           `json:"public_key"` // Hex encoded
	Algorithm SigningAlgorithm `json:"algorithm"`
}

// ThirdPartyTokenRequest represents a third party token request
type ThirdPartyTokenRequest struct {
	Audience *string `json:"audience,omitempty"`
}

// ThirdPartyTokenResponse represents a third party token response
type ThirdPartyTokenResponse struct {
	Token string `json:"token"`
}

// EncryptDataRequest represents an encrypt data request
type EncryptDataRequest struct {
	Data       string                 `json:"data"`
	KeyOptions *EncryptionKeyOptions  `json:"key_options,omitempty"`
}

// EncryptionKeyOptions represents key options for encryption
type EncryptionKeyOptions struct {
	PrivateKeyDerivationPath *string `json:"private_key_derivation_path,omitempty"`
	SeedPhraseDerivationPath *string `json:"seed_phrase_derivation_path,omitempty"`
}

// EncryptDataResponse represents an encrypt data response
type EncryptDataResponse struct {
	EncryptedData string `json:"encrypted_data"`
}

// DecryptDataRequest represents a decrypt data request
type DecryptDataRequest struct {
	EncryptedData string                `json:"encrypted_data"`
	KeyOptions    *EncryptionKeyOptions `json:"key_options,omitempty"`
}

// ChangePasswordRequest represents a change password request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Email        string    `json:"email"`
	HashedSecret string    `json:"hashed_secret"`
	ClientID     uuid.UUID `json:"client_id"`
}

// PasswordResetConfirmRequest represents a password reset confirmation
type PasswordResetConfirmRequest struct {
	Email            string    `json:"email"`
	AlphanumericCode string    `json:"alphanumeric_code"`
	PlaintextSecret  string    `json:"plaintext_secret"`
	NewPassword      string    `json:"new_password"`
	ClientID         uuid.UUID `json:"client_id"`
}

// ConvertGuestToEmailRequest represents a guest to email conversion request
type ConvertGuestToEmailRequest struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	Name     *string `json:"name,omitempty"`
}

// RequestVerificationCodeRequest represents a verification code request
type RequestVerificationCodeRequest struct{}

// InitiateAccountDeletionRequest represents an account deletion initiation
type InitiateAccountDeletionRequest struct {
	HashedSecret string `json:"hashed_secret"`
}

// ConfirmAccountDeletionRequest represents an account deletion confirmation
type ConfirmAccountDeletionRequest struct {
	ConfirmationCode string `json:"confirmation_code"`
	PlaintextSecret  string `json:"plaintext_secret"`
}

// ApiKey represents an API key
type ApiKey struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// ApiKeyListResponse represents an API key list response
type ApiKeyListResponse struct {
	Keys []ApiKey `json:"keys"`
}

// ApiKeyCreateRequest represents an API key creation request
type ApiKeyCreateRequest struct {
	Name string `json:"name"`
}

// ApiKeyCreateResponse represents an API key creation response
type ApiKeyCreateResponse struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// ConversationsDeleteResponse represents a conversations delete response
type ConversationsDeleteResponse struct {
	Object  string `json:"object"`
	Deleted bool   `json:"deleted"`
}

// BatchDeleteConversationsRequest represents a batch delete request
type BatchDeleteConversationsRequest struct {
	IDs []string `json:"ids"`
}

// BatchDeleteItemResult represents a batch delete item result
type BatchDeleteItemResult struct {
	ID      string  `json:"id"`
	Object  string  `json:"object"`
	Deleted bool    `json:"deleted"`
	Error   *string `json:"error,omitempty"`
}

// BatchDeleteConversationsResponse represents a batch delete response
type BatchDeleteConversationsResponse struct {
	Object string                  `json:"object"`
	Data   []BatchDeleteItemResult `json:"data"`
}

// Model represents an AI model
type Model struct {
	ID      string  `json:"id"`
	Object  string  `json:"object"`
	Created *int64  `json:"created,omitempty"`
	OwnedBy *string `json:"owned_by,omitempty"`
}

// ModelsResponse represents a models list response
type ModelsResponse struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

// Tool represents a tool/function definition
type Tool struct {
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

// Function represents a function definition
type Function struct {
	Name        string      `json:"name"`
	Description *string     `json:"description,omitempty"`
	Parameters  interface{} `json:"parameters"`
}

// ToolCall represents a tool call from the model
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
	Index    *int         `json:"index,omitempty"`
}

// FunctionCall represents a function call
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatMessage represents a chat message
type ChatMessage struct {
	Role             string      `json:"role"`
	Content          interface{} `json:"content"` // Can be string or array
	ToolCalls        []ToolCall  `json:"tool_calls,omitempty"`
	ReasoningContent *string     `json:"reasoning_content,omitempty"`
}

// StreamOptions represents streaming options
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// ChatCompletionRequest represents a chat completion request
type ChatCompletionRequest struct {
	Model         string         `json:"model"`
	Messages      []ChatMessage  `json:"messages"`
	Temperature   *float32       `json:"temperature,omitempty"`
	MaxTokens     *int           `json:"max_tokens,omitempty"`
	Stream        *bool          `json:"stream,omitempty"`
	StreamOptions *StreamOptions `json:"stream_options,omitempty"`
	Tools         []Tool         `json:"tools,omitempty"`
	ToolChoice    interface{}    `json:"tool_choice,omitempty"`
}

// Usage represents token usage
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatChoice represents a chat completion choice
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason *string     `json:"finish_reason,omitempty"`
}

// ChatCompletionResponse represents a chat completion response
type ChatCompletionResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   *Usage       `json:"usage,omitempty"`
}

// ChatMessageDelta represents a delta in a streaming response
type ChatMessageDelta struct {
	Role             *string     `json:"role,omitempty"`
	Content          interface{} `json:"content,omitempty"`
	ToolCalls        []ToolCall  `json:"tool_calls,omitempty"`
	ReasoningContent *string     `json:"reasoning_content,omitempty"`
}

// ChatChoiceDelta represents a streaming choice
type ChatChoiceDelta struct {
	Index        int              `json:"index"`
	Delta        ChatMessageDelta `json:"delta"`
	FinishReason *string          `json:"finish_reason,omitempty"`
}

// ChatCompletionChunk represents a streaming chunk
type ChatCompletionChunk struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []ChatChoiceDelta `json:"choices"`
	Usage   *Usage            `json:"usage,omitempty"`
}

// EmbeddingInput can be a single string or array of strings
type EmbeddingInput struct {
	Single   *string
	Multiple []string
}

// MarshalJSON implements json.Marshaler
func (e EmbeddingInput) MarshalJSON() ([]byte, error) {
	if e.Single != nil {
		return json.Marshal(*e.Single)
	}
	return json.Marshal(e.Multiple)
}

// UnmarshalJSON implements json.Unmarshaler
func (e *EmbeddingInput) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		e.Single = &single
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		e.Multiple = multiple
		return nil
	}

	return NewSerializationError("invalid embedding input", nil)
}

// NewSingleEmbeddingInput creates an EmbeddingInput from a single string
func NewSingleEmbeddingInput(s string) EmbeddingInput {
	return EmbeddingInput{Single: &s}
}

// NewMultipleEmbeddingInput creates an EmbeddingInput from multiple strings
func NewMultipleEmbeddingInput(s []string) EmbeddingInput {
	return EmbeddingInput{Multiple: s}
}

// EmbeddingRequest represents an embedding request
type EmbeddingRequest struct {
	Input          EmbeddingInput `json:"input"`
	Model          string         `json:"model"`
	EncodingFormat *string        `json:"encoding_format,omitempty"`
	Dimensions     *int           `json:"dimensions,omitempty"`
	User           *string        `json:"user,omitempty"`
}

// EmbeddingData represents embedding data
type EmbeddingData struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// EmbeddingUsage represents embedding usage
type EmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// EmbeddingResponse represents an embedding response
type EmbeddingResponse struct {
	Object string          `json:"object"`
	Data   []EmbeddingData `json:"data"`
	Model  string          `json:"model"`
	Usage  EmbeddingUsage  `json:"usage"`
}
