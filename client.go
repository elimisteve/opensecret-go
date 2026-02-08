package opensecret

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// OpenSecretClient provides methods to interact with the OpenSecret TEE API
type OpenSecretClient struct {
	httpClient         *http.Client
	baseURL            string
	sessionManager     *SessionManager
	verifier           *AttestationVerifier
	serverPublicKey    []byte
	serverPublicKeyMu  sync.RWMutex
	useMockAttestation bool
}

// NewClient creates a new OpenSecret client
func NewClient(baseURL string) *OpenSecretClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	useMock := strings.Contains(baseURL, "localhost") || strings.Contains(baseURL, "127.0.0.1")

	return &OpenSecretClient{
		httpClient:         &http.Client{},
		baseURL:            baseURL,
		sessionManager:     NewSessionManager(),
		verifier:           NewAttestationVerifier().WithAllowDebug(useMock),
		useMockAttestation: useMock,
	}
}

// NewClientWithAPIKey creates a new OpenSecret client with an API key
func NewClientWithAPIKey(baseURL, apiKey string) *OpenSecretClient {
	client := NewClient(baseURL)
	client.sessionManager.SetAPIKey(apiKey)
	return client
}

// SetAPIKey sets the API key
func (c *OpenSecretClient) SetAPIKey(apiKey string) {
	c.sessionManager.SetAPIKey(apiKey)
}

// ClearAPIKey clears the API key
func (c *OpenSecretClient) ClearAPIKey() {
	c.sessionManager.ClearAPIKey()
}

// GetSessionID returns the current session ID
func (c *OpenSecretClient) GetSessionID() (uuid.UUID, error) {
	session := c.sessionManager.GetSession()
	if session == nil {
		return uuid.Nil, ErrSession
	}
	return session.SessionID, nil
}

// PerformAttestationHandshake establishes a secure session with the TEE
func (c *OpenSecretClient) PerformAttestationHandshake(ctx context.Context) error {
	// Generate a nonce
	nonce := uuid.New().String()

	// Step 1: Get attestation document
	attestationResp, err := c.getAttestationDocument(ctx, nonce)
	if err != nil {
		return err
	}

	// Step 2: Parse and verify attestation document
	var doc *AttestationDocument
	if !c.useMockAttestation {
		doc, err = c.verifier.VerifyAttestationDocument(attestationResp.AttestationDocument, nonce)
		if err != nil {
			return err
		}
	} else {
		// For mock mode, extract without full verification
		doc, err = ParseMockAttestation(attestationResp.AttestationDocument)
		if err != nil {
			return err
		}
	}

	// Store server's public key from attestation document
	if len(doc.PublicKey) == 0 {
		return NewAttestationError("no public key in attestation document", nil)
	}

	c.serverPublicKeyMu.Lock()
	c.serverPublicKey = make([]byte, len(doc.PublicKey))
	copy(c.serverPublicKey, doc.PublicKey)
	c.serverPublicKeyMu.Unlock()

	// Step 3: Perform key exchange
	return c.performKeyExchange(ctx, nonce)
}

func (c *OpenSecretClient) getAttestationDocument(ctx context.Context, nonce string) (*AttestationResponse, error) {
	reqURL := fmt.Sprintf("%s/attestation/%s", c.baseURL, nonce)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, NewAPIError(0, fmt.Sprintf("failed to create request: %v", err))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, NewAPIError(0, fmt.Sprintf("request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, NewAPIError(resp.StatusCode, string(body))
	}

	var attestationResp AttestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attestationResp); err != nil {
		return nil, NewSerializationError("failed to decode attestation response", err)
	}

	return &attestationResp, nil
}

func (c *OpenSecretClient) performKeyExchange(ctx context.Context, nonce string) error {
	// Generate client keypair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return err
	}

	// Get server's public key
	c.serverPublicKeyMu.RLock()
	serverPubKey := c.serverPublicKey
	c.serverPublicKeyMu.RUnlock()

	if len(serverPubKey) != KeySize {
		return NewKeyExchangeError("invalid server public key length", nil)
	}

	// Prepare key exchange request
	keyExchangeReq := KeyExchangeRequest{
		ClientPublicKey: base64.StdEncoding.EncodeToString(keyPair.PublicKey[:]),
		Nonce:           nonce,
	}

	body, err := json.Marshal(keyExchangeReq)
	if err != nil {
		return NewSerializationError("failed to encode key exchange request", err)
	}

	reqURL := fmt.Sprintf("%s/key_exchange", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("failed to create request: %v", err))
	}
	req.Header.Set("Content-Type", "application/json")

	// Add authorization if we have a token
	if token := c.sessionManager.GetAccessToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("key exchange request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return NewAPIError(resp.StatusCode, string(respBody))
	}

	var keyExchangeResp KeyExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyExchangeResp); err != nil {
		return NewSerializationError("failed to decode key exchange response", err)
	}

	// Perform ECDH
	var serverPubKeyArr [KeySize]byte
	copy(serverPubKeyArr[:], serverPubKey)

	sharedSecret, err := DeriveSharedSecret(&keyPair.PrivateKey, &serverPubKeyArr)
	if err != nil {
		return err
	}

	// Decrypt session key
	sessionKey, err := DecryptSessionKey(&sharedSecret, keyExchangeResp.EncryptedSessionKey)
	if err != nil {
		return err
	}

	// Parse session ID
	sessionID, err := uuid.Parse(keyExchangeResp.SessionID)
	if err != nil {
		return NewSessionError("invalid session ID format", err)
	}

	// Store session
	c.sessionManager.SetSession(sessionID, sessionKey)

	return nil
}

// TestConnection tests the connection to the server
func (c *OpenSecretClient) TestConnection(ctx context.Context) (string, error) {
	reqURL := fmt.Sprintf("%s/health-check", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", NewAPIError(0, fmt.Sprintf("failed to create request: %v", err))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", NewAPIError(0, fmt.Sprintf("request failed: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewAPIError(0, fmt.Sprintf("failed to read response: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		return "", NewAPIError(resp.StatusCode, string(body))
	}

	return string(body), nil
}

// encryptedAPICall makes an encrypted API call
func (c *OpenSecretClient) encryptedAPICall(ctx context.Context, endpoint, method string, data interface{}, result interface{}) error {
	session := c.sessionManager.GetSession()
	if session == nil {
		return NewSessionError("no active session - call PerformAttestationHandshake first", nil)
	}

	reqURL := c.baseURL + endpoint

	// Encrypt request data if provided
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return NewSerializationError("failed to encode request data", err)
		}

		encrypted, err := EncryptData(&session.SessionKey, jsonData)
		if err != nil {
			return err
		}

		encReq := EncryptedRequest{
			Encrypted: base64.StdEncoding.EncodeToString(encrypted),
		}

		encBody, err := json.Marshal(encReq)
		if err != nil {
			return NewSerializationError("failed to encode encrypted request", err)
		}

		body = bytes.NewReader(encBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("failed to create request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-session-id", session.SessionID.String())

	// Add JWT authorization (not API key for regular endpoints)
	if token := c.sessionManager.GetAccessToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("request failed: %v", err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("failed to read response: %v", err))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewAPIError(resp.StatusCode, string(respBody))
	}

	// Decrypt response
	var encResp EncryptedResponse
	if err := json.Unmarshal(respBody, &encResp); err != nil {
		return NewSerializationError("failed to decode encrypted response", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encResp.Encrypted)
	if err != nil {
		return NewDecryptionError("failed to decode response", err)
	}

	decrypted, err := DecryptData(&session.SessionKey, encryptedBytes)
	if err != nil {
		return err
	}

	if result != nil {
		if err := json.Unmarshal(decrypted, result); err != nil {
			return NewSerializationError("failed to decode response data", err)
		}
	}

	return nil
}

// encryptedOpenAICall makes an encrypted API call for OpenAI endpoints
// This supports both API key and JWT authentication, with API key taking priority
func (c *OpenSecretClient) encryptedOpenAICall(ctx context.Context, endpoint, method string, data interface{}, result interface{}) error {
	session := c.sessionManager.GetSession()
	if session == nil {
		return NewSessionError("no active session - call PerformAttestationHandshake first", nil)
	}

	reqURL := c.baseURL + endpoint

	// Encrypt request data if provided
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return NewSerializationError("failed to encode request data", err)
		}

		encrypted, err := EncryptData(&session.SessionKey, jsonData)
		if err != nil {
			return err
		}

		encReq := EncryptedRequest{
			Encrypted: base64.StdEncoding.EncodeToString(encrypted),
		}

		encBody, err := json.Marshal(encReq)
		if err != nil {
			return NewSerializationError("failed to encode encrypted request", err)
		}

		body = bytes.NewReader(encBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("failed to create request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-session-id", session.SessionID.String())

	// For OpenAI endpoints: Prefer API key over JWT token
	if apiKey := c.sessionManager.GetAPIKey(); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else if token := c.sessionManager.GetAccessToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("request failed: %v", err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewAPIError(0, fmt.Sprintf("failed to read response: %v", err))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewAPIError(resp.StatusCode, string(respBody))
	}

	// Decrypt response
	var encResp EncryptedResponse
	if err := json.Unmarshal(respBody, &encResp); err != nil {
		return NewSerializationError("failed to decode encrypted response", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encResp.Encrypted)
	if err != nil {
		return NewDecryptionError("failed to decode response", err)
	}

	decrypted, err := DecryptData(&session.SessionKey, encryptedBytes)
	if err != nil {
		return err
	}

	if result != nil {
		if err := json.Unmarshal(decrypted, result); err != nil {
			return NewSerializationError("failed to decode response data", err)
		}
	}

	return nil
}

// Login authenticates a user with email and password
func (c *OpenSecretClient) Login(ctx context.Context, email, password string, clientID uuid.UUID) (*LoginResponse, error) {
	credentials := LoginCredentials{
		Email:    &email,
		Password: password,
		ClientID: clientID,
	}

	var response LoginResponse
	if err := c.encryptedAPICall(ctx, "/login", http.MethodPost, credentials, &response); err != nil {
		return nil, err
	}

	c.sessionManager.SetTokens(response.AccessToken, response.RefreshToken)
	return &response, nil
}

// LoginWithID authenticates a user with ID and password
func (c *OpenSecretClient) LoginWithID(ctx context.Context, id uuid.UUID, password string, clientID uuid.UUID) (*LoginResponse, error) {
	credentials := LoginCredentials{
		ID:       &id,
		Password: password,
		ClientID: clientID,
	}

	var response LoginResponse
	if err := c.encryptedAPICall(ctx, "/login", http.MethodPost, credentials, &response); err != nil {
		return nil, err
	}

	c.sessionManager.SetTokens(response.AccessToken, response.RefreshToken)
	return &response, nil
}

// Register creates a new user account
func (c *OpenSecretClient) Register(ctx context.Context, email, password string, clientID uuid.UUID, name *string) (*LoginResponse, error) {
	credentials := RegisterCredentials{
		Email:    &email,
		Name:     name,
		Password: password,
		ClientID: clientID,
	}

	var response LoginResponse
	if err := c.encryptedAPICall(ctx, "/register", http.MethodPost, credentials, &response); err != nil {
		return nil, err
	}

	c.sessionManager.SetTokens(response.AccessToken, response.RefreshToken)
	return &response, nil
}

// RegisterGuest creates a new guest account
func (c *OpenSecretClient) RegisterGuest(ctx context.Context, password string, clientID uuid.UUID) (*LoginResponse, error) {
	credentials := RegisterCredentials{
		Password: password,
		ClientID: clientID,
	}

	var response LoginResponse
	if err := c.encryptedAPICall(ctx, "/register", http.MethodPost, credentials, &response); err != nil {
		return nil, err
	}

	c.sessionManager.SetTokens(response.AccessToken, response.RefreshToken)
	return &response, nil
}

// RefreshToken refreshes the access token
func (c *OpenSecretClient) RefreshToken(ctx context.Context) error {
	refreshToken := c.sessionManager.GetRefreshToken()
	if refreshToken == "" {
		return ErrNoRefreshToken
	}

	request := RefreshRequest{RefreshToken: refreshToken}

	var response RefreshResponse
	if err := c.encryptedAPICall(ctx, "/refresh", http.MethodPost, request, &response); err != nil {
		return err
	}

	c.sessionManager.SetTokens(response.AccessToken, response.RefreshToken)
	return nil
}

// Logout logs out the current user
func (c *OpenSecretClient) Logout(ctx context.Context) error {
	refreshToken := c.sessionManager.GetRefreshToken()
	if refreshToken == "" {
		return ErrNoRefreshToken
	}

	request := LogoutRequest{RefreshToken: refreshToken}

	var response json.RawMessage
	if err := c.encryptedAPICall(ctx, "/logout", http.MethodPost, request, &response); err != nil {
		return err
	}

	c.sessionManager.ClearAll()
	return nil
}

// GetAccessToken returns the current access token
func (c *OpenSecretClient) GetAccessToken() string {
	return c.sessionManager.GetAccessToken()
}

// GetRefreshTokenValue returns the current refresh token
func (c *OpenSecretClient) GetRefreshTokenValue() string {
	return c.sessionManager.GetRefreshToken()
}

// GetUser retrieves the current user's profile
func (c *OpenSecretClient) GetUser(ctx context.Context) (*UserResponse, error) {
	var response UserResponse
	if err := c.encryptedAPICall(ctx, "/protected/user", http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateAPIKey creates a new API key
func (c *OpenSecretClient) CreateAPIKey(ctx context.Context, name string) (*ApiKeyCreateResponse, error) {
	request := ApiKeyCreateRequest{Name: name}

	var response ApiKeyCreateResponse
	if err := c.encryptedAPICall(ctx, "/protected/api-keys", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// ListAPIKeys lists all API keys
func (c *OpenSecretClient) ListAPIKeys(ctx context.Context) ([]ApiKey, error) {
	var response ApiKeyListResponse
	if err := c.encryptedAPICall(ctx, "/protected/api-keys", http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return response.Keys, nil
}

// DeleteAPIKey deletes an API key by name
func (c *OpenSecretClient) DeleteAPIKey(ctx context.Context, name string) error {
	endpoint := "/protected/api-keys/" + url.PathEscape(name)
	var response json.RawMessage
	return c.encryptedAPICall(ctx, endpoint, http.MethodDelete, nil, &response)
}

// KVGet retrieves a value from key-value storage
func (c *OpenSecretClient) KVGet(ctx context.Context, key string) (string, error) {
	endpoint := "/protected/kv/" + url.PathEscape(key)
	var response string
	if err := c.encryptedAPICall(ctx, endpoint, http.MethodGet, nil, &response); err != nil {
		return "", err
	}
	return response, nil
}

// KVPut stores a value in key-value storage
func (c *OpenSecretClient) KVPut(ctx context.Context, key, value string) (string, error) {
	endpoint := "/protected/kv/" + url.PathEscape(key)
	var response string
	if err := c.encryptedAPICall(ctx, endpoint, http.MethodPut, value, &response); err != nil {
		return "", err
	}
	return response, nil
}

// KVDelete deletes a value from key-value storage
func (c *OpenSecretClient) KVDelete(ctx context.Context, key string) error {
	endpoint := "/protected/kv/" + url.PathEscape(key)
	var response json.RawMessage
	return c.encryptedAPICall(ctx, endpoint, http.MethodDelete, nil, &response)
}

// KVDeleteAll deletes all values from key-value storage
func (c *OpenSecretClient) KVDeleteAll(ctx context.Context) error {
	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/protected/kv", http.MethodDelete, nil, &response)
}

// KVList lists all key-value pairs
func (c *OpenSecretClient) KVList(ctx context.Context) ([]KVListItem, error) {
	var response []KVListItem
	if err := c.encryptedAPICall(ctx, "/protected/kv", http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetPrivateKey retrieves the user's private key (mnemonic)
func (c *OpenSecretClient) GetPrivateKey(ctx context.Context, options *KeyOptions) (*PrivateKeyResponse, error) {
	endpoint := "/protected/private_key"
	if options != nil {
		params := url.Values{}
		if options.SeedPhraseDerivationPath != nil {
			params.Set("seed_phrase_derivation_path", *options.SeedPhraseDerivationPath)
		}
		if options.PrivateKeyDerivationPath != nil {
			params.Set("private_key_derivation_path", *options.PrivateKeyDerivationPath)
		}
		if len(params) > 0 {
			endpoint += "?" + params.Encode()
		}
	}

	var response PrivateKeyResponse
	if err := c.encryptedAPICall(ctx, endpoint, http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetPrivateKeyBytes retrieves the user's private key bytes
func (c *OpenSecretClient) GetPrivateKeyBytes(ctx context.Context, options *KeyOptions) (*PrivateKeyBytesResponse, error) {
	endpoint := "/protected/private_key_bytes"
	if options != nil {
		params := url.Values{}
		if options.SeedPhraseDerivationPath != nil {
			params.Set("seed_phrase_derivation_path", *options.SeedPhraseDerivationPath)
		}
		if options.PrivateKeyDerivationPath != nil {
			params.Set("private_key_derivation_path", *options.PrivateKeyDerivationPath)
		}
		if len(params) > 0 {
			endpoint += "?" + params.Encode()
		}
	}

	var response PrivateKeyBytesResponse
	if err := c.encryptedAPICall(ctx, endpoint, http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// SignMessage signs a message
func (c *OpenSecretClient) SignMessage(ctx context.Context, message []byte, algorithm SigningAlgorithm, keyOptions *KeyOptions) (*SignMessageResponse, error) {
	request := SignMessageRequest{
		MessageBase64: base64.StdEncoding.EncodeToString(message),
		Algorithm:     algorithm,
	}
	if keyOptions != nil {
		request.KeyOptions = &SigningKeyOptions{
			PrivateKeyDerivationPath: keyOptions.PrivateKeyDerivationPath,
			SeedPhraseDerivationPath: keyOptions.SeedPhraseDerivationPath,
		}
	}

	var response SignMessageResponse
	if err := c.encryptedAPICall(ctx, "/protected/sign_message", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetPublicKey retrieves the user's public key
func (c *OpenSecretClient) GetPublicKey(ctx context.Context, algorithm SigningAlgorithm, keyOptions *KeyOptions) (*PublicKeyResponse, error) {
	params := url.Values{}
	params.Set("algorithm", string(algorithm))
	if keyOptions != nil {
		if keyOptions.PrivateKeyDerivationPath != nil {
			params.Set("private_key_derivation_path", *keyOptions.PrivateKeyDerivationPath)
		}
		if keyOptions.SeedPhraseDerivationPath != nil {
			params.Set("seed_phrase_derivation_path", *keyOptions.SeedPhraseDerivationPath)
		}
	}

	endpoint := "/protected/public_key?" + params.Encode()

	var response PublicKeyResponse
	if err := c.encryptedAPICall(ctx, endpoint, http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GenerateThirdPartyToken generates a token for third party services
func (c *OpenSecretClient) GenerateThirdPartyToken(ctx context.Context, audience *string) (*ThirdPartyTokenResponse, error) {
	request := ThirdPartyTokenRequest{Audience: audience}

	var response ThirdPartyTokenResponse
	if err := c.encryptedAPICall(ctx, "/protected/third_party_token", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// EncryptUserData encrypts data using the user's key
func (c *OpenSecretClient) EncryptUserData(ctx context.Context, data string, keyOptions *KeyOptions) (*EncryptDataResponse, error) {
	request := EncryptDataRequest{Data: data}
	if keyOptions != nil {
		request.KeyOptions = &EncryptionKeyOptions{
			PrivateKeyDerivationPath: keyOptions.PrivateKeyDerivationPath,
			SeedPhraseDerivationPath: keyOptions.SeedPhraseDerivationPath,
		}
	}

	var response EncryptDataResponse
	if err := c.encryptedAPICall(ctx, "/protected/encrypt", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// DecryptUserData decrypts data using the user's key
func (c *OpenSecretClient) DecryptUserData(ctx context.Context, encryptedData string, keyOptions *KeyOptions) (string, error) {
	request := DecryptDataRequest{EncryptedData: encryptedData}
	if keyOptions != nil {
		request.KeyOptions = &EncryptionKeyOptions{
			PrivateKeyDerivationPath: keyOptions.PrivateKeyDerivationPath,
			SeedPhraseDerivationPath: keyOptions.SeedPhraseDerivationPath,
		}
	}

	var response string
	if err := c.encryptedAPICall(ctx, "/protected/decrypt", http.MethodPost, request, &response); err != nil {
		return "", err
	}
	return response, nil
}

// ChangePassword changes the user's password
func (c *OpenSecretClient) ChangePassword(ctx context.Context, currentPassword, newPassword string) error {
	request := ChangePasswordRequest{
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}

	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/protected/change_password", http.MethodPost, request, &response)
}

// RequestPasswordReset requests a password reset
func (c *OpenSecretClient) RequestPasswordReset(ctx context.Context, email, hashedSecret string, clientID uuid.UUID) error {
	request := PasswordResetRequest{
		Email:        email,
		HashedSecret: hashedSecret,
		ClientID:     clientID,
	}

	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/password-reset/request", http.MethodPost, request, &response)
}

// ConfirmPasswordReset confirms a password reset
func (c *OpenSecretClient) ConfirmPasswordReset(ctx context.Context, email, code, plaintextSecret, newPassword string, clientID uuid.UUID) error {
	request := PasswordResetConfirmRequest{
		Email:            email,
		AlphanumericCode: code,
		PlaintextSecret:  plaintextSecret,
		NewPassword:      newPassword,
		ClientID:         clientID,
	}

	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/password-reset/confirm", http.MethodPost, request, &response)
}

// ConvertGuestToEmail converts a guest account to an email account
func (c *OpenSecretClient) ConvertGuestToEmail(ctx context.Context, email, password string, name *string) error {
	request := ConvertGuestToEmailRequest{
		Email:    email,
		Password: password,
		Name:     name,
	}

	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/protected/convert_guest", http.MethodPost, request, &response)
}

// VerifyEmail verifies an email address
func (c *OpenSecretClient) VerifyEmail(ctx context.Context, code string) error {
	endpoint := fmt.Sprintf("/verify-email/%s", code)
	var response json.RawMessage
	return c.encryptedAPICall(ctx, endpoint, http.MethodGet, nil, &response)
}

// RequestNewVerificationCode requests a new email verification code
func (c *OpenSecretClient) RequestNewVerificationCode(ctx context.Context) error {
	request := RequestVerificationCodeRequest{}
	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/protected/request_verification", http.MethodPost, request, &response)
}

// RequestAccountDeletion initiates account deletion
func (c *OpenSecretClient) RequestAccountDeletion(ctx context.Context, hashedSecret string) error {
	request := InitiateAccountDeletionRequest{HashedSecret: hashedSecret}
	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/protected/delete-account/request", http.MethodPost, request, &response)
}

// ConfirmAccountDeletion confirms account deletion
func (c *OpenSecretClient) ConfirmAccountDeletion(ctx context.Context, confirmationCode, plaintextSecret string) error {
	request := ConfirmAccountDeletionRequest{
		ConfirmationCode: confirmationCode,
		PlaintextSecret:  plaintextSecret,
	}
	var response json.RawMessage
	return c.encryptedAPICall(ctx, "/protected/delete-account/confirm", http.MethodPost, request, &response)
}

// DeleteConversations deletes all conversations
func (c *OpenSecretClient) DeleteConversations(ctx context.Context) (*ConversationsDeleteResponse, error) {
	var response ConversationsDeleteResponse
	if err := c.encryptedAPICall(ctx, "/v1/conversations", http.MethodDelete, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// BatchDeleteConversations deletes multiple conversations by ID
func (c *OpenSecretClient) BatchDeleteConversations(ctx context.Context, ids []string) (*BatchDeleteConversationsResponse, error) {
	request := BatchDeleteConversationsRequest{IDs: ids}

	var response BatchDeleteConversationsResponse
	if err := c.encryptedAPICall(ctx, "/v1/conversations/batch-delete", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetModels retrieves available AI models
func (c *OpenSecretClient) GetModels(ctx context.Context) (*ModelsResponse, error) {
	var response ModelsResponse
	if err := c.encryptedOpenAICall(ctx, "/v1/models", http.MethodGet, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateEmbeddings creates embeddings for the given input
func (c *OpenSecretClient) CreateEmbeddings(ctx context.Context, request EmbeddingRequest) (*EmbeddingResponse, error) {
	var response EmbeddingResponse
	if err := c.encryptedOpenAICall(ctx, "/v1/embeddings", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateChatCompletion creates a chat completion (non-streaming)
func (c *OpenSecretClient) CreateChatCompletion(ctx context.Context, request ChatCompletionRequest) (*ChatCompletionResponse, error) {
	request.Stream = boolPtr(false)

	var response ChatCompletionResponse
	if err := c.encryptedOpenAICall(ctx, "/v1/chat/completions", http.MethodPost, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateChatCompletionStream creates a streaming chat completion
// Returns a channel that will receive ChatCompletionChunk values
func (c *OpenSecretClient) CreateChatCompletionStream(ctx context.Context, request ChatCompletionRequest) (<-chan StreamEvent, error) {
	session := c.sessionManager.GetSession()
	if session == nil {
		return nil, NewSessionError("no active session - call PerformAttestationHandshake first", nil)
	}

	request.Stream = boolPtr(true)
	request.StreamOptions = &StreamOptions{IncludeUsage: true}

	// Encrypt the request
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, NewSerializationError("failed to encode request", err)
	}

	encrypted, err := EncryptData(&session.SessionKey, jsonData)
	if err != nil {
		return nil, err
	}

	encReq := EncryptedRequest{
		Encrypted: base64.StdEncoding.EncodeToString(encrypted),
	}

	encBody, err := json.Marshal(encReq)
	if err != nil {
		return nil, NewSerializationError("failed to encode encrypted request", err)
	}

	reqURL := c.baseURL + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(encBody))
	if err != nil {
		return nil, NewAPIError(0, fmt.Sprintf("failed to create request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("x-session-id", session.SessionID.String())

	// Prefer API key over JWT token
	if apiKey := c.sessionManager.GetAPIKey(); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else if token := c.sessionManager.GetAccessToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, NewAPIError(0, fmt.Sprintf("request failed: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, NewAPIError(resp.StatusCode, string(body))
	}

	// Create channel for events
	eventChan := make(chan StreamEvent, 100)

	// Start goroutine to read SSE events
	go func() {
		defer close(eventChan)
		defer resp.Body.Close()

		reader := bufio.NewReader(resp.Body)
		for {
			select {
			case <-ctx.Done():
				eventChan <- StreamEvent{Err: ctx.Err()}
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					eventChan <- StreamEvent{Err: err}
				}
				return
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Parse SSE event
			if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))

				// Check for [DONE]
				if data == "[DONE]" {
					return
				}

				// Decrypt the data
				encryptedBytes, err := base64.StdEncoding.DecodeString(data)
				if err != nil {
					eventChan <- StreamEvent{Err: NewDecryptionError("failed to decode event data", err)}
					continue
				}

				decrypted, err := DecryptData(&session.SessionKey, encryptedBytes)
				if err != nil {
					eventChan <- StreamEvent{Err: err}
					continue
				}

				var chunk ChatCompletionChunk
				if err := json.Unmarshal(decrypted, &chunk); err != nil {
					eventChan <- StreamEvent{Err: NewSerializationError("failed to decode chunk", err)}
					continue
				}

				eventChan <- StreamEvent{Chunk: &chunk}
			}
		}
	}()

	return eventChan, nil
}

// StreamEvent represents an event from the streaming API
type StreamEvent struct {
	Chunk *ChatCompletionChunk
	Err   error
}

func boolPtr(b bool) *bool {
	return &b
}
