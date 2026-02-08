// Package opensecret provides a Go client for the OpenSecret TEE API.
// It enables secure communication with Trusted Execution Environments (TEEs)
// using attestation verification and end-to-end encryption.
package opensecret

import (
	"errors"
	"fmt"
)

// Standard errors for the OpenSecret SDK
var (
	// ErrSession indicates no active session exists
	ErrSession = errors.New("no active session")

	// ErrNoRefreshToken indicates no refresh token is available
	ErrNoRefreshToken = errors.New("no refresh token available")

	// ErrNoServerPublicKey indicates the server public key is not available
	ErrNoServerPublicKey = errors.New("server public key not available")

	// ErrInvalidKeyLength indicates an invalid key length
	ErrInvalidKeyLength = errors.New("invalid key length")

	// ErrDataTooShort indicates encrypted data is too short
	ErrDataTooShort = errors.New("encrypted data too short")
)

// Error represents an OpenSecret SDK error
type Error struct {
	Type    ErrorType
	Message string
	Cause   error
}

// ErrorType categorizes errors
type ErrorType int

const (
	// ErrTypeSession indicates a session-related error
	ErrTypeSession ErrorType = iota
	// ErrTypeAttestation indicates an attestation verification error
	ErrTypeAttestation
	// ErrTypeCrypto indicates a cryptographic operation error
	ErrTypeCrypto
	// ErrTypeEncryption indicates an encryption error
	ErrTypeEncryption
	// ErrTypeDecryption indicates a decryption error
	ErrTypeDecryption
	// ErrTypeKeyExchange indicates a key exchange error
	ErrTypeKeyExchange
	// ErrTypeAuthentication indicates an authentication error
	ErrTypeAuthentication
	// ErrTypeAPI indicates an API error
	ErrTypeAPI
	// ErrTypeConfiguration indicates a configuration error
	ErrTypeConfiguration
	// ErrTypeSerialization indicates a serialization error
	ErrTypeSerialization
)

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// APIError represents an HTTP API error with status code
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// NewSessionError creates a new session error
func NewSessionError(message string, cause error) *Error {
	return &Error{Type: ErrTypeSession, Message: message, Cause: cause}
}

// NewAttestationError creates a new attestation error
func NewAttestationError(message string, cause error) *Error {
	return &Error{Type: ErrTypeAttestation, Message: message, Cause: cause}
}

// NewCryptoError creates a new crypto error
func NewCryptoError(message string, cause error) *Error {
	return &Error{Type: ErrTypeCrypto, Message: message, Cause: cause}
}

// NewEncryptionError creates a new encryption error
func NewEncryptionError(message string, cause error) *Error {
	return &Error{Type: ErrTypeEncryption, Message: message, Cause: cause}
}

// NewDecryptionError creates a new decryption error
func NewDecryptionError(message string, cause error) *Error {
	return &Error{Type: ErrTypeDecryption, Message: message, Cause: cause}
}

// NewKeyExchangeError creates a new key exchange error
func NewKeyExchangeError(message string, cause error) *Error {
	return &Error{Type: ErrTypeKeyExchange, Message: message, Cause: cause}
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string, cause error) *Error {
	return &Error{Type: ErrTypeAuthentication, Message: message, Cause: cause}
}

// NewAPIError creates a new API error with status code
func NewAPIError(statusCode int, message string) *APIError {
	return &APIError{StatusCode: statusCode, Message: message}
}

// NewConfigurationError creates a new configuration error
func NewConfigurationError(message string, cause error) *Error {
	return &Error{Type: ErrTypeConfiguration, Message: message, Cause: cause}
}

// NewSerializationError creates a new serialization error
func NewSerializationError(message string, cause error) *Error {
	return &Error{Type: ErrTypeSerialization, Message: message, Cause: cause}
}
