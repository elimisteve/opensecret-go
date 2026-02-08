package opensecret

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize is the size of X25519 keys in bytes
	KeySize = 32
	// NonceSize is the size of ChaCha20-Poly1305 nonces
	NonceSize = 12
)

// KeyPair represents an X25519 key pair
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, NewCryptoError("failed to generate random bytes", err)
	}

	// Clamp the private key (X25519 requirement)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [KeySize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// DeriveSharedSecret performs X25519 ECDH to derive a shared secret
func DeriveSharedSecret(privateKey, peerPublicKey *[KeySize]byte) ([KeySize]byte, error) {
	var sharedSecret [KeySize]byte
	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return sharedSecret, NewKeyExchangeError("ECDH key exchange failed", err)
	}
	copy(sharedSecret[:], result)
	return sharedSecret, nil
}

// EncryptData encrypts data using ChaCha20-Poly1305
// Returns: 12-byte nonce || ciphertext with tag
func EncryptData(key *[KeySize]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, NewCryptoError("failed to create cipher", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, NewCryptoError("failed to generate nonce", err)
	}

	// Encrypt and prepend nonce
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// DecryptData decrypts data encrypted with EncryptData
// Input format: 12-byte nonce || ciphertext with tag
func DecryptData(key *[KeySize]byte, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < NonceSize {
		return nil, NewDecryptionError("encrypted data too short", nil)
	}

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, NewCryptoError("failed to create cipher", err)
	}

	nonce := encryptedData[:NonceSize]
	ciphertext := encryptedData[NonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, NewDecryptionError("decryption failed", err)
	}

	return plaintext, nil
}

// DecryptSessionKey decrypts a base64-encoded session key using the shared secret
func DecryptSessionKey(sharedSecret *[KeySize]byte, encryptedKeyB64 string) ([KeySize]byte, error) {
	var sessionKey [KeySize]byte

	encrypted, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return sessionKey, NewDecryptionError("failed to decode base64", err)
	}

	decrypted, err := DecryptData(sharedSecret, encrypted)
	if err != nil {
		return sessionKey, err
	}

	if len(decrypted) != KeySize {
		return sessionKey, NewDecryptionError("invalid session key length", nil)
	}

	copy(sessionKey[:], decrypted)
	return sessionKey, nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, NewCryptoError("failed to generate random bytes", err)
	}
	return b, nil
}

// EncryptMessage is an alias for EncryptData for API compatibility
func EncryptMessage(plaintext []byte, key *[KeySize]byte) ([]byte, error) {
	return EncryptData(key, plaintext)
}

// DecryptMessage is an alias for DecryptData for API compatibility
func DecryptMessage(ciphertext []byte, key *[KeySize]byte) ([]byte, error) {
	return DecryptData(key, ciphertext)
}
