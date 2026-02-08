package opensecret

import (
	"encoding/base64"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	keypair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Public key should be 32 bytes
	if len(keypair.PublicKey) != KeySize {
		t.Errorf("Public key length = %d, want %d", len(keypair.PublicKey), KeySize)
	}

	// Private key should be 32 bytes
	if len(keypair.PrivateKey) != KeySize {
		t.Errorf("Private key length = %d, want %d", len(keypair.PrivateKey), KeySize)
	}

	// Keys should be different
	if keypair.PublicKey == keypair.PrivateKey {
		t.Error("Public and private keys should be different")
	}
}

func TestECDHKeyExchange(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (Alice) failed: %v", err)
	}

	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (Bob) failed: %v", err)
	}

	// Derive shared secrets
	aliceShared, err := DeriveSharedSecret(&alice.PrivateKey, &bob.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret (Alice) failed: %v", err)
	}

	bobShared, err := DeriveSharedSecret(&bob.PrivateKey, &alice.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret (Bob) failed: %v", err)
	}

	// Both should derive the same shared secret
	if aliceShared != bobShared {
		t.Error("Shared secrets should be equal")
	}

	// Shared secret should be 32 bytes
	if len(aliceShared) != KeySize {
		t.Errorf("Shared secret length = %d, want %d", len(aliceShared), KeySize)
	}
}

func TestEncryptionDecryption(t *testing.T) {
	key := [KeySize]byte{}
	for i := range key {
		key[i] = byte(i + 42)
	}

	plaintext := []byte("Hello, OpenSecret!")

	// Encrypt
	ciphertext, err := EncryptData(&key, plaintext)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Ciphertext should be different from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Ciphertext should be longer (includes nonce and tag)
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("Ciphertext length %d should be greater than plaintext length %d", len(ciphertext), len(plaintext))
	}

	// Decrypt
	decrypted, err := DecryptData(&key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	// Should recover original plaintext
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptionWithDifferentNonces(t *testing.T) {
	key := [KeySize]byte{}
	for i := range key {
		key[i] = byte(i + 42)
	}

	plaintext := []byte("Test message")

	// Encrypt the same message twice
	ciphertext1, err := EncryptData(&key, plaintext)
	if err != nil {
		t.Fatalf("EncryptData (1) failed: %v", err)
	}

	ciphertext2, err := EncryptData(&key, plaintext)
	if err != nil {
		t.Fatalf("EncryptData (2) failed: %v", err)
	}

	// Ciphertexts should be different (different nonces)
	if string(ciphertext1) == string(ciphertext2) {
		t.Error("Ciphertexts should be different due to different nonces")
	}

	// But both should decrypt to the same plaintext
	decrypted1, err := DecryptData(&key, ciphertext1)
	if err != nil {
		t.Fatalf("DecryptData (1) failed: %v", err)
	}

	decrypted2, err := DecryptData(&key, ciphertext2)
	if err != nil {
		t.Fatalf("DecryptData (2) failed: %v", err)
	}

	if string(decrypted1) != string(plaintext) {
		t.Errorf("Decrypted1 = %q, want %q", decrypted1, plaintext)
	}

	if string(decrypted2) != string(plaintext) {
		t.Errorf("Decrypted2 = %q, want %q", decrypted2, plaintext)
	}
}

func TestDecryptionWithWrongKeyFails(t *testing.T) {
	key1 := [KeySize]byte{}
	key2 := [KeySize]byte{}
	for i := range key1 {
		key1[i] = 1
		key2[i] = 2
	}

	plaintext := []byte("Secret message")

	// Encrypt with key1
	ciphertext, err := EncryptData(&key1, plaintext)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Try to decrypt with key2 - should fail
	_, err = DecryptData(&key2, ciphertext)
	if err == nil {
		t.Error("DecryptData should have failed with wrong key")
	}
}

func TestSessionKeyDecryption(t *testing.T) {
	// Simulate server and client key exchange
	clientKeypair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (client) failed: %v", err)
	}

	serverKeypair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (server) failed: %v", err)
	}

	// Derive shared secret (what the server would do)
	sharedSecret, err := DeriveSharedSecret(&serverKeypair.PrivateKey, &clientKeypair.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSharedSecret failed: %v", err)
	}

	// Server creates a session key
	sessionKey := [KeySize]byte{}
	for i := range sessionKey {
		sessionKey[i] = 99
	}

	// Server encrypts the session key with the shared secret
	encryptedSessionKey, err := EncryptData(&sharedSecret, sessionKey[:])
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}
	encryptedB64 := base64.StdEncoding.EncodeToString(encryptedSessionKey)

	// Client decrypts the session key
	decryptedKey, err := DecryptSessionKey(&sharedSecret, encryptedB64)
	if err != nil {
		t.Fatalf("DecryptSessionKey failed: %v", err)
	}

	if decryptedKey != sessionKey {
		t.Error("Decrypted session key should match original")
	}
}

func TestInvalidBase64SessionKey(t *testing.T) {
	clientKeypair, _ := GenerateKeyPair()
	serverKeypair, _ := GenerateKeyPair()
	sharedSecret, _ := DeriveSharedSecret(&clientKeypair.PrivateKey, &serverKeypair.PublicKey)

	_, err := DecryptSessionKey(&sharedSecret, "not-valid-base64!")
	if err == nil {
		t.Error("DecryptSessionKey should have failed with invalid base64")
	}
}

func TestCorruptedCiphertext(t *testing.T) {
	key := [KeySize]byte{}
	for i := range key {
		key[i] = 42
	}

	plaintext := []byte("Test")

	ciphertext, err := EncryptData(&key, plaintext)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Corrupt the ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	// Decryption should fail
	_, err = DecryptData(&key, ciphertext)
	if err == nil {
		t.Error("DecryptData should have failed with corrupted ciphertext")
	}
}

func TestDecryptDataTooShort(t *testing.T) {
	key := [KeySize]byte{}

	// Try to decrypt data that's too short (less than nonce size)
	_, err := DecryptData(&key, []byte{1, 2, 3})
	if err == nil {
		t.Error("DecryptData should have failed with data too short")
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := [KeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte{}

	ciphertext, err := EncryptData(&key, plaintext)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	decrypted, err := DecryptData(&key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Decrypted length = %d, want 0", len(decrypted))
	}
}

func TestEncryptDecryptLarge(t *testing.T) {
	key := [KeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}

	// 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := EncryptData(&key, plaintext)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	decrypted, err := DecryptData(&key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Decrypted length = %d, want %d", len(decrypted), len(plaintext))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Mismatch at byte %d: got %d, want %d", i, decrypted[i], plaintext[i])
			break
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	bytes1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	bytes2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if len(bytes1) != 32 || len(bytes2) != 32 {
		t.Error("Generated bytes should be 32 bytes")
	}

	// Random bytes should be different (with very high probability)
	same := true
	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Two random byte arrays should be different")
	}
}
