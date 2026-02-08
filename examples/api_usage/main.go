// Example: API Usage
//
// This example demonstrates how to use the OpenSecret SDK for various operations
// including authentication, key-value storage, cryptographic operations, and more.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/elimisteve/opensecret-go"
	"github.com/google/uuid"
)

func main() {
	// Initialize the client
	client := opensecret.NewClient("http://localhost:3000")

	// Your client ID - either set VITE_TEST_CLIENT_ID env var or replace the string below
	clientIDStr := os.Getenv("VITE_TEST_CLIENT_ID")
	if clientIDStr == "" {
		clientIDStr = "your-client-id-here"
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		log.Fatalf("Please set VITE_TEST_CLIENT_ID environment variable or replace 'your-client-id-here' with a valid UUID: %v", err)
	}

	ctx := context.Background()

	fmt.Println("OpenSecret SDK - API Usage Examples")
	fmt.Println()

	// Step 1: Establish secure session
	fmt.Println("1. Establishing secure session...")
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		log.Fatalf("Failed to establish session: %v", err)
	}
	fmt.Println("   Secure session established")
	fmt.Println()

	// Step 2: Authentication
	fmt.Println("2. Authentication")
	email := "demo@example.com"
	password := "secure_password_123"

	// Try to login, register if user doesn't exist
	response, err := client.Login(ctx, email, password, clientID)
	if err != nil {
		fmt.Println("   User not found, registering...")
		name := "Demo User"
		response, err = client.Register(ctx, email, password, clientID, &name)
		if err != nil {
			log.Fatalf("Failed to register: %v", err)
		}
		fmt.Println("   Registered new user")
	} else {
		fmt.Println("   Logged in as existing user")
	}
	fmt.Printf("   User ID: %s\n", response.ID)
	fmt.Println()

	// Step 3: Get User Profile
	fmt.Println("3. User Profile")
	user, err := client.GetUser(ctx)
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user.User.Email != nil {
		fmt.Printf("   Email: %s\n", *user.User.Email)
	}
	fmt.Printf("   Verified: %v\n", user.User.EmailVerified)
	fmt.Printf("   Method: %s\n", user.User.LoginMethod)
	fmt.Printf("   Created: %s\n", user.User.CreatedAt)
	fmt.Println()

	// Step 4: Key-Value Storage
	fmt.Println("4. Key-Value Storage")

	// Store a value
	key := "user_preference"
	value := `{"theme": "dark", "language": "en"}`
	_, err = client.KVPut(ctx, key, value)
	if err != nil {
		log.Fatalf("Failed to store value: %v", err)
	}
	fmt.Printf("   Stored: %s = %s\n", key, value)

	// Retrieve the value
	retrieved, err := client.KVGet(ctx, key)
	if err != nil {
		log.Fatalf("Failed to retrieve value: %v", err)
	}
	fmt.Printf("   Retrieved: %s\n", retrieved)

	// List all keys
	keys, err := client.KVList(ctx)
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}
	fmt.Printf("   Total keys: %d\n", len(keys))
	for i, item := range keys {
		if i >= 3 {
			break
		}
		fmt.Printf("     - %s: %s\n", item.Key, item.Value)
	}

	// Clean up
	if err := client.KVDelete(ctx, key); err != nil {
		log.Fatalf("Failed to delete key: %v", err)
	}
	fmt.Printf("   Deleted key: %s\n", key)
	fmt.Println()

	// Step 5: Private Key Generation
	fmt.Println("5. Private Key Generation")

	// Generate default mnemonic (12 words)
	privateKey, err := client.GetPrivateKey(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to get private key: %v", err)
	}
	words := strings.Fields(privateKey.Mnemonic)
	fmt.Printf("   Generated %d word mnemonic\n", len(words))
	if len(words) >= 3 {
		fmt.Printf("   First 3 words: %s...\n", strings.Join(words[:3], " "))
	}

	// Generate with 24 words using BIP-85 derivation path
	derivationPath := "m/83696968'/39'/0'/24'/0'"
	options := &opensecret.KeyOptions{
		SeedPhraseDerivationPath: &derivationPath,
	}
	_, err = client.GetPrivateKey(ctx, options)
	if err != nil {
		log.Fatalf("Failed to get private key with derivation: %v", err)
	}
	fmt.Println("   Generated 24 word mnemonic via BIP-85")

	// Get raw private key bytes
	keyBytes, err := client.GetPrivateKeyBytes(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to get private key bytes: %v", err)
	}
	if len(keyBytes.PrivateKey) >= 20 {
		fmt.Printf("   Private key bytes (hex): %s...\n", keyBytes.PrivateKey[:20])
	}
	fmt.Println()

	// Step 6: Message Signing
	fmt.Println("6. Digital Signatures")
	message := "Sign this important message"

	// Sign with Schnorr (Bitcoin Taproot compatible)
	schnorrSig, err := client.SignMessage(ctx, []byte(message), opensecret.SigningAlgorithmSchnorr, nil)
	if err != nil {
		log.Fatalf("Failed to sign with Schnorr: %v", err)
	}
	if len(schnorrSig.Signature) >= 20 {
		fmt.Printf("   Schnorr signature: %s...\n", schnorrSig.Signature[:20])
	}

	// Sign with ECDSA (Classic Bitcoin/Ethereum)
	ecdsaSig, err := client.SignMessage(ctx, []byte(message), opensecret.SigningAlgorithmEcdsa, nil)
	if err != nil {
		log.Fatalf("Failed to sign with ECDSA: %v", err)
	}
	if len(ecdsaSig.Signature) >= 20 {
		fmt.Printf("   ECDSA signature: %s...\n", ecdsaSig.Signature[:20])
	}

	// Sign with custom derivation path
	customPath := "m/44'/0'/0'/0/5"
	keyOpts := &opensecret.KeyOptions{
		PrivateKeyDerivationPath: &customPath,
	}
	customSig, err := client.SignMessage(ctx, []byte(message), opensecret.SigningAlgorithmSchnorr, keyOpts)
	if err != nil {
		log.Fatalf("Failed to sign with custom path: %v", err)
	}
	if len(customSig.Signature) >= 20 {
		fmt.Printf("   Signature at path %s: %s...\n", customPath, customSig.Signature[:20])
	}
	fmt.Println()

	// Step 7: Public Keys
	fmt.Println("7. Public Keys")

	// Get public keys for different algorithms
	schnorrPub, err := client.GetPublicKey(ctx, opensecret.SigningAlgorithmSchnorr, nil)
	if err != nil {
		log.Fatalf("Failed to get Schnorr public key: %v", err)
	}
	if len(schnorrPub.PublicKey) >= 20 {
		fmt.Printf("   Schnorr public key: %s...\n", schnorrPub.PublicKey[:20])
	}

	ecdsaPub, err := client.GetPublicKey(ctx, opensecret.SigningAlgorithmEcdsa, nil)
	if err != nil {
		log.Fatalf("Failed to get ECDSA public key: %v", err)
	}
	if len(ecdsaPub.PublicKey) >= 20 {
		fmt.Printf("   ECDSA public key: %s...\n", ecdsaPub.PublicKey[:20])
	}

	// Public key at derivation path
	ethPath := "m/44'/60'/0'/0/0"
	ethKeyOpts := &opensecret.KeyOptions{
		PrivateKeyDerivationPath: &ethPath,
	}
	derivedPub, err := client.GetPublicKey(ctx, opensecret.SigningAlgorithmEcdsa, ethKeyOpts)
	if err != nil {
		log.Fatalf("Failed to get derived public key: %v", err)
	}
	if len(derivedPub.PublicKey) >= 20 {
		fmt.Printf("   Ethereum public key: %s...\n", derivedPub.PublicKey[:20])
	}
	fmt.Println()

	// Step 8: Data Encryption
	fmt.Println("8. End-to-End Encryption")
	secretData := "This is highly confidential information"

	// Encrypt data
	encrypted, err := client.EncryptUserData(ctx, secretData, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}
	if len(encrypted.EncryptedData) >= 30 {
		fmt.Printf("   Encrypted: %s...\n", encrypted.EncryptedData[:30])
	}

	// Decrypt data
	decrypted, err := client.DecryptUserData(ctx, encrypted.EncryptedData, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v", err)
	}
	fmt.Printf("   Decrypted: %s\n", decrypted)

	if decrypted != secretData {
		log.Fatal("Decrypted data doesn't match original!")
	}

	// Encrypt with custom BIP-32 derivation
	customKeyPath := "m/0'/1'/2'"
	customKeyOpts := &opensecret.KeyOptions{
		PrivateKeyDerivationPath: &customKeyPath,
	}
	customEncrypted, err := client.EncryptUserData(ctx, "Secret with custom key", customKeyOpts)
	if err != nil {
		log.Fatalf("Failed to encrypt with custom key: %v", err)
	}
	if len(customEncrypted.EncryptedData) >= 30 {
		fmt.Printf("   Custom encryption: %s...\n", customEncrypted.EncryptedData[:30])
	}
	fmt.Println()

	// Step 9: Third-Party Tokens
	fmt.Println("9. Third-Party Token Generation")

	// Generate token without audience
	token, err := client.GenerateThirdPartyToken(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	if len(token.Token) >= 30 {
		fmt.Printf("   Generated token: %s...\n", token.Token[:30])
	}

	// Generate token for specific service
	audience := "https://api.example.com"
	scopedToken, err := client.GenerateThirdPartyToken(ctx, &audience)
	if err != nil {
		log.Fatalf("Failed to generate scoped token: %v", err)
	}
	if len(scopedToken.Token) >= 30 {
		fmt.Printf("   Token for %s: %s...\n", audience, scopedToken.Token[:30])
	}
	fmt.Println()

	// Step 10: Session Management
	fmt.Println("10. Session Management")

	// Refresh access token
	fmt.Println("   Refreshing tokens...")
	if err := client.RefreshToken(ctx); err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Println("   Tokens refreshed")

	// Get current session info
	if sessionID, err := client.GetSessionID(); err == nil {
		fmt.Printf("   Session ID: %s\n", sessionID)
	}

	if accessToken := client.GetAccessToken(); accessToken != "" && len(accessToken) >= 20 {
		fmt.Printf("   Access Token: %s...\n", accessToken[:20])
	}

	// Logout
	fmt.Println("   Logging out...")
	if err := client.Logout(ctx); err != nil {
		log.Fatalf("Failed to logout: %v", err)
	}
	fmt.Println("   Logged out successfully")
	fmt.Println()

	fmt.Println("All API examples completed successfully!")
	fmt.Println()
	fmt.Println("For more information, visit: https://docs.opensecret.cloud")
}
