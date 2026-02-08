// Example: Authentication Flows
//
// This example demonstrates authentication flows including registration,
// login, guest accounts, and token management.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/elimisteve/opensecret-go"
	"github.com/google/uuid"
)

func main() {
	// Initialize the client
	client := opensecret.NewClient("http://localhost:3000")

	// Your client ID
	clientIDStr := os.Getenv("VITE_TEST_CLIENT_ID")
	if clientIDStr == "" {
		clientIDStr = "your-client-id-here"
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		log.Fatalf("Please set VITE_TEST_CLIENT_ID: %v", err)
	}

	ctx := context.Background()

	fmt.Println("OpenSecret SDK - Authentication Examples")
	fmt.Println()

	// Step 1: Establish secure session (required for all operations)
	fmt.Println("1. Establishing secure session...")
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		log.Fatalf("Failed to establish session: %v", err)
	}
	fmt.Println("   Session established")
	fmt.Println()

	// Step 2: Register a guest account
	fmt.Println("2. Registering guest account...")
	guestPassword := "guest_secure_password_123"
	guestResponse, err := client.RegisterGuest(ctx, guestPassword, clientID)
	if err != nil {
		log.Fatalf("Failed to register guest: %v", err)
	}
	fmt.Printf("   Guest user created: %s\n", guestResponse.ID)
	fmt.Println()

	// Step 3: Get user profile (should show guest)
	fmt.Println("3. Getting guest user profile...")
	user, err := client.GetUser(ctx)
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	fmt.Printf("   Login method: %s\n", user.User.LoginMethod)
	fmt.Printf("   Email verified: %v\n", user.User.EmailVerified)
	fmt.Println()

	// Step 4: Refresh tokens
	fmt.Println("4. Refreshing tokens...")
	if err := client.RefreshToken(ctx); err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Println("   Tokens refreshed successfully")
	fmt.Println()

	// Step 5: Logout
	fmt.Println("5. Logging out...")
	if err := client.Logout(ctx); err != nil {
		log.Fatalf("Failed to logout: %v", err)
	}
	fmt.Println("   Logged out successfully")
	fmt.Println()

	// Step 6: Re-establish session (after logout, session is cleared)
	fmt.Println("6. Re-establishing session...")
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		log.Fatalf("Failed to re-establish session: %v", err)
	}
	fmt.Println("   Session re-established")
	fmt.Println()

	// Step 7: Register with email
	fmt.Println("7. Registering with email...")
	email := fmt.Sprintf("test-%s@example.com", uuid.New().String()[:8])
	password := "secure_password_456"
	name := "Test User"

	emailResponse, err := client.Register(ctx, email, password, clientID, &name)
	if err != nil {
		log.Fatalf("Failed to register with email: %v", err)
	}
	fmt.Printf("   Email user created: %s\n", emailResponse.ID)
	if emailResponse.Email != nil {
		fmt.Printf("   Email: %s\n", *emailResponse.Email)
	}
	fmt.Println()

	// Step 8: Logout and login with email
	fmt.Println("8. Testing login flow...")
	if err := client.Logout(ctx); err != nil {
		log.Fatalf("Failed to logout: %v", err)
	}
	fmt.Println("   Logged out")

	// Re-establish session
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		log.Fatalf("Failed to re-establish session: %v", err)
	}

	// Login with email
	loginResponse, err := client.Login(ctx, email, password, clientID)
	if err != nil {
		log.Fatalf("Failed to login: %v", err)
	}
	fmt.Printf("   Logged in as: %s\n", loginResponse.ID)
	fmt.Println()

	// Step 9: Final logout
	fmt.Println("9. Final logout...")
	if err := client.Logout(ctx); err != nil {
		log.Fatalf("Failed to logout: %v", err)
	}
	fmt.Println("   Logged out successfully")
	fmt.Println()

	fmt.Println("All authentication examples completed successfully!")
}
