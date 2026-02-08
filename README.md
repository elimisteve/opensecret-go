# OpenSecret Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/elimisteve/opensecret-go.svg)](https://pkg.go.dev/github.com/elimisteve/opensecret-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Go client for the OpenSecret TEE API. This SDK enables secure communication with Trusted Execution Environments (TEEs) using attestation verification and end-to-end encryption.

## Features

- **AWS Nitro Attestation Verification** - Verify TEE attestation documents with full certificate chain validation
- **End-to-End Encryption** - All API calls are encrypted using ChaCha20-Poly1305 with X25519 key exchange
- **OpenAI-Compatible API** - Chat completions, embeddings, and streaming support
- **User Authentication** - Login, registration, guest accounts, and token management
- **Cryptographic Operations** - Key derivation, message signing (Schnorr/ECDSA), and data encryption
- **Key-Value Storage** - Encrypted key-value storage with full CRUD operations

## Installation

```bash
go get github.com/elimisteve/opensecret-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/elimisteve/opensecret-go"
)

func main() {
    // Create client with API key from environment
    client := opensecret.NewClientWithAPIKey(
        "https://enclave.trymaple.ai",
        os.Getenv("MAPLE_API_KEY"),
    )

    ctx := context.Background()

    // Establish secure session with attestation verification
    if err := client.PerformAttestationHandshake(ctx); err != nil {
        log.Fatal(err)
    }

    // Make encrypted API calls
    req := opensecret.ChatCompletionRequest{
        Model: "kimi-k2-5",
        Messages: []opensecret.ChatMessage{
            {Role: "user", Content: "Hello, world!"},
        },
    }

    resp, err := client.CreateChatCompletion(ctx, req)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(resp.Choices[0].Message.Content)
}
```

## Streaming Example

```go
// Create streaming chat completion
stream, err := client.CreateChatCompletionStream(ctx, opensecret.ChatCompletionRequest{
    Model: "kimi-k2-5",
    Messages: []opensecret.ChatMessage{
        {Role: "user", Content: "Write a short poem"},
    },
})
if err != nil {
    log.Fatal(err)
}

// Consume the stream
for event := range stream {
    if event.Err != nil {
        log.Fatal(event.Err)
    }
    for _, choice := range event.Chunk.Choices {
        if choice.Delta.Content != nil {
            fmt.Print(choice.Delta.Content)
        }
    }
}
```

## Authentication

```go
// Login with email
resp, err := client.Login(ctx, "user@example.com", "password", clientID)

// Register new account
name := "John Doe"
resp, err := client.Register(ctx, "user@example.com", "password", clientID, &name)

// Register guest account
resp, err := client.RegisterGuest(ctx, "password", clientID)

// Refresh tokens
err := client.RefreshToken(ctx)

// Logout
err := client.Logout(ctx)
```

## Cryptographic Operations

```go
// Get user's private key (mnemonic)
pk, err := client.GetPrivateKey(ctx, nil)
fmt.Println(pk.Mnemonic)

// Sign a message with Schnorr
sig, err := client.SignMessage(ctx, []byte("message"), opensecret.SigningAlgorithmSchnorr, nil)

// Encrypt user data
encrypted, err := client.EncryptUserData(ctx, "secret data", nil)

// Decrypt user data
decrypted, err := client.DecryptUserData(ctx, encrypted.EncryptedData, nil)
```

## Key-Value Storage

```go
// Store a value
client.KVPut(ctx, "key", "value")

// Retrieve a value
value, err := client.KVGet(ctx, "key")

// List all keys
items, err := client.KVList(ctx)

// Delete a key
client.KVDelete(ctx, "key")
```

## Mock Mode

When connecting to `localhost` or `127.0.0.1`, the SDK automatically enables mock mode which skips certificate chain verification while still performing key exchange and encryption.

## API Reference

See the [Go package documentation](https://pkg.go.dev/github.com/elimisteve/opensecret-go) for full API reference.

## Examples

See the `examples/` directory for complete working examples:

- `examples/api_usage/` - Comprehensive API usage examples
- `examples/auth_example/` - Authentication flow examples

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

Contributions are welcome! Please see our [contributing guidelines](CONTRIBUTING.md).

## Related

- [OpenSecret Rust SDK](https://github.com/OpenSecretCloud/OpenSecret-SDK/tree/main/rust)
- [OpenSecret Documentation](https://docs.opensecret.cloud)
