package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/elimisteve/opensecret-go/mapleproxy"
)

// runProxy starts a local OpenAI-compatible API server that proxies
// requests through the OpenSecret SDK with attestation and encryption.
func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "Host to bind (env: MAPLE_HOST)")
	port := fs.Int("port", 3000, "Port (env: MAPLE_PORT)")
	backendURL := fs.String("url", defaultBaseURL, "TEE enclave URL (env: MAPLE_BACKEND_URL)")
	cors := fs.Bool("cors", false, "Enable CORS (env: MAPLE_ENABLE_CORS)")
	fs.Parse(args)

	// Env var overrides
	if v := os.Getenv("MAPLE_HOST"); v != "" {
		*host = v
	}
	if v := os.Getenv("MAPLE_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			*port = p
		}
	}
	if v := os.Getenv("MAPLE_BACKEND_URL"); v != "" {
		*backendURL = v
	}
	if v := os.Getenv("MAPLE_ENABLE_CORS"); v != "" {
		*cors = strings.EqualFold(v, "true") || v == "1"
	}

	apiKey := os.Getenv("MAPLE_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Warning: MAPLE_API_KEY not set; requests must include Authorization: Bearer header")
	}

	ctx := context.Background()
	if err := mapleproxy.Run(ctx, mapleproxy.Config{
		Host:       *host,
		Port:       *port,
		BackendURL: *backendURL,
		APIKey:     apiKey,
		EnableCORS: *cors,
		Logger:     log,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
