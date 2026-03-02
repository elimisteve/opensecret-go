// Package mapleproxy provides an OpenAI-compatible HTTP proxy server that forwards
// requests through the OpenSecret SDK with attestation and encryption.
package mapleproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	opensecret "github.com/elimisteve/opensecret-go"
)

// Config holds configuration for the OpenAI-compatible proxy server.
type Config struct {
	Host       string       // Bind address (default "127.0.0.1")
	Port       int          // Port (default 3000)
	BackendURL string       // TEE enclave URL
	APIKey     string       // Default API key (optional; per-request auth supported)
	EnableCORS bool         // Enable CORS headers
	Logger     *slog.Logger // Optional logger (nil = discard)
}

func (c *Config) defaults() {
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		c.Port = 3000
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run starts the proxy server (blocking). Performs attestation, then
// listens. Returns error if attestation or listen fails.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	log := cfg.Logger

	// Create client — API key is optional
	var client *opensecret.OpenSecretClient
	if cfg.APIKey != "" {
		client = opensecret.NewClientWithAPIKey(cfg.BackendURL, cfg.APIKey)
	} else {
		client = opensecret.NewClient(cfg.BackendURL)
	}

	log.Debug("Establishing secure connection...")
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		return fmt.Errorf("attestation handshake failed: %w", err)
	}
	log.Debug("Secure session established")

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		applyRequestAPIKey(client, r, cfg.APIKey)
		models, err := client.GetModels(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, models)
	})

	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}

		applyRequestAPIKey(client, r, cfg.APIKey)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		var req opensecret.ChatCompletionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		if req.Stream != nil && *req.Stream {
			handleStream(w, r, client, req)
			return
		}

		resp, err := client.CreateChatCompletion(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}

		applyRequestAPIKey(client, r, cfg.APIKey)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		var req opensecret.EmbeddingRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		resp, err := client.CreateEmbeddings(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, resp)
	})

	var handler http.Handler = mux
	if cfg.EnableCORS {
		handler = corsMiddleware(mux)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	fmt.Fprintf(os.Stderr, "maple proxy listening on http://%s\n", addr)

	return http.ListenAndServe(addr, handler)
}

// applyRequestAPIKey extracts a Bearer token from the incoming request and
// sets it on the client. If no per-request key is present, falls back to
// the configured default API key.
func applyRequestAPIKey(client *opensecret.OpenSecretClient, r *http.Request, defaultKey string) {
	if key := extractBearerToken(r); key != "" {
		client.SetAPIKey(key)
	} else if defaultKey != "" {
		client.SetAPIKey(defaultKey)
	}
}

// extractBearerToken returns the Bearer token from the Authorization header,
// or empty string if not present.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return auth[len(prefix):]
	}
	return ""
}

func handleStream(w http.ResponseWriter, r *http.Request, client *opensecret.OpenSecretClient, req opensecret.ChatCompletionRequest) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	stream, err := client.CreateChatCompletionStream(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	for event := range stream {
		if event.Err != nil {
			errData, _ := json.Marshal(map[string]string{"error": event.Err.Error()})
			fmt.Fprintf(w, "data: %s\n\n", errData)
			flusher.Flush()
			return
		}

		if event.Chunk == nil {
			continue
		}

		data, err := json.Marshal(event.Chunk)
		if err != nil {
			continue
		}

		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": msg,
			"type":    "proxy_error",
		},
	})
}

// corsMiddleware wraps an http.Handler and adds CORS headers to all responses.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
