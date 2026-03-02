package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	opensecret "github.com/elimisteve/opensecret-go"
)

// runProxy starts a local OpenAI-compatible API server that proxies
// requests through the OpenSecret SDK with attestation and encryption.
func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	port := fs.Int("port", 8080, "Port to listen on (env: MAPLE_PROXY_PORT)")
	baseURL := fs.String("url", defaultBaseURL, "TEE enclave URL")
	fs.Parse(args)

	// Allow env var to override default port
	if v := os.Getenv("MAPLE_PROXY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			*port = p
		}
	}

	apiKey := os.Getenv("MAPLE_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: MAPLE_API_KEY environment variable is required")
		os.Exit(1)
	}

	// Create client and perform attestation
	client := opensecret.NewClientWithAPIKey(*baseURL, apiKey)

	ctx := context.Background()
	log.Debug("Establishing secure connection...")
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: attestation handshake failed: %v\n", err)
		os.Exit(1)
	}
	log.Debug("Secure session established")

	// Set up routes
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
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

		// Check if streaming was requested
		if req.Stream != nil && *req.Stream {
			handleStream(w, r, client, req)
			return
		}

		// Non-streaming
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

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	fmt.Fprintf(os.Stderr, "maple proxy listening on http://%s\n", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
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
			// Write error as SSE event and stop
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
