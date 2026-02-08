// maple - Direct TEE chat client using OpenSecret SDK
//
// Connects directly to the Maple TEE enclave with full attestation
// verification and end-to-end encryption. No proxy required.
//
// Usage:
//
//	maple "What is the meaning of life?"
//	echo "Tell me a joke" | maple
//	maple --model kimi-k2-5 "Explain quantum computing"
//	maple --list-models
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	opensecret "github.com/elimisteve/opensecret-go"
)

const defaultBaseURL = "https://enclave.trymaple.ai"

var log *slog.Logger

func init() {
	level := slog.LevelWarn
	if os.Getenv("DEBUG") == "1" {
		level = slog.LevelDebug
	}
	log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

func main() {
	model := flag.String("model", "qwen3-vl-30b", "Model name to use")
	baseURL := flag.String("url", defaultBaseURL, "TEE enclave URL")
	think := flag.Bool("think", false, "Enable extended thinking")
	listModels := flag.Bool("list-models", false, "List available models and exit")
	noStream := flag.Bool("no-stream", false, "Disable streaming (get complete response)")
	maxTokens := flag.Int("max-tokens", 0, "Maximum tokens to generate (0 = model default)")
	temperature := flag.Float64("temperature", 0, "Temperature (0 = model default)")
	systemPrompt := flag.String("system", "", "System prompt")
	flag.Parse()

	apiKey := os.Getenv("MAPLE_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: MAPLE_API_KEY environment variable is required")
		os.Exit(1)
	}

	// Create client with API key
	client := opensecret.NewClientWithAPIKey(*baseURL, apiKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nInterrupted")
		cancel()
		os.Exit(130)
	}()

	// Perform attestation handshake
	log.Debug("Establishing secure connection...")
	if err := client.PerformAttestationHandshake(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: attestation handshake failed: %v\n", err)
		os.Exit(1)
	}
	log.Debug("Secure session established")

	// List models if requested
	if *listModels {
		models, err := client.GetModels(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing models: %v\n", err)
			os.Exit(1)
		}
		for _, m := range models.Data {
			fmt.Println(m.ID)
		}
		return
	}

	// Get prompt from args or stdin
	var prompt string
	if args := flag.Args(); len(args) > 0 {
		prompt = strings.Join(args, " ")
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		prompt = string(data)
	}

	if strings.TrimSpace(prompt) == "" {
		fmt.Fprintln(os.Stderr, "Usage: maple [flags] \"prompt\"")
		fmt.Fprintln(os.Stderr, "       echo \"prompt\" | maple [flags]")
		os.Exit(1)
	}

	// Build messages
	var messages []opensecret.ChatMessage
	if *systemPrompt != "" {
		messages = append(messages, opensecret.ChatMessage{
			Role:    "system",
			Content: *systemPrompt,
		})
	}
	messages = append(messages, opensecret.ChatMessage{
		Role:    "user",
		Content: prompt,
	})

	// Build request
	req := opensecret.ChatCompletionRequest{
		Model:    *model,
		Messages: messages,
	}

	if *maxTokens > 0 {
		req.MaxTokens = maxTokens
	}

	if *temperature > 0 {
		temp := float32(*temperature)
		req.Temperature = &temp
	}

	if *think {
		req.ToolChoice = map[string]interface{}{
			"thinking": map[string]interface{}{
				"type":          "enabled",
				"budget_tokens": 8192,
			},
		}
	}

	if *noStream {
		resp, err := client.CreateChatCompletion(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if len(resp.Choices) > 0 {
			content := resp.Choices[0].Message.Content
			if s, ok := content.(string); ok {
				fmt.Println(s)
			} else if content != nil {
				data, _ := json.Marshal(content)
				fmt.Println(string(data))
			}
		}
	} else {
		stream, err := client.CreateChatCompletionStream(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		for event := range stream {
			if event.Err != nil {
				if ctx.Err() != nil {
					return
				}
				fmt.Fprintf(os.Stderr, "\nError during streaming: %v\n", event.Err)
				os.Exit(1)
			}

			if event.Chunk == nil {
				continue
			}

			for _, choice := range event.Chunk.Choices {
				if choice.Delta.Content != nil {
					switch c := choice.Delta.Content.(type) {
					case string:
						fmt.Print(c)
					default:
						data, _ := json.Marshal(c)
						fmt.Print(string(data))
					}
				}
			}
		}
		fmt.Println()
	}
}
