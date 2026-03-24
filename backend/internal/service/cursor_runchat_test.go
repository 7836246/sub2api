package service

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestCursorRunChat tests the RunChat BiDi streaming with a real Cursor account.
// Run with: CURSOR_TOKEN=<token> go test -v -run TestCursorRunChat -timeout 60s ./internal/service/
func TestCursorRunChat(t *testing.T) {
	token := os.Getenv("CURSOR_TOKEN")
	if token == "" {
		t.Skip("CURSOR_TOKEN not set")
	}

	creds := CursorCredentials{
		AccessToken: token,
	}

	client := NewCursorSDKClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("Starting RunChat with model=claude-4-sonnet...")
	start := time.Now()
	eventsCh, err := client.RunChat(ctx, creds, CursorChatOptions{
		Model:   "claude-4-sonnet",
		Prompt:  "hi",
		Timeout: 25 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunChat failed: %v", err)
	}

	var gotText bool
	for event := range eventsCh {
		elapsed := time.Since(start).Seconds()
		if event.Error != nil {
			t.Logf("[%.1fs] ERROR: code=%s msg=%s", elapsed, event.Error.Code, event.Error.Message)
			t.Fatalf("Got error from Cursor API")
		}
		if event.TextDelta != "" {
			t.Logf("[%.1fs] TEXT: %s", elapsed, event.TextDelta)
			gotText = true
		}
		if event.TurnEnded {
			t.Logf("[%.1fs] TURN ENDED", elapsed)
			break
		}
	}

	if !gotText {
		t.Fatal("No text received from Cursor API")
	}

	fmt.Printf("Test completed in %.1fs\n", time.Since(start).Seconds())
}
