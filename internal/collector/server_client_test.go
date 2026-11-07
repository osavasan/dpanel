package collector

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerClient_DF_Top(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test-collector.sock")
	token := "valid-secret-token-1234"

	logger := log.New(io.Discard, "", 0)
	srv := NewServer(ServerConfig{
		SocketPath:       sockPath,
		SecretToken:      token,
		DefaultTimeout:   5 * time.Second,
		MaxResponseBytes: 1024 * 1024,
		Logger:           logger,
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// Verify socket permissions
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("socket does not exist: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", fi.Mode().Perm())
	}

	client := NewClient(sockPath, token)

	// Test DF
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dfOut, err := client.DF(ctx)
	if err != nil {
		t.Fatalf("client.DF failed: %v", err)
	}
	if !strings.Contains(dfOut, "Filesystem") && !strings.Contains(dfOut, "/") {
		t.Errorf("unexpected df output: %s", dfOut)
	}

	// Test Top
	topOut, err := client.Top(ctx)
	if err != nil {
		t.Fatalf("client.Top failed: %v", err)
	}
	if !strings.Contains(topOut, "top -") && !strings.Contains(topOut, "Tasks:") && !strings.Contains(topOut, "PID") {
		t.Errorf("unexpected top output: %s", topOut)
	}
}

func TestServerClient_UnauthorizedToken(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "unauth.sock")
	validToken := "correct-token"

	logger := log.New(io.Discard, "", 0)
	srv := NewServer(ServerConfig{
		SocketPath:     sockPath,
		SecretToken:    validToken,
		DefaultTimeout: 2 * time.Second,
		Logger:         logger,
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// Client with wrong token
	badClient := NewClient(sockPath, "wrong-token")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := badClient.DF(ctx)
	if err == nil {
		t.Fatalf("expected authorization failure for invalid token")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected error to mention unauthorized, got: %v", err)
	}
}

func TestServerClient_ResponseSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "limit.sock")
	token := "token-limit"

	logger := log.New(io.Discard, "", 0)
	// Set limit to very small: 50 bytes
	srv := NewServer(ServerConfig{
		SocketPath:       sockPath,
		SecretToken:      token,
		DefaultTimeout:   5 * time.Second,
		MaxResponseBytes: 50,
		Logger:           logger,
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	client := NewClient(sockPath, token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dfOut, err := client.DF(ctx)
	if err != nil {
		t.Fatalf("client.DF failed: %v", err)
	}
	if !strings.Contains(dfOut, "output truncated") {
		t.Errorf("expected output to be truncated with size limit notice, got: %s", dfOut)
	}
}

func TestServer_CleanupOnStop(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "cleanup.sock")

	logger := log.New(io.Discard, "", 0)
	srv := NewServer(ServerConfig{
		SocketPath: sockPath,
		Logger:     logger,
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket should exist")
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("socket file was not cleaned up on stop")
	}
}
