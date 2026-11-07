package main

import (
	"context"
	"database/sql"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dpanel/internal/collector"
	_ "github.com/mattn/go-sqlite3"
)

func TestInitCollector(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "collector.sock")
	tokenFile := filepath.Join(tmpDir, "collector.token")

	_ = os.WriteFile(tokenFile, []byte("my-test-token\n"), 0600)

	t.Setenv("COLLECTOR_SOCK", sockPath)
	t.Setenv("COLLECTOR_TOKEN_FILE", tokenFile)
	t.Setenv("EXEC_TIMEOUT_SEC", "15")

	initCollector()

	if collectorClient == nil {
		t.Fatalf("expected collectorClient to be initialized")
	}
}

func TestRunners_WithCollector(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "col.sock")
	token := "runner-test-token"

	logger := log.New(io.Discard, "", 0)
	srv := collector.NewServer(collector.ServerConfig{
		SocketPath:     sockPath,
		SecretToken:    token,
		DefaultTimeout: 5 * time.Second,
		Logger:         logger,
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start collector server: %v", err)
	}
	defer srv.Stop()

	collectorClient = collector.NewClient(sockPath, token)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. runDF
	dfOut, err := runDF(ctx)
	if err != nil {
		t.Fatalf("runDF failed: %v", err)
	}
	if !strings.Contains(dfOut, "Filesystem") && !strings.Contains(dfOut, "/") {
		t.Errorf("unexpected runDF output: %s", dfOut)
	}

	// 2. runTop
	topOut, err := runTop(ctx)
	if err != nil {
		t.Fatalf("runTop failed: %v", err)
	}
	if !strings.Contains(topOut, "top -") && !strings.Contains(topOut, "Tasks:") && !strings.Contains(topOut, "PID") {
		t.Errorf("unexpected runTop output: %s", topOut)
	}

	// 3. runDockerStats (may fail if docker not running, but should return gracefully)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = runDockerStats(shortCtx)
	shortCancel()

	// 4. runDockerInspect with valid ID
	shortCtx2, shortCancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = runDockerInspect(shortCtx2, "nonexistent-container")
	shortCancel2()

	// 5. runDockerLogs
	shortCtx3, shortCancel3 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = runDockerLogs(shortCtx3, "nonexistent-container", 10)
	shortCancel3()

	// 6. runDockerStop
	shortCtx4, shortCancel4 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = runDockerStop(shortCtx4, "nonexistent-container")
	shortCancel4()

	// 7. runComposeServices & runComposePS with temp compose file
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	_ = os.WriteFile(composePath, []byte("version: '3'\nservices:\n  web:\n    image: nginx\n"), 0644)

	shortCtx5, shortCancel5 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = runComposeServices(shortCtx5, composePath)
	shortCancel5()

	shortCtx6, shortCancel6 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = runComposePS(shortCtx6, composePath)
	shortCancel6()

	// 8. runAuthLog
	lines, _ := runAuthLog(ctx, 10)
	if lines == nil {
		t.Logf("runAuthLog returned nil or error as expected if /var/log/auth.log unreadable")
	}
}

func TestRunners_Fallback(t *testing.T) {
	// Point to non-existent socket to test fallback behavior
	collectorClient = collector.NewClient("/tmp/nonexistent-socket.sock", "bad-token")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// runDF should fall back to execCmdCombinedOutput
	dfOut, err := runDF(ctx)
	if err != nil {
		t.Fatalf("runDF fallback failed: %v", err)
	}
	if !strings.Contains(dfOut, "Filesystem") && !strings.Contains(dfOut, "/") {
		t.Errorf("unexpected fallback df output: %s", dfOut)
	}

	// runTop fallback
	topOut, err := runTop(ctx)
	if err != nil {
		t.Fatalf("runTop fallback failed: %v", err)
	}
	if !strings.Contains(topOut, "top -") && !strings.Contains(topOut, "Tasks:") && !strings.Contains(topOut, "PID") {
		t.Errorf("unexpected fallback top output: %s", topOut)
	}
}

func TestInitDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_init.db")
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer db.Close()

	if err := initDB(); err != nil {
		t.Fatalf("initDB failed: %v", err)
	}

	// Check table exists
	var count int
	err = db.QueryRow("SELECT COUNT(1) FROM users").Scan(&count)
	if err != nil {
		t.Fatalf("users table does not exist: %v", err)
	}
}
