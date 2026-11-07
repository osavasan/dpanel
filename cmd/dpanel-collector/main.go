package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dpanel/internal/collector"
)

func main() {
	socketFlag := flag.String("socket", "", "Path to unix domain socket")
	tokenFlag := flag.String("token", "", "Shared secret token for authentication")
	tokenFileFlag := flag.String("token-file", "/tmp/dpanel-collector.token", "Path to file storing secret token")
	allowedUIDFlag := flag.Int("allowed-uid", -1, "Allowed peer UID (-1 for current process UID)")
	expectedPIDFlag := flag.Int("expected-pid", 0, "Expected client PID (0 to disable PID check)")
	timeoutFlag := flag.Int("timeout", 30, "Command execution timeout in seconds")
	maxSizeFlag := flag.Int("max-size", 2, "Maximum response size limit in MB")
	flag.Parse()

	socketPath := *socketFlag
	if socketPath == "" {
		socketPath = os.Getenv("COLLECTOR_SOCK")
	}
	if socketPath == "" {
		socketPath = "/tmp/dpanel-collector.sock"
	}

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("COLLECTOR_TOKEN")
	}
	if token == "" && *tokenFileFlag != "" {
		// Read or generate token file
		token = loadOrGenerateToken(*tokenFileFlag)
	}

	allowedUID := *allowedUIDFlag
	if allowedUID == -1 {
		if envUID := os.Getenv("COLLECTOR_ALLOWED_UID"); envUID != "" {
			if v, err := strconv.Atoi(envUID); err == nil {
				allowedUID = v
			}
		}
	}
	if allowedUID == -1 {
		allowedUID = os.Getuid()
	}

	expectedPID := *expectedPIDFlag
	if expectedPID == 0 {
		if envPID := os.Getenv("COLLECTOR_EXPECTED_PID"); envPID != "" {
			if v, err := strconv.Atoi(envPID); err == nil {
				expectedPID = v
			}
		}
	}

	timeoutSec := *timeoutFlag
	if envTimeout := os.Getenv("EXEC_TIMEOUT_SEC"); envTimeout != "" {
		if v, err := strconv.Atoi(envTimeout); err == nil {
			timeoutSec = v
		}
	}

	maxSizeMB := *maxSizeFlag
	if envSize := os.Getenv("COLLECTOR_MAX_SIZE_MB"); envSize != "" {
		if v, err := strconv.Atoi(envSize); err == nil {
			maxSizeMB = v
		}
	}

	logger := log.New(os.Stderr, "[dpanel-collector] ", log.LstdFlags)

	srv := collector.NewServer(collector.ServerConfig{
		SocketPath:       socketPath,
		SecretToken:      token,
		AllowedUIDs:      []uint32{uint32(allowedUID)},
		ExpectedPID:      int32(expectedPID),
		DefaultTimeout:   time.Duration(timeoutSec) * time.Second,
		MaxResponseBytes: int64(maxSizeMB) * 1024 * 1024,
		Logger:           logger,
	})

	if err := srv.Start(); err != nil {
		logger.Fatalf("Failed to start collector server: %v", err)
	}

	logger.Printf("dpanel-collector running on %s (Allowed UID: %d, Expected PID: %d)", socketPath, allowedUID, expectedPID)

	// Listen for shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	sig := <-sigCh
	logger.Printf("Received signal %s, shutting down...", sig)

	if err := srv.Stop(); err != nil {
		logger.Printf("Error stopping server: %v", err)
	}
	logger.Println("dpanel-collector stopped cleanly.")
}

// loadOrGenerateToken reads the token from the given path or creates a cryptographically secure random token.
func loadOrGenerateToken(path string) string {
	b, err := os.ReadFile(path)
	if err == nil {
		tok := strings.TrimSpace(string(b))
		if tok != "" {
			return tok
		}
	}

	// Generate random 32-byte hex token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "fallback_insecure_token"
	}
	token := hex.EncodeToString(bytes)
	_ = os.WriteFile(path, []byte(token+"\n"), 0600)
	return token
}
