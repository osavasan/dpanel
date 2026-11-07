package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrGenerateToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "test.token")

	// 1. Generate new token
	token1 := loadOrGenerateToken(tokenFile)
	if token1 == "" {
		t.Fatalf("expected non-empty token")
	}
	if len(token1) != 64 { // 32 bytes hex encoded is 64 characters
		t.Errorf("expected 64 char hex token, got length %d", len(token1))
	}

	// Verify file permissions 0600
	fi, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("token file was not created: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected file mode 0600, got %o", fi.Mode().Perm())
	}

	// 2. Load existing token
	token2 := loadOrGenerateToken(tokenFile)
	if token1 != token2 {
		t.Errorf("expected same token to be loaded, got %s vs %s", token1, token2)
	}

	// 3. Existing custom file
	customFile := filepath.Join(tmpDir, "custom.token")
	_ = os.WriteFile(customFile, []byte("  my-custom-token  \n"), 0600)
	token3 := loadOrGenerateToken(customFile)
	if strings.TrimSpace(token3) != "my-custom-token" {
		t.Errorf("expected my-custom-token, got %s", token3)
	}
}
