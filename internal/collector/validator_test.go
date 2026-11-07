package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateIdentifier(t *testing.T) {
	valid := []string{"container1", "my-app", "my_app.123", "abc", "A1"}
	for _, id := range valid {
		if err := ValidateIdentifier(id); err != nil {
			t.Errorf("expected %q to be valid, got: %v", id, err)
		}
	}

	invalid := []string{
		"",
		"-startwithhyphen",
		"has space",
		"has;semicolon",
		"has|pipe",
		"has&amp",
		"has$dollar",
		"has\x00null",
		"$(whoami)",
		"`id`",
	}
	for _, id := range invalid {
		if err := ValidateIdentifier(id); err == nil {
			t.Errorf("expected %q to be invalid, got nil", id)
		}
	}
}

func TestValidateComposePath(t *testing.T) {
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "docker-compose.yml")
	if err := os.WriteFile(validFile, []byte("version: '3'"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// Valid path
	if err := ValidateComposePath(validFile); err != nil {
		t.Errorf("expected valid compose path, got: %v", err)
	}

	// Non-absolute path
	if err := ValidateComposePath("docker-compose.yml"); err == nil {
		t.Errorf("expected error for relative path")
	}

	// Directory
	if err := ValidateComposePath(tmpDir); err == nil {
		t.Errorf("expected error when path is a directory")
	}

	// Non-existent file
	if err := ValidateComposePath(filepath.Join(tmpDir, "nonexistent.yml")); err == nil {
		t.Errorf("expected error for nonexistent file")
	}

	// Invalid extension
	txtFile := filepath.Join(tmpDir, "compose.txt")
	_ = os.WriteFile(txtFile, []byte(""), 0644)
	if err := ValidateComposePath(txtFile); err == nil {
		t.Errorf("expected error for .txt extension")
	}
}

func TestValidateRequest(t *testing.T) {
	if err := ValidateRequest(nil); err == nil {
		t.Errorf("expected error for nil request")
	}

	// DF, Top, DockerStats require no extra params
	for _, action := range []string{ActionDF, ActionTop, ActionDockerStats} {
		req := &Request{Action: action}
		if err := ValidateRequest(req); err != nil {
			t.Errorf("expected %s to be valid, got: %v", action, err)
		}
	}

	// DockerInspect requires valid ID
	if err := ValidateRequest(&Request{Action: ActionDockerInspect, ID: "valid123"}); err != nil {
		t.Errorf("expected valid inspect, got: %v", err)
	}
	if err := ValidateRequest(&Request{Action: ActionDockerInspect, ID: "-invalid"}); err == nil {
		t.Errorf("expected invalid inspect ID")
	}

	// DockerLogs checks tail clamping and limit
	reqLogs := &Request{Action: ActionDockerLogs, ID: "valid123", Tail: 0}
	if err := ValidateRequest(reqLogs); err != nil {
		t.Errorf("expected logs with 0 tail to be valid: %v", err)
	}
	if reqLogs.Tail != 200 {
		t.Errorf("expected tail to default to 200, got %d", reqLogs.Tail)
	}
	if err := ValidateRequest(&Request{Action: ActionDockerLogs, ID: "valid123", Tail: 99999}); err == nil {
		t.Errorf("expected error for tail exceeding 5000")
	}

	// AuthLog checks lines clamping and limit
	reqAuth := &Request{Action: ActionAuthLog, Lines: 0}
	if err := ValidateRequest(reqAuth); err != nil {
		t.Errorf("expected auth_log with 0 lines to be valid: %v", err)
	}
	if reqAuth.Lines != 100 {
		t.Errorf("expected lines to default to 100, got %d", reqAuth.Lines)
	}
	if err := ValidateRequest(&Request{Action: ActionAuthLog, Lines: 99999}); err == nil {
		t.Errorf("expected error for lines exceeding 500")
	}

	// Unknown action
	if err := ValidateRequest(&Request{Action: "rm -rf /"}); err == nil {
		t.Errorf("expected error for unknown action")
	}
}
