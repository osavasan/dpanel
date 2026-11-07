package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// identifierRegex ensures container IDs and service names are safe alphanumeric strings.
	identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

// ValidateIdentifier checks if a string is a safe container ID or service name.
func ValidateIdentifier(s string) error {
	if s == "" {
		return errors.New("identifier cannot be empty")
	}
	if strings.HasPrefix(s, "-") {
		return errors.New("identifier cannot start with a hyphen")
	}
	if !identifierRegex.MatchString(s) {
		return fmt.Errorf("identifier contains invalid characters: %q", s)
	}
	return nil
}

// ValidateComposePath checks if the given path is a valid existing docker-compose YAML file.
func ValidateComposePath(path string) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %s", path)
	}
	clean := filepath.Clean(path)
	if strings.Contains(clean, "\x00") {
		return errors.New("path contains null bytes")
	}
	ext := strings.ToLower(filepath.Ext(clean))
	if ext != ".yml" && ext != ".yaml" {
		return fmt.Errorf("invalid file extension %q, expected .yml or .yaml", ext)
	}
	fi, err := os.Stat(clean)
	if err != nil {
		return fmt.Errorf("file error: %w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("path is a directory: %s", clean)
	}
	return nil
}

// ValidateRequest performs thorough validation on an incoming CollectorRequest.
func ValidateRequest(req *Request) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}

	switch req.Action {
	case ActionDF, ActionTop, ActionDockerStats:
		// No additional required parameters
		return nil

	case ActionDockerInspect, ActionDockerStop:
		if err := ValidateIdentifier(req.ID); err != nil {
			return fmt.Errorf("invalid container id: %w", err)
		}
		return nil

	case ActionDockerLogs:
		if err := ValidateIdentifier(req.ID); err != nil {
			return fmt.Errorf("invalid container id: %w", err)
		}
		if req.Tail <= 0 {
			req.Tail = 200
		}
		if req.Tail > 5000 {
			return errors.New("tail exceeds maximum allowed limit (5000)")
		}
		return nil

	case ActionComposeServices, ActionComposePS:
		if err := ValidateComposePath(req.Path); err != nil {
			return fmt.Errorf("invalid compose path: %w", err)
		}
		return nil

	case ActionComposeUp:
		if err := ValidateComposePath(req.Path); err != nil {
			return fmt.Errorf("invalid compose path: %w", err)
		}
		if err := ValidateIdentifier(req.Service); err != nil {
			return fmt.Errorf("invalid compose service name: %w", err)
		}
		return nil

	case ActionAuthLog:
		if req.Lines <= 0 {
			req.Lines = 100
		}
		if req.Lines > 500 {
			return errors.New("lines exceeds maximum allowed limit (500)")
		}
		return nil

	default:
		return fmt.Errorf("unsupported action: %q", req.Action)
	}
}
