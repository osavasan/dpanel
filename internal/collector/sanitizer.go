package collector

import (
	"regexp"
	"strings"
)

var (
	keyValPattern = regexp.MustCompile(`(?i)\b(token|password|secret)\s*[:=]\s*["']?([^"'\s&]+)["']?`)
	authPattern   = regexp.MustCompile(`(?i)\b(authorization\s*:\s*bearer\s+)([^"'\s&]+)`)
)

// RedactSensitive masks common sensitive key-value pairs from error messages and logs.
func RedactSensitive(msg string) string {
	res := keyValPattern.ReplaceAllString(msg, "${1}=[REDACTED]")
	res = authPattern.ReplaceAllString(res, "${1}[REDACTED]")
	return res
}

// SanitizeLog removes any instance of the secret token and redacts sensitive data.
func SanitizeLog(msg string, token string) string {
	if token != "" {
		msg = strings.ReplaceAll(msg, token, "[REDACTED]")
	}
	return RedactSensitive(msg)
}
