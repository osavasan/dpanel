package collector

import (
	"strings"
	"testing"
)

func TestSanitizeLog(t *testing.T) {
	token := "super-secret-token-12345"
	logMsg := "Connecting to server with token=" + token + " and proceeding"
	sanitized := SanitizeLog(logMsg, token)

	if strings.Contains(sanitized, token) {
		t.Errorf("SanitizeLog failed to mask secret token: %s", sanitized)
	}
	if !strings.Contains(sanitized, "[REDACTED]") {
		t.Errorf("SanitizeLog should contain [REDACTED]")
	}
}

func TestRedactSensitive(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{"failed login with password=mySecretPassword123", "password=[REDACTED]"},
		{"header: Authorization: Bearer abcdef123456", "Authorization: Bearer [REDACTED]"},
		{"db secret: secret='my_db_secret'", "secret=[REDACTED]"},
	}

	for _, c := range cases {
		out := RedactSensitive(c.input)
		if !strings.Contains(out, c.contains) {
			t.Errorf("expected %q to contain %q, got %q", c.input, c.contains, out)
		}
	}
}
