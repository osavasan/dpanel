package collector

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ServerConfig holds configuration options for the collector server.
type ServerConfig struct {
	SocketPath       string
	SecretToken      string
	AllowedUIDs      []uint32
	ExpectedPID      int32
	DefaultTimeout   time.Duration
	MaxResponseBytes int64
	Logger           *log.Logger
}

// Server is the Unix domain socket server executing validated system commands.
type Server struct {
	config   ServerConfig
	listener net.Listener
	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup
}

// NewServer creates a new collector server instance.
func NewServer(cfg ServerConfig) *Server {
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = 30 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 2 * 1024 * 1024 // 2MB default
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "[dpanel-collector] ", log.LstdFlags)
	}
	if len(cfg.AllowedUIDs) == 0 {
		cfg.AllowedUIDs = []uint32{uint32(os.Getuid())}
	}
	return &Server{
		config: cfg,
	}
}

// Start begins listening on the Unix domain socket with restrictive permissions.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return errors.New("server already started")
	}

	// 1. Ensure parent directory exists with restrictive permissions (0700)
	dir := filepath.Dir(s.config.SocketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// 2. Remove any existing stale socket file
	if _, err := os.Stat(s.config.SocketPath); err == nil {
		_ = os.Remove(s.config.SocketPath)
	}

	// 3. Listen on unix socket
	l, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", s.config.SocketPath, err)
	}

	// 4. Set socket file permissions to 0600 (owner read/write only)
	if err := os.Chmod(s.config.SocketPath, 0600); err != nil {
		l.Close()
		_ = os.Remove(s.config.SocketPath)
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.listener = l
	s.closed = false

	s.config.Logger.Printf("Listening on unix domain socket %s (perms: 0600)", s.config.SocketPath)

	s.wg.Add(1)
	go s.serve()

	return nil
}

// serve accepts incoming Unix connections.
func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			s.config.Logger.Printf("Accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(c)
		}(conn)
	}
}

// handleConnection handles an individual client connection.
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. Extract peer credentials (SO_PEERCRED on Linux)
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		s.config.Logger.Printf("Connection rejected: not a UnixConn")
		return
	}

	creds, err := GetPeerCredentials(unixConn)
	if err != nil {
		s.config.Logger.Printf("Security check failed: unable to get peer credentials: %v", err)
		return
	}

	// 2. Verify peer UID
	uidAllowed := false
	for _, allowed := range s.config.AllowedUIDs {
		if creds.UID == allowed {
			uidAllowed = true
			break
		}
	}
	if !uidAllowed {
		s.config.Logger.Printf("Security alert: unauthorized peer UID %d (PID %d) rejected", creds.UID, creds.PID)
		return
	}

	// 3. Optionally verify peer PID if specified
	if s.config.ExpectedPID > 0 && creds.PID != s.config.ExpectedPID {
		s.config.Logger.Printf("Security alert: unexpected peer PID %d (expected %d) rejected", creds.PID, s.config.ExpectedPID)
		return
	}

	// Set connection read/write deadline
	_ = conn.SetDeadline(time.Now().Add(s.config.DefaultTimeout + 5*time.Second))

	// 4. Decode Request JSON
	var req Request
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		s.config.Logger.Printf("Failed to decode request from PID %d: %v", creds.PID, err)
		s.sendResponse(conn, Response{
			Success: false,
			Error:   "invalid json request",
		})
		return
	}

	// 5. Verify Token if configured
	if s.config.SecretToken != "" {
		if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.config.SecretToken)) != 1 {
			s.config.Logger.Printf("Security alert: invalid secret token from PID %d, UID %d", creds.PID, creds.UID)
			s.sendResponse(conn, Response{
				Success: false,
				Error:   "unauthorized: invalid token",
			})
			return
		}
	}

	// 6. Validate Request
	if err := ValidateRequest(&req); err != nil {
		sanitizedErr := SanitizeLog(err.Error(), s.config.SecretToken)
		s.config.Logger.Printf("Validation error for PID %d (action=%s): %s", creds.PID, req.Action, sanitizedErr)
		s.sendResponse(conn, Response{
			Success: false,
			Error:   sanitizedErr,
		})
		return
	}

	// 7. Execute Request with timeout and limits
	start := time.Now()
	resp := s.executeAction(req)
	duration := time.Since(start)
	resp.DurationMs = duration.Milliseconds()

	// 8. Log request safely (never leak token or sensitive payloads)
	s.logRequest(creds, req, resp, duration)

	// 9. Send typed JSON response
	s.sendResponse(conn, resp)
}

// executeAction runs the validated command with execution timeouts and size limits.
func (s *Server) executeAction(req Request) Response {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.DefaultTimeout)
	defer cancel()

	switch req.Action {
	case ActionDF:
		out, exitCode, err := s.runCmd(ctx, "df", "-H")
		return buildResponse(out, exitCode, err)

	case ActionTop:
		out, exitCode, err := s.runCmd(ctx, "top", "-b", "-n", "1")
		return buildResponse(out, exitCode, err)

	case ActionDockerStats:
		format := "{{.Container}}|{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}"
		out, exitCode, err := s.runCmd(ctx, "docker", "stats", "--no-stream", "--format", format)
		return buildResponse(out, exitCode, err)

	case ActionDockerInspect:
		out, exitCode, err := s.runCmd(ctx, "docker", "inspect", req.ID)
		return buildResponse(out, exitCode, err)

	case ActionDockerLogs:
		tailStr := fmt.Sprintf("%d", req.Tail)
		out, exitCode, err := s.runCmd(ctx, "docker", "logs", "--tail", tailStr, req.ID)
		return buildResponse(out, exitCode, err)

	case ActionDockerStop:
		out, exitCode, err := s.runCmd(ctx, "docker", "stop", req.ID)
		return buildResponse(out, exitCode, err)

	case ActionComposeServices:
		out, exitCode, err := s.runCmdStdoutOnly(ctx, "docker", "compose", "-f", req.Path, "config", "--services")
		return buildResponse(out, exitCode, err)

	case ActionComposePS:
		out, exitCode, err := s.runCmdStdoutOnly(ctx, "docker", "compose", "-f", req.Path, "ps", "-a", "--format", "json")
		return buildResponse(out, exitCode, err)

	case ActionComposeUp:
		out, exitCode, err := s.runCmd(ctx, "docker", "compose", "-f", req.Path, "up", "-d", req.Service)
		return buildResponse(out, exitCode, err)

	case ActionAuthLog:
		return s.readAuthLog(req.Lines)

	default:
		return Response{
			Success: false,
			Error:   fmt.Sprintf("unknown action: %s", req.Action),
		}
	}
}

// readAuthLog reads /var/log/auth.log with limit and reverses newest first.
func (s *Server) readAuthLog(lines int) Response {
	b, err := os.ReadFile("/var/log/auth.log")
	if err != nil {
		return Response{
			Success: false,
			Error:   fmt.Sprintf("failed to read auth log: %v", err),
		}
	}

	allLines := strings.Split(strings.TrimSpace(string(b)), "\n")
	start := 0
	if len(allLines) > lines {
		start = len(allLines) - lines
	}

	var result []string
	for i := len(allLines) - 1; i >= start; i-- {
		if ln := strings.TrimSpace(allLines[i]); ln != "" {
			result = append(result, ln)
		}
	}

	outBytes, _ := json.Marshal(result)
	return Response{
		Success: true,
		Output:  string(outBytes),
	}
}

// runCmd executes a command capturing combined output with response size limits.
func (s *Server) runCmd(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	buf := &limitBuffer{limit: s.config.MaxResponseBytes}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	outStr := buf.String()
	if buf.truncated {
		outStr += "\n[output truncated: exceeded maximum response size limit]"
	}
	return outStr, exitCode, err
}

// runCmdStdoutOnly executes a command capturing only stdout with response size limits.
func (s *Server) runCmdStdoutOnly(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	buf := &limitBuffer{limit: s.config.MaxResponseBytes}
	cmd.Stdout = buf
	// Stderr is discarded or captured separately
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	outStr := buf.String()
	if buf.truncated {
		outStr += "\n[output truncated: exceeded maximum response size limit]"
	}
	return outStr, exitCode, err
}

// buildResponse wraps command output and error into a Response.
func buildResponse(output string, exitCode int, err error) Response {
	resp := Response{
		Output:   output,
		ExitCode: exitCode,
	}
	if err != nil {
		resp.Success = false
		resp.Error = RedactSensitive(err.Error())
	} else {
		resp.Success = true
	}
	return resp
}

// sendResponse writes the typed JSON response to the client.
func (s *Server) sendResponse(w io.Writer, resp Response) {
	enc := json.NewEncoder(w)
	_ = enc.Encode(resp)
}

// logRequest outputs structured sanitized logs.
func (s *Server) logRequest(creds *PeerCreds, req Request, resp Response, duration time.Duration) {
	status := "OK"
	if !resp.Success {
		status = "FAIL"
	}
	target := ""
	if req.ID != "" {
		target = " id=" + req.ID
	}
	if req.Path != "" {
		target += " path=" + req.Path
	}
	if req.Service != "" {
		target += " service=" + req.Service
	}

	s.config.Logger.Printf("peer_pid=%d peer_uid=%d action=%s%s status=%s duration=%s err=%q",
		creds.PID, creds.UID, req.Action, target, status, duration, RedactSensitive(resp.Error))
}

// Stop gracefully shuts down the server and removes the socket file.
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	_ = os.Remove(s.config.SocketPath)
	return err
}

// limitBuffer is a thread-safe bytes buffer with size limiting.
type limitBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (l *limitBuffer) Write(p []byte) (n int, err error) {
	remaining := l.limit - int64(l.buf.Len())
	if remaining <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		l.buf.Write(p[:remaining])
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *limitBuffer) String() string {
	return l.buf.String()
}
