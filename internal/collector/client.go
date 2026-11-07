package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client provides typed RPC over the Unix domain socket to dpanel-collector.
type Client struct {
	socketPath string
	token      string
	timeout    time.Duration
}

// NewClient returns a new Client.
func NewClient(socketPath string, token string) *Client {
	return &Client{
		socketPath: socketPath,
		token:      token,
		timeout:    30 * time.Second,
	}
}

// SetTimeout configures client request timeout.
func (c *Client) SetTimeout(t time.Duration) {
	c.timeout = t
}

// Exec sends a typed Request to dpanel-collector and returns the typed Response.
func (c *Client) Exec(ctx context.Context, req Request) (*Response, error) {
	// Inject token
	req.Token = c.token

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to collector socket at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(deadline)

	// Send Request
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request to collector: %w", err)
	}

	// Receive Response
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode response from collector: %w", err)
	}

	return &resp, nil
}

// DF executes the df -H command via the collector.
func (c *Client) DF(ctx context.Context) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionDF})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// Top executes top -b -n 1 via the collector.
func (c *Client) Top(ctx context.Context) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionTop})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// DockerStats executes docker stats via the collector.
func (c *Client) DockerStats(ctx context.Context) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionDockerStats})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// DockerInspect executes docker inspect <id> via the collector.
func (c *Client) DockerInspect(ctx context.Context, id string) ([]byte, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionDockerInspect, ID: id})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return []byte(resp.Output), errors.New(resp.Error)
	}
	return []byte(resp.Output), nil
}

// DockerLogs executes docker logs --tail <tail> <id> via the collector.
func (c *Client) DockerLogs(ctx context.Context, id string, tail int) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionDockerLogs, ID: id, Tail: tail})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// DockerStop executes docker stop <id> via the collector.
func (c *Client) DockerStop(ctx context.Context, id string) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionDockerStop, ID: id})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// ComposeServices executes docker compose -f <path> config --services via the collector.
func (c *Client) ComposeServices(ctx context.Context, path string) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionComposeServices, Path: path})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// ComposePS executes docker compose -f <path> ps -a --format json via the collector.
func (c *Client) ComposePS(ctx context.Context, path string) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionComposePS, Path: path})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// ComposeUp executes docker compose -f <path> up -d <service> via the collector.
func (c *Client) ComposeUp(ctx context.Context, path string, service string) (string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionComposeUp, Path: path, Service: service})
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return resp.Output, errors.New(resp.Error)
	}
	return resp.Output, nil
}

// AuthLog reads auth log entries via the collector.
func (c *Client) AuthLog(ctx context.Context, lines int) ([]string, error) {
	resp, err := c.Exec(ctx, Request{Action: ActionAuthLog, Lines: lines})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, errors.New(resp.Error)
	}
	var entries []string
	if err := json.Unmarshal([]byte(resp.Output), &entries); err != nil {
		return nil, fmt.Errorf("failed to parse auth log json: %w", err)
	}
	return entries, nil
}
