package client

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/arkrix/gojail/pkg/server"
)

// Client handles communication with the gojaild Unix socket.
type Client struct {
	socketPath string
}

// NewClient creates a new daemon client targeting the specified socket path.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = "/var/run/gojail.sock"
	}
	return &Client{socketPath: socketPath}
}

// ExecOptions defines the execution parameters for a client request.
type ExecOptions struct {
	Command          string
	Args             []string
	Env              []string
	Timeout          time.Duration
	MemoryLimitBytes int64
	MaxProcesses     int64
}

// Run sends an execution request over the Unix socket and returns the result.
func (c *Client) Run(opts ExecOptions) (*server.Response, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gojaild at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	req := server.Request{
		Command:          opts.Command,
		Args:             opts.Args,
		Env:              opts.Env,
		Timeout:          opts.Timeout,
		MemoryLimitBytes: opts.MemoryLimitBytes,
		MaxProcesses:     opts.MaxProcesses,
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to transmit execution request: %w", err)
	}

	var resp server.Response
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode daemon response: %w", err)
	}

	return &resp, nil
}
