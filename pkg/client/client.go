package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
	"github.com/arkrix/gojail/pkg/sandbox"
)

// ExecOptions defines the parameters sent to the daemon.
type ExecOptions struct {
	Command          string
	Args             []string
	Env              []string
	Timeout          time.Duration
	MemoryLimitBytes int64
	MaxProcesses     int64
	Stdout           io.Writer
	Stderr           io.Writer
}

// Response models the aggregate result returned to CLI callers.
type Response struct {
	ExitCode int
	Duration time.Duration
	TimedOut bool
	Metrics  sandbox.ResourceMetrics
	Error    string
}

// Client connects to the gojaild Unix domain socket.
type Client struct {
	socketPath string
}

// NewClient returns a new Client pointing to the specified socket.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = "/var/run/gojail.sock"
	}
	return &Client{socketPath: socketPath}
}

// Run executes the command via gojaild and streams stdout/stderr directly.
func (c *Client) Run(opts ExecOptions) (*Response, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gojaild at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	req := struct {
		Command          string        `json:"command"`
		Args             []string      `json:"args"`
		Env              []string      `json:"env"`
		Timeout          time.Duration `json:"timeout"`
		MemoryLimitBytes int64         `json:"memory_limit_bytes"`
		MaxProcesses     int64         `json:"max_processes"`
	}{
		Command:          opts.Command,
		Args:             opts.Args,
		Env:              opts.Env,
		Timeout:          opts.Timeout,
		MemoryLimitBytes: opts.MemoryLimitBytes,
		MaxProcesses:     opts.MaxProcesses,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	reader := protocol.NewFrameReader(conn)
	for {
		streamType, payload, rErr := reader.ReadFrame()
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("streaming error from daemon: %w", rErr)
		}

		switch streamType {
		case protocol.StreamStdout:
			_, _ = opts.Stdout.Write(payload)
		case protocol.StreamStderr:
			_, _ = opts.Stderr.Write(payload)
		case protocol.StreamExit:
			exitPayload, pErr := protocol.ParseExitPayload(payload)
			if pErr != nil {
				return nil, fmt.Errorf("failed to read exit status: %w", pErr)
			}
			return &Response{
				ExitCode: exitPayload.ExitCode,
				Duration: exitPayload.Duration,
				TimedOut: exitPayload.TimedOut,
				Metrics:  exitPayload.Metrics,
				Error:    exitPayload.Error,
			}, nil
		}
	}

	return &Response{ExitCode: 0}, nil
}
