package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
	"github.com/arkrix/gojail/pkg/sandbox"
	"golang.org/x/term"
)

// ExecOptions defines the parameters sent to the daemon.
type ExecOptions struct {
	Command          string
	Args             []string
	Env              []string
	Timeout          time.Duration
	MemoryLimitBytes int64
	MaxProcesses     int64
	StorageLimitMB   int64
	Mounts           []sandbox.MountSpec
	TTY              bool
	Stdout           io.Writer
	Stderr           io.Writer
	SeccompProfile   string
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

// ListJobs queries the daemon for currently active and recent sandboxes.
func (c *Client) ListJobs() ([]protocol.JobInfo, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	req := protocol.Request{Action: "list"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send list request: %w", err)
	}

	var resp protocol.ControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode list response: %w", err)
	}

	if !resp.Success {
		return nil, errors.New(resp.Error)
	}
	return resp.Jobs, nil
}

// StopJob instructs the daemon to terminate an active sandbox instance by ID.
func (c *Client) StopJob(targetID string) error {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	req := protocol.Request{
		Action:   "stop",
		TargetID: targetID,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("failed to send stop request: %w", err)
	}

	var resp protocol.ControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode stop response: %w", err)
	}

	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// Run executes the command via gojaild and streams I/O directly.
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

	req := protocol.Request{
		Action:           "run",
		Command:          opts.Command,
		Args:             opts.Args,
		Env:              opts.Env,
		Timeout:          opts.Timeout,
		MemoryLimitBytes: opts.MemoryLimitBytes,
		MaxProcesses:     opts.MaxProcesses,
		StorageLimitMB:   opts.StorageLimitMB,
		Mounts:           opts.Mounts,
		TTY:              opts.TTY,
		SeccompProfile:   opts.SeccompProfile,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	frameWriter := protocol.NewFrameWriter(conn)
	frameReader := protocol.NewFrameReader(conn)

	// If interactive TTY requested, configure raw mode and forward stdin + window resizes
	if opts.TTY && term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, rErr := term.MakeRaw(int(os.Stdin.Fd()))
		if rErr == nil {
			defer func() {
				_ = term.Restore(int(os.Stdin.Fd()), oldState)
			}()
		}

		// Initial window size
		if width, height, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
			_ = frameWriter.WriteFrame(protocol.StreamResize, protocol.EncodeWindowSize(uint16(height), uint16(width)))
		}

		// Watch SIGWINCH for window resizes
		sigwinch := make(chan os.Signal, 1)
		signal.Notify(sigwinch, syscall.SIGWINCH)
		defer signal.Stop(sigwinch)

		go func() {
			for range sigwinch {
				if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
					_ = frameWriter.WriteFrame(protocol.StreamResize, protocol.EncodeWindowSize(uint16(h), uint16(w)))
				}
			}
		}()

		// Pump os.Stdin -> StreamStdin frames
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					_ = frameWriter.WriteFrame(protocol.StreamStdin, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()
	}

	// Read responses from daemon
	for {
		streamType, payload, rErr := frameReader.ReadFrame()
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
