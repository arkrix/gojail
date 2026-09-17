package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arkrix/gojail/pkg/sandbox"
)

// Request defines the wire format sent by clients over the Unix socket.
type Request struct {
	Command          string        `json:"command"`
	Args             []string      `json:"args"`
	Env              []string      `json:"env"`
	Timeout          time.Duration `json:"timeout"`
	MemoryLimitBytes int64         `json:"memory_limit_bytes"`
	MaxProcesses     int64         `json:"max_processes"`
}

// Response defines the wire format returned by the daemon.
type Response struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	TimedOut bool          `json:"timed_out"`
	Error    string        `json:"error,omitempty"`
}

// Daemon represents the long-running gojaild server instance.
type Daemon struct {
	socketPath string
	listener   net.Listener
	shutdown   chan struct{}
	wg         sync.WaitGroup
}

// NewDaemon initializes a new Unix socket daemon.
func NewDaemon(socketPath string) *Daemon {
	if socketPath == "" {
		socketPath = "/var/run/gojail.sock"
	}
	return &Daemon{
		socketPath: socketPath,
		shutdown:   make(chan struct{}),
	}
}

// Start creates the socket, sets permissions, and begins accepting connections.
func (d *Daemon) Start() error {
	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Clean up stale socket if it exists
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", d.socketPath, err)
	}

	// Restrict permissions to owner and group read/write (0660) to prevent untrusted world access
	if err := os.Chmod(d.socketPath, 0660); err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	d.listener = listener
	fmt.Printf("[gojaild] Listening on unix://%s\n", d.socketPath)

	d.wg.Add(1)
	go d.acceptLoop()

	return nil
}

func (d *Daemon) acceptLoop() {
	defer d.wg.Done()

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.shutdown:
				return
			default:
				fmt.Fprintf(os.Stderr, "[gojaild] Accept error: %v\n", err)
				continue
			}
		}

		d.wg.Add(1)
		go func(c net.Conn) {
			defer d.wg.Done()
			d.handleConnection(c)
		}(conn)
	}
}

func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			_ = encoder.Encode(Response{Error: fmt.Sprintf("invalid request payload: %v", err)})
		}
		return
	}

	// Populate defaults
	if req.Command == "" {
		req.Command = "/bin/sh"
	}
	if req.Timeout == 0 {
		req.Timeout = 10 * time.Second
	}
	if req.MemoryLimitBytes == 0 {
		req.MemoryLimitBytes = 128 * 1024 * 1024
	}
	if req.MaxProcesses == 0 {
		req.MaxProcesses = 64
	}
	if len(req.Env) == 0 {
		req.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"}
	}

	sandboxID := fmt.Sprintf("jail-%d", time.Now().UnixNano())
	cfg := sandbox.Config{
		ID:               sandboxID,
		MemoryLimitBytes: req.MemoryLimitBytes,
		MaxProcesses:     req.MaxProcesses,
		Timeout:          req.Timeout,
		Command:          req.Command,
		Args:             req.Args,
		Env:              req.Env,
	}

	runner := sandbox.NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		_ = encoder.Encode(Response{Error: err.Error()})
		return
	}

	_ = encoder.Encode(Response{
		ExitCode: res.ExitCode,
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		Duration: res.Duration,
		TimedOut: res.TimedOut,
	})
}

// Stop gracefully shuts down the listener and waits for active connections.
func (d *Daemon) Stop() {
	close(d.shutdown)
	if d.listener != nil {
		_ = d.listener.Close()
	}
	d.wg.Wait()
	_ = os.Remove(d.socketPath)
	fmt.Println("[gojaild] Daemon stopped cleanly")
}
