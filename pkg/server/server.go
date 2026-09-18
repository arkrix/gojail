package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	ExitCode int                     `json:"exit_code"`
	Stdout   string                  `json:"stdout"`
	Stderr   string                  `json:"stderr"`
	Duration time.Duration           `json:"duration"`
	TimedOut bool                    `json:"timed_out"`
	Metrics  sandbox.ResourceMetrics `json:"metrics"`
	Error    string                  `json:"error,omitempty"`
}

// Daemon represents the long-running gojaild server instance.
type Daemon struct {
	socketPath string
	listener   net.Listener
	shutdown   chan struct{}
	wg         sync.WaitGroup
	pool       *sandbox.Pool
}

// NewDaemon initializes a new Unix socket daemon with a warm pool.
func NewDaemon(socketPath string) *Daemon {
	if socketPath == "" {
		socketPath = "/var/run/gojail.sock"
	}
	return &Daemon{
		socketPath: socketPath,
		shutdown:   make(chan struct{}),
	}
}

// Start creates the socket, warms up sandboxes, and begins accepting connections.
func (d *Daemon) Start() error {
	pool, err := sandbox.NewPool(2)
	if err != nil {
		return fmt.Errorf("failed to initialize warm pool: %w", err)
	}
	d.pool = pool

	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", d.socketPath, err)
	}

	if err := os.Chmod(d.socketPath, 0666); err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	d.listener = listener
	fmt.Printf("[gojaild] Listening on unix://%s (Warm Pool Ready)\n", d.socketPath)

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

	if req.Timeout == 0 {
		req.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()

	script := strings.Join(req.Args, " ")
	if len(req.Args) >= 2 && req.Args[0] == "-c" {
		script = req.Args[1]
	}

	worker, err := d.pool.Acquire()
	if err != nil {
		_ = encoder.Encode(Response{Error: fmt.Sprintf("worker acquire failed: %v", err)})
		return
	}

	res, err := worker.Execute(ctx, script)
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
		Metrics:  res.Metrics,
	})
}

// Stop gracefully shuts down the listener and active workers.
func (d *Daemon) Stop() {
	close(d.shutdown)
	if d.listener != nil {
		_ = d.listener.Close()
	}
	if d.pool != nil {
		d.pool.Close()
	}
	d.wg.Wait()
	_ = os.Remove(d.socketPath)
	fmt.Println("[gojaild] Daemon stopped cleanly")
}
