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
	"syscall"
	"time"

	"github.com/arkrix/gojail/pkg/config"
	"github.com/arkrix/gojail/pkg/protocol"
	"github.com/arkrix/gojail/pkg/sandbox"
)

// Request defines the wire format sent by clients over the Unix socket.
type Request = protocol.Request

// Daemon represents the long-running gojaild server instance.
type Daemon struct {
	cfg      *config.DaemonConfig
	listener net.Listener
	shutdown chan struct{}
	wg       sync.WaitGroup
	pool     *sandbox.Pool
	registry *JobRegistry
	lockFile *os.File
}

// NewDaemon initializes a new Unix socket daemon driven by DaemonConfig.
func NewDaemon(cfg *config.DaemonConfig) *Daemon {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Daemon{
		cfg:      cfg,
		registry: NewJobRegistry(),
		shutdown: make(chan struct{}),
	}
}

// Start acquires the daemon lock, executes crash recovery, warms sandboxes, and starts accepting requests.
func (d *Daemon) Start() error {
	// 1. Ensure single running daemon instance via advisory flock
	lockFile, err := AcquireDaemonLock("/var/run/gojaild.pid")
	if err != nil {
		return fmt.Errorf("daemon start aborted: %w", err)
	}
	d.lockFile = lockFile

	// 2. Perform crash recovery: sweep lingering mounts, scratch layers, and dead cgroups
	if unmounted, err := SweepStaleMounts(defaultLayersDir); err != nil {
		fmt.Fprintf(os.Stderr, "[recovery] Error sweeping mounts: %v\n", err)
	} else if unmounted > 0 {
		fmt.Printf("[recovery] Cleaned %d orphaned mount points from previous runs\n", unmounted)
	}

	if err := ResetLayersTree(defaultLayersDir); err != nil {
		fmt.Fprintf(os.Stderr, "[recovery] Error resetting layers: %v\n", err)
	}

	if err := SweepStaleCgroups(); err != nil {
		fmt.Fprintf(os.Stderr, "[recovery] Error sweeping cgroups: %v\n", err)
	}

	// 3. Initialize standby sandbox pool
	poolSize := d.cfg.Pool.WarmWorkers
	if poolSize <= 0 {
		poolSize = 2
	}

	storageLimit := d.cfg.Defaults.StorageLimitMB
	if storageLimit <= 0 {
		storageLimit = 64
	}

	pool, err := sandbox.NewPoolWithStorage(poolSize, storageLimit)
	if err != nil {
		return fmt.Errorf("failed to initialize warm pool: %w", err)
	}
	d.pool = pool

	// 4. Bind Unix domain socket
	socketPath := d.cfg.Server.SocketPath
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
	}

	mode := os.FileMode(d.cfg.Server.SocketMode)
	if mode == 0 {
		mode = 0666
	}

	if err := os.Chmod(socketPath, mode); err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	d.listener = listener
	fmt.Printf("[gojaild] Listening on unix://%s (Pool: %d workers, Storage: %dMB, Mode: %04o)\n",
		socketPath, poolSize, storageLimit, mode)

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

	frameWriter := protocol.NewFrameWriter(conn)
	frameReader := protocol.NewFrameReader(conn)

	var req protocol.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
				ExitCode: 1,
				Error:    fmt.Sprintf("invalid request payload: %v", err),
			})
		}
		return
	}

	// Dispatch non-streaming control commands ("list" / "stop")
	switch req.Action {
	case "list":
		jobs := d.registry.List()
		_ = json.NewEncoder(conn).Encode(protocol.ControlResponse{
			Success: true,
			Jobs:    jobs,
		})
		return

	case "stop":
		err := d.registry.Stop(req.TargetID)
		resp := protocol.ControlResponse{Success: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(resp)
		return
	}

	// Default action: execute container workload
	if req.Timeout == 0 {
		req.Timeout = time.Duration(d.cfg.Defaults.TimeoutSec) * time.Second
	}
	if req.MemoryLimitBytes == 0 {
		req.MemoryLimitBytes = d.cfg.Defaults.MemoryLimitMB * 1024 * 1024
	}
	if req.MaxProcesses == 0 {
		req.MaxProcesses = d.cfg.Defaults.MaxProcesses
	}
	if req.StorageLimitMB == 0 {
		req.StorageLimitMB = d.cfg.Defaults.StorageLimitMB
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()

	initialCmd := []string{req.Command}
	if len(req.Args) > 0 {
		initialCmd = append(initialCmd, req.Args...)
	}

	worker, err := d.pool.AcquireCustom(req.StorageLimitMB, req.Mounts, req.TTY, initialCmd)
	if err != nil {
		_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    fmt.Sprintf("worker acquire failed: %v", err),
		})
		return
	}

	// Register active container instance in daemon registry
	d.registry.Register(worker.ID, 0, req.Command, req.Args, cancel)

	var writeMu sync.Mutex

	if req.TTY {
		go func() {
			for {
				streamType, payload, rErr := frameReader.ReadFrame()
				if rErr != nil {
					break
				}
				switch streamType {
				case protocol.StreamStdin:
					_ = worker.WriteInput(payload)
				case protocol.StreamResize:
					ws, pErr := protocol.ParseWindowSize(payload)
					if pErr == nil {
						_ = worker.Resize(ws.Rows, ws.Cols)
					}
				}
			}
		}()

		ptyHandler := sandbox.PTYIOHandler{
			OnOutput: func(chunk []byte) {
				writeMu.Lock()
				_ = frameWriter.WriteFrame(protocol.StreamStdout, chunk)
				writeMu.Unlock()
			},
		}

		res, ptyErr := worker.ExecutePTY(ctx, ptyHandler)
		if ptyErr != nil {
			d.registry.UpdateFinished(worker.ID, 1, 0, false)
			_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
				ExitCode: 1,
				Error:    ptyErr.Error(),
			})
			return
		}

		d.registry.UpdateFinished(worker.ID, res.ExitCode, res.Metrics.PeakMemoryBytes, res.TimedOut)

		_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
			ExitCode: res.ExitCode,
			Duration: res.Duration,
			TimedOut: res.TimedOut,
			Metrics:  res.Metrics,
		})
		return
	}

	script := strings.Join(req.Args, " ")
	if len(req.Args) >= 2 && req.Args[0] == "-c" {
		script = req.Args[1]
	}

	handler := sandbox.StreamHandler{
		OnStdout: func(chunk []byte) {
			writeMu.Lock()
			_ = frameWriter.WriteFrame(protocol.StreamStdout, chunk)
			writeMu.Unlock()
		},
		OnStderr: func(chunk []byte) {
			writeMu.Lock()
			_ = frameWriter.WriteFrame(protocol.StreamStderr, chunk)
			writeMu.Unlock()
		},
	}

	res, err := worker.ExecuteStream(ctx, script, handler)
	if err != nil {
		d.registry.UpdateFinished(worker.ID, 1, 0, false)
		_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    err.Error(),
		})
		return
	}

	d.registry.UpdateFinished(worker.ID, res.ExitCode, res.Metrics.PeakMemoryBytes, res.TimedOut)

	_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
		ExitCode: res.ExitCode,
		Duration: res.Duration,
		TimedOut: res.TimedOut,
		Metrics:  res.Metrics,
	})
}

// Stop gracefully terminates the listener, shuts down workers, and releases the PID lock.
func (d *Daemon) Stop() {
	close(d.shutdown)
	if d.listener != nil {
		_ = d.listener.Close()
	}
	if d.pool != nil {
		d.pool.Close()
	}
	d.wg.Wait()
	_ = os.Remove(d.cfg.Server.SocketPath)

	if d.lockFile != nil {
		_ = syscall.Flock(int(d.lockFile.Fd()), syscall.LOCK_UN)
		_ = d.lockFile.Close()
		_ = os.Remove("/var/run/gojaild.pid")
	}

	fmt.Println("[gojaild] Daemon stopped cleanly")
}
