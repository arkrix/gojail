package client

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
)

func TestClient_Run(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteFrame(protocol.StreamStdout, []byte("hello from daemon"))
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 0,
			Duration: 10 * time.Millisecond,
		})
	}()

	c := NewClient(sockPath)
	resp, err := c.Run(ExecOptions{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", resp.ExitCode)
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	c := NewClient("/tmp/nonexistent_gojail_socket.sock")
	_, err := c.Run(ExecOptions{
		Command: "/bin/echo",
	})
	if err == nil {
		t.Errorf("expected error on missing socket, got nil")
	}
}

func TestClient_StreamStats(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_stats.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteStatsFrame(protocol.StatsPayload{
			ContainerID:      "test-jail-1",
			Timestamp:        time.Now(),
			MemoryBytes:      32 * 1024 * 1024,
			MemoryLimitBytes: 128 * 1024 * 1024,
			PeakMemoryBytes:  40 * 1024 * 1024,
			CPUPercent:       15.5,
			PIDsCurrent:      3,
			PIDsLimit:        64,
		})
		_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: 0})
	}()

	c := NewClient(sockPath)
	receivedSamples := 0

	err = c.StreamStats("test-jail-1", func(s protocol.StatsPayload) {
		receivedSamples++
		if s.ContainerID != "test-jail-1" {
			t.Errorf("expected container ID 'test-jail-1', got %s", s.ContainerID)
		}
		if s.CPUPercent != 15.5 {
			t.Errorf("expected CPU percent 15.5, got %.2f", s.CPUPercent)
		}
		if s.PIDsCurrent != 3 {
			t.Errorf("expected 3 current PIDs, got %d", s.PIDsCurrent)
		}
	})

	if err != nil {
		t.Fatalf("StreamStats failed: %v", err)
	}

	if receivedSamples != 1 {
		t.Fatalf("expected 1 sample, got %d", receivedSamples)
	}
}

func TestClient_PauseAndUnpause(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_pause.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, aErr := l.Accept()
			if aErr != nil {
				return
			}

			var req protocol.Request
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				continue
			}

			var resp protocol.ControlResponse
			if req.TargetID == "test-jail-1" && (req.Action == "pause" || req.Action == "unpause") {
				resp.Success = true
			} else {
				resp.Success = false
				resp.Error = "invalid target or action"
			}

			_ = json.NewEncoder(conn).Encode(resp)
			conn.Close()
		}
	}()

	c := NewClient(sockPath)

	if err := c.PauseJob("test-jail-1"); err != nil {
		t.Fatalf("PauseJob failed: %v", err)
	}

	if err := c.UnpauseJob("test-jail-1"); err != nil {
		t.Fatalf("UnpauseJob failed: %v", err)
	}

	if err := c.PauseJob("invalid-id"); err == nil {
		t.Errorf("expected error on invalid target, got nil")
	}
}
