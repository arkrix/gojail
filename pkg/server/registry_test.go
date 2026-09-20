package server

import (
	"context"
	"testing"
)

func TestJobRegistry_RegisterAndList(t *testing.T) {
	reg := NewJobRegistry()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.Register("job-1", 1234, "/bin/echo", []string{"hello"}, cancel)

	jobs := reg.List()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].ID != "job-1" {
		t.Errorf("expected ID 'job-1', got %s", jobs[0].ID)
	}
	if jobs[0].Status != "running" {
		t.Errorf("expected status 'running', got %s", jobs[0].Status)
	}
	if jobs[0].Command != "/bin/echo" {
		t.Errorf("expected command '/bin/echo', got %s", jobs[0].Command)
	}
}

func TestJobRegistry_UpdateFinished(t *testing.T) {
	reg := NewJobRegistry()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.Register("job-1", 1234, "/bin/sh", nil, cancel)
	reg.UpdateFinished("job-1", 0, 1024*1024, false)

	jobs := reg.List()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].Status != "completed" {
		t.Errorf("expected status 'completed', got %s", jobs[0].Status)
	}
	if jobs[0].ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", jobs[0].ExitCode)
	}
	if jobs[0].PeakMemoryBytes != 1024*1024 {
		t.Errorf("expected 1MB peak memory, got %d", jobs[0].PeakMemoryBytes)
	}
}

func TestJobRegistry_Stop(t *testing.T) {
	reg := NewJobRegistry()

	canceled := false
	cancel := func() {
		canceled = true
	}

	reg.Register("job-1", 1234, "/bin/sleep", []string{"100"}, cancel)

	if err := reg.Stop("job-1"); err != nil {
		t.Fatalf("expected stop to succeed, got %v", err)
	}

	if !canceled {
		t.Errorf("expected cancel func to be invoked on stop")
	}

	jobs := reg.List()
	if jobs[0].Status != "killed" {
		t.Errorf("expected status 'killed', got %s", jobs[0].Status)
	}

	if err := reg.Stop("job-1"); err == nil {
		t.Errorf("expected error when stopping non-running job, got nil")
	}
	if err := reg.Stop("nonexistent"); err == nil {
		t.Errorf("expected error when stopping nonexistent job, got nil")
	}
}

func TestJobRegistry_PauseAndUnpauseValidation(t *testing.T) {
	reg := NewJobRegistry()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.Register("job-1", 1234, "/bin/sleep", []string{"60"}, cancel)

	// Pausing without an attached cgroup controller should fail
	if err := reg.Pause("job-1"); err == nil {
		t.Errorf("expected error when pausing job without attached cgroup, got nil")
	}

	// Unpausing a running job should fail
	if err := reg.Unpause("job-1"); err == nil {
		t.Errorf("expected error when unpausing non-paused job, got nil")
	}

	// Pausing or unpausing nonexistent job should fail
	if err := reg.Pause("nonexistent"); err == nil {
		t.Errorf("expected error when pausing nonexistent job, got nil")
	}
	if err := reg.Unpause("nonexistent"); err == nil {
		t.Errorf("expected error when unpausing nonexistent job, got nil")
	}
}
