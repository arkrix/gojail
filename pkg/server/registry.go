package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
	"github.com/arkrix/gojail/pkg/sandbox"
)

type activeJob struct {
	info    protocol.JobInfo
	cancel  context.CancelFunc
	cgroup  *sandbox.CgroupController
	memLim  int64
	procLim int64
}

// JobRegistry provides thread-safe runtime container tracking.
type JobRegistry struct {
	mu   sync.RWMutex
	jobs map[string]*activeJob
}

// NewJobRegistry initializes an empty container tracking table.
func NewJobRegistry() *JobRegistry {
	return &JobRegistry{
		jobs: make(map[string]*activeJob),
	}
}

// Register adds a new active container instance to the registry.
func (r *JobRegistry) Register(id string, pid int, cmd string, args []string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.jobs[id] = &activeJob{
		info: protocol.JobInfo{
			ID:        id,
			PID:       pid,
			Command:   cmd,
			Args:      args,
			Status:    "running",
			StartTime: time.Now(),
		},
		cancel: cancel,
	}
}

// AttachCgroup associates the active cgroup controller and resource limits with the job.
func (r *JobRegistry) AttachCgroup(id string, cg *sandbox.CgroupController, memLimit, procLimit int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if job, exists := r.jobs[id]; exists {
		job.cgroup = cg
		job.memLim = memLimit
		job.procLim = procLimit
	}
}

// GetJob returns a copy of the job info and its active cgroup controller if present.
func (r *JobRegistry) GetJob(id string) (protocol.JobInfo, *sandbox.CgroupController, int64, int64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	job, exists := r.jobs[id]
	if !exists {
		return protocol.JobInfo{}, nil, 0, 0, false
	}
	return job.info, job.cgroup, job.memLim, job.procLim, true
}

// UpdatePID records the container host PID once spawned.
func (r *JobRegistry) UpdatePID(id string, pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if job, exists := r.jobs[id]; exists {
		job.info.PID = pid
	}
}

// UpdateFinished finalizes metadata when the job completes.
func (r *JobRegistry) UpdateFinished(id string, exitCode int, peakMem int64, timedOut bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	job, exists := r.jobs[id]
	if !exists {
		return
	}

	job.info.ExitCode = exitCode
	job.info.PeakMemoryBytes = peakMem
	job.info.Duration = time.Since(job.info.StartTime)

	if job.info.Status == "killed" {
		return
	}

	if timedOut {
		job.info.Status = "timed_out"
	} else if exitCode == 0 {
		job.info.Status = "completed"
	} else {
		job.info.Status = "failed"
	}
}

// Pause halts execution of all processes inside the container's cgroup.
func (r *JobRegistry) Pause(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	job, exists := r.jobs[id]
	if !exists {
		return fmt.Errorf("container instance %q not found", id)
	}

	if job.info.Status != "running" {
		return fmt.Errorf("cannot pause container %q with status %q", id, job.info.Status)
	}

	if job.cgroup == nil {
		return fmt.Errorf("cgroup controller not attached to container %q", id)
	}

	if err := job.cgroup.Freeze(); err != nil {
		return fmt.Errorf("failed to freeze container cgroup: %w", err)
	}

	job.info.Status = "paused"
	return nil
}

// Unpause resumes execution of all frozen processes inside the container's cgroup.
func (r *JobRegistry) Unpause(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	job, exists := r.jobs[id]
	if !exists {
		return fmt.Errorf("container instance %q not found", id)
	}

	if job.info.Status != "paused" {
		return fmt.Errorf("cannot unpause container %q with status %q", id, job.info.Status)
	}

	if job.cgroup == nil {
		return fmt.Errorf("cgroup controller not attached to container %q", id)
	}

	if err := job.cgroup.Thaw(); err != nil {
		return fmt.Errorf("failed to thaw container cgroup: %w", err)
	}

	job.info.Status = "running"
	return nil
}

// Stop signals cancellation to an active container job.
func (r *JobRegistry) Stop(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	job, exists := r.jobs[id]
	if !exists {
		return fmt.Errorf("container instance %q not found", id)
	}

	if job.info.Status != "running" && job.info.Status != "paused" {
		return fmt.Errorf("container instance %q is not active (current status: %s)", id, job.info.Status)
	}

	// If paused, thaw before canceling so SIGKILL/context cancel can be handled
	if job.info.Status == "paused" && job.cgroup != nil {
		_ = job.cgroup.Thaw()
	}

	job.info.Status = "killed"
	if job.cancel != nil {
		job.cancel()
	}
	return nil
}

// List returns a point-in-time snapshot of all active and finished jobs.
func (r *JobRegistry) List() []protocol.JobInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]protocol.JobInfo, 0, len(r.jobs))
	for _, job := range r.jobs {
		info := job.info
		if info.Status == "running" || info.Status == "paused" {
			info.Duration = time.Since(info.StartTime)
		}
		result = append(result, info)
	}
	return result
}
