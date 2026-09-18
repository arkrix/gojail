package sandbox

import "time"

// ResourceMetrics contains accounting information collected from Cgroups v2.
type ResourceMetrics struct {
	PeakMemoryBytes int64 `json:"peak_memory_bytes"`
	UserCPUTimeUS   int64 `json:"user_cpu_time_us"`
	SystemCPUTimeUS int64 `json:"system_cpu_time_us"`
}

// Config defines the constraints and execution parameters for a sandbox run.
type Config struct {
	ID               string        `json:"id"`
	MemoryLimitBytes int64         `json:"memory_limit_bytes"`
	MaxProcesses     int64         `json:"max_processes"`
	StorageLimitMB   int64         `json:"storage_limit_mb"`
	Timeout          time.Duration `json:"timeout"`
	Command          string        `json:"command"`
	Args             []string      `json:"args"`
	Env              []string      `json:"env"`
	RootPath         string        `json:"root_path,omitempty"`
}

// Result holds standard output, errors, execution timings, and resource telemetry.
type Result struct {
	ExitCode int             `json:"exit_code"`
	Stdout   string          `json:"stdout"`
	Stderr   string          `json:"stderr"`
	Duration time.Duration   `json:"duration"`
	TimedOut bool            `json:"timed_out"`
	Metrics  ResourceMetrics `json:"metrics"`
}
