package seccomp

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Action represents the outcome when a rule matches.
type Action string

const (
	ActionAllow Action = "allow"
	ActionErrno Action = "errno"
	ActionKill  Action = "kill"
	ActionTrap  Action = "trap"
	ActionTrace Action = "trace"
)

// SyscallRule configures filtering for a named syscall.
type SyscallRule struct {
	Name   string `json:"name"`
	Action Action `json:"action"`
	Errno  uint32 `json:"errno,omitempty"`
}

// Profile represents the declarative JSON configuration for seccomp.
type Profile struct {
	DefaultAction Action        `json:"default_action"`
	Syscalls      []SyscallRule `json:"syscalls"`
}

// DefaultHardenedProfile returns the standard defense-in-depth sandbox profile.
func DefaultHardenedProfile() *Profile {
	return &Profile{
		DefaultAction: ActionAllow,
		Syscalls: []SyscallRule{
			{Name: "ptrace", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "bpf", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "kexec_load", Action: ActionKill},
			{Name: "kexec_file_load", Action: ActionKill},
			{Name: "reboot", Action: ActionKill},
			{Name: "sysfs", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "pivot_root", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "mount", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "umount2", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "swapon", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "swapoff", Action: ActionErrno, Errno: uint32(unix.EPERM)},
			{Name: "init_module", Action: ActionKill},
			{Name: "finit_module", Action: ActionKill},
			{Name: "delete_module", Action: ActionKill},
		},
	}
}

// LoadProfile reads and parses a JSON seccomp profile or returns the default profile if empty.
func LoadProfile(path string) (*Profile, error) {
	if path == "" {
		return DefaultHardenedProfile(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read seccomp profile: %w", err)
	}

	var prof Profile
	if err := json.Unmarshal(data, &prof); err != nil {
		return nil, fmt.Errorf("failed to parse seccomp profile json: %w", err)
	}

	return &prof, nil
}

type bpfInstruction struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *bpfInstruction
}

func actionToValue(act Action, errnoVal uint32) uint32 {
	switch act {
	case ActionAllow:
		return 0x7fff0000 // SECCOMP_RET_ALLOW
	case ActionErrno:
		if errnoVal == 0 {
			errnoVal = uint32(unix.EPERM)
		}
		return 0x00050000 | (errnoVal & 0x0000ffff) // SECCOMP_RET_ERRNO
	case ActionKill:
		return 0x00000000 // SECCOMP_RET_KILL_THREAD
	case ActionTrap:
		return 0x00030000 // SECCOMP_RET_TRAP
	case ActionTrace:
		return 0x7ff00000 // SECCOMP_RET_TRACE
	default:
		return 0x00050000 | uint32(unix.EPERM)
	}
}

func compileBPF(profile *Profile) ([]bpfInstruction, error) {
	const (
		bpfLd  = 0x00
		bpfW   = 0x00
		bpfAbs = 0x20
		bpfJmp = 0x05
		bpfJeq = 0x10
		bpfK   = 0x00
		bpfRet = 0x06
	)

	const (
		seccompDataNrOffset   = 0
		seccompDataArchOffset = 4
	)

	const auditArchX86_64 = 0xc000003e

	var filter []bpfInstruction

	// 1. Verify architecture
	filter = append(filter,
		bpfInstruction{code: bpfLd | bpfW | bpfAbs, k: seccompDataArchOffset},
		bpfInstruction{code: bpfJmp | bpfJeq | bpfK, jt: 1, jf: 0, k: auditArchX86_64},
		bpfInstruction{code: bpfRet | bpfK, k: 0x00000000},
	)

	// 2. Load syscall number
	filter = append(filter, bpfInstruction{code: bpfLd | bpfW | bpfAbs, k: seccompDataNrOffset})

	// 3. Map syscall names to numbers
	type compiledRule struct {
		nr    uint32
		value uint32
	}
	var rules []compiledRule

	for _, r := range profile.Syscalls {
		nr, ok := syscallNameToNR(r.Name)
		if !ok {
			continue
		}
		rules = append(rules, compiledRule{
			nr:    nr,
			value: actionToValue(r.Action, r.Errno),
		})
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].nr < rules[j].nr
	})

	// 4. Generate conditional jump checks
	defaultRet := actionToValue(profile.DefaultAction, uint32(unix.EPERM))

	for _, rule := range rules {
		filter = append(filter,
			bpfInstruction{code: bpfJmp | bpfJeq | bpfK, jt: 0, jf: 1, k: rule.nr},
			bpfInstruction{code: bpfRet | bpfK, k: rule.value},
		)
	}

	// 5. Default fallback
	filter = append(filter, bpfInstruction{code: bpfRet | bpfK, k: defaultRet})

	return filter, nil
}

// ApplyProfile compiles and loads the seccomp profile into the current thread/process.
func ApplyProfile(profilePath string) error {
	prof, err := LoadProfile(profilePath)
	if err != nil {
		return err
	}

	filter, err := compileBPF(prof)
	if err != nil {
		return fmt.Errorf("failed to compile seccomp filter: %w", err)
	}

	// PR_SET_NO_NEW_PRIVS is required before setting seccomp filter without CAP_SYS_ADMIN
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %w", err)
	}

	prog := sockFprog{
		len:    uint16(len(filter)),
		filter: &filter[0],
	}

	const seccompModeFilter = 2
	if err := unix.Prctl(unix.PR_SET_SECCOMP, seccompModeFilter, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return fmt.Errorf("failed to install seccomp filter: %w", err)
	}

	return nil
}

func syscallNameToNR(name string) (uint32, bool) {
	table := map[string]uint32{
		"read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5, "lstat": 6,
		"poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
		"rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16,
		"access": 21, "pipe": 22, "select": 23, "sched_yield": 24, "mremap": 25,
		"dup": 32, "dup2": 33, "pause": 34, "nanosleep": 35, "getpid": 39, "socket": 41,
		"connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45, "clone": 56,
		"fork": 57, "vfork": 58, "execve": 59, "exit": 60, "wait4": 61, "kill": 62,
		"uname": 63, "fcntl": 72, "fsync": 74, "getdents": 78, "getcwd": 79,
		"chdir": 80, "mkdir": 83, "rmdir": 84, "unlink": 87, "readlink": 89,
		"chmod": 90, "chown": 92, "umask": 95, "getuid": 102, "syslog": 103,
		"getgid": 104, "setuid": 105, "setgid": 106, "ptrace": 101, "prctl": 157,
		"pivot_root": 155, "mount": 165, "umount2": 166, "swapon": 167, "swapoff": 168,
		"reboot": 169, "sethostname": 170, "init_module": 175, "delete_module": 176,
		"futex": 202, "exit_group": 231, "epoll_wait": 232, "epoll_ctl": 233,
		"tgkill": 234, "kexec_load": 246, "openat": 257, "mkdirat": 258,
		"newfstatat": 262, "unlinkat": 263, "unshare": 272, "finit_module": 313,
		"seccomp": 317, "kexec_file_load": 320, "bpf": 321, "clone3": 435, "close_range": 436,
	}
	val, ok := table[name]
	return val, ok
}
