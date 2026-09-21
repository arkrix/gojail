package sandbox

import (
	"fmt"
	"unsafe"

	"github.com/arkrix/gojail/pkg/seccomp"
	"golang.org/x/sys/unix"
)

// BPF constants from Linux socket filter interface
const (
	bpfLd  = 0x00
	bpfW   = 0x00
	bpfAbs = 0x20
	bpfJmp = 0x05
	bpfJeq = 0x10
	bpfK   = 0x00
	bpfRet = 0x06
)

// bpfInstruction defines an individual BPF filter operation
type bpfInstruction struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog defines the BPF program passed to seccomp
type sockFprog struct {
	len    uint16
	filter *bpfInstruction
}

// DropCapabilities clears ambient, bounding, and effective Linux capabilities.
func DropCapabilities() error {
	// Set PR_SET_NO_NEW_PRIVS so no future child can escalate privileges
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// Drop all bounding capabilities without shadowing built-in cap()
	for capID := 0; capID <= 63; capID++ {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capID), 0, 0, 0)
	}

	return nil
}

// ApplySeccompFilter installs a configurable profile via pkg/seccomp,
// falling back to the default denylist if no profile path is provided.
func ApplySeccompFilter(profilePath string) error {
	if profilePath != "" {
		return seccomp.ApplyProfile(profilePath)
	}
	return ApplySeccompDenylist()
}

// ApplySeccompDenylist installs a raw BPF seccomp filter blocking high-risk syscalls.
func ApplySeccompDenylist() error {
	blockedSyscalls := []uint32{
		uint32(unix.SYS_PTRACE),
		uint32(unix.SYS_BPF),
		uint32(unix.SYS_MOUNT),
		uint32(unix.SYS_UMOUNT2),
		uint32(unix.SYS_PIVOT_ROOT),
		uint32(unix.SYS_REBOOT),
		uint32(unix.SYS_KEXEC_LOAD),
		uint32(unix.SYS_SYSLOG),
		uint32(unix.SYS_KEYCTL),
		uint32(unix.SYS_ADD_KEY),
		uint32(unix.SYS_REQUEST_KEY),
		uint32(unix.SYS_SWAPON),
		uint32(unix.SYS_SWAPOFF),
		uint32(unix.SYS_CHROOT),
	}

	var filter []bpfInstruction

	filter = append(filter, bpfInstruction{
		code: bpfLd | bpfW | bpfAbs,
		jt:   0,
		jf:   0,
		k:    0,
	})

	totalBlocked := len(blockedSyscalls)
	for i, syscallNum := range blockedSyscalls {
		jumpTrue := uint8(totalBlocked - i)
		filter = append(filter, bpfInstruction{
			code: bpfJmp | bpfJeq | bpfK,
			jt:   jumpTrue,
			jf:   0,
			k:    syscallNum,
		})
	}

	filter = append(filter, bpfInstruction{
		code: bpfRet | bpfK,
		jt:   0,
		jf:   0,
		k:    unix.SECCOMP_RET_ALLOW,
	})

	filter = append(filter, bpfInstruction{
		code: bpfRet | bpfK,
		jt:   0,
		jf:   0,
		k:    unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & 0x0000ffff),
	})

	prog := sockFprog{
		len:    uint16(len(filter)),
		filter: &filter[0],
	}

	_, _, errno := unix.Syscall(
		unix.SYS_PRCTL,
		unix.PR_SET_SECCOMP,
		unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return fmt.Errorf("prctl(PR_SET_SECCOMP) failed: %w", errno)
	}

	return nil
}
