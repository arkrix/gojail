package network

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestIPAM_AllocationAndRelease(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	ipam, err := NewIPAMWithPaths("10.200.0.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	ip1, err := ipam.AllocateIP("container-1")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}

	if ip1.String() != "10.200.0.2" {
		t.Errorf("expected 10.200.0.2, got %s", ip1.String())
	}

	// Idempotency check: same container should receive same IP
	ip1Again, err := ipam.AllocateIP("container-1")
	if err != nil {
		t.Fatalf("idempotent allocation failed: %v", err)
	}
	if !ip1.Equal(ip1Again) {
		t.Errorf("expected same IP for same container, got %s vs %s", ip1, ip1Again)
	}

	// Next container gets next sequential address
	ip2, err := ipam.AllocateIP("container-2")
	if err != nil {
		t.Fatalf("failed to allocate IP 2: %v", err)
	}
	if ip2.String() != "10.200.0.3" {
		t.Errorf("expected 10.200.0.3, got %s", ip2.String())
	}

	// Release container 1
	if err := ipam.ReleaseIP("container-1"); err != nil {
		t.Fatalf("failed to release IP: %v", err)
	}

	// Container 3 should reuse the released 10.200.0.2 address
	ip3, err := ipam.AllocateIP("container-3")
	if err != nil {
		t.Fatalf("failed to allocate IP 3: %v", err)
	}
	if ip3.String() != "10.200.0.2" {
		t.Errorf("expected recycled IP 10.200.0.2, got %s", ip3.String())
	}
}

func TestIPAM_ConcurrentAllocations(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	ipam, err := NewIPAMWithPaths("10.200.0.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	const workerCount = 20
	var wg sync.WaitGroup
	allocated := sync.Map{}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cID := fmt.Sprintf("jail-concurrent-%d", id)
			ip, aErr := ipam.AllocateIP(cID)
			if aErr != nil {
				t.Errorf("failed allocating for %s: %v", cID, aErr)
				return
			}
			if _, loaded := allocated.LoadOrStore(ip.String(), cID); loaded {
				t.Errorf("duplicate IP collision detected: %s", ip.String())
			}
		}(i)
	}

	wg.Wait()
}
