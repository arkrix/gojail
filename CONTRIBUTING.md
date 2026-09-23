# Contributing to gojail

Thank you for your interest in contributing to `gojail`! As a low-level container runtime and process isolation engine, stability, determinism, and security are critical.

Please review the following guidelines before submitting code or proposing architectural changes.

---

## Development Prerequisites

- **OS:** Linux with kernel version $\ge$ 5.8 (with Cgroups v2 enabled and mounted at `/sys/fs/cgroup`).
- **Go:** Version 1.22 or higher.
- **Privileges:** Root access (`sudo`) is required to run namespace, mount, and cgroup integration tests.

---

## Local Development Workflow

### 1. Formatting

All Go source files must strictly conform to standard `gofmt` style:

```bash
gofmt -w .

# Verify no files need formatting
gofmt -l .
```

### 2. Static Analysis & Vulnerability Auditing

```bash
go vet ./...
govulncheck ./...
```

### 3. Running Tests

Run non-root unit tests with the race detector enabled:

```bash
go test -v -race ./pkg/...
```

Run integration and root suites (handles namespace allocation, Cgroup v2 limits, and OverlayFS):

```bash
sudo -E env "PATH=$PATH" go test -v ./pkg/sandbox/...
sudo -E env "PATH=$PATH" go test -v ./pkg/server/...
```

## Commit Message Convention

`gojail` strictly follows **Conventional Commits** using scoped prefixes:

```text
<type>(<scope>): <short summary in lowercase>
```

### Allowed Types

- `feat`: New feature or runtime capability.
- `fix`: Bug fix or crash resolution.
- `docs`: Documentation updates or additions.
- `ci`: Workflow, pipeline, or action changes.
- `test`: Adding or refactoring test suites.
- `chore`: Dependency updates, maintenance, or tooling.

### Common Scopes

- `sandbox`: Namespaces, process runner, or confinement primitives.
- `cgroups`: Cgroup v2 limits, freeze/thaw, and metrics collection.
- `seccomp`: Syscall filters and BPF profile loading.
- `daemon`: Server lifecycle, recovery, or worker pools.
- `client`: CLI flags, command handling, and socket IPC.
- `storage`: OverlayFS management, volume mounts, or disk quotas.

### Examples

- `feat(sandbox): add network namespace loopback auto-configuration`
- `fix(cgroups): ensure parent subtree control delegates controllers to child slices`
- `docs(readme): update cgroup delegation instructions for ubuntu runners`

## Pull Request Guidelines

1. **Keep Pull Requests Focused:** Avoid combining unrelated bug fixes, refactors, and feature additions into a single PR.
2. **Sign Your Commits:** Include the `-s` / `--signoff` flag (`Signed-off-by: Name <email>`) when committing.
3. **CI Passing:** All checks in `.github/workflows/ci.yml` (Formatting, `govulncheck`, Unit Tests, Root Integration Tests, Cross-Architecture Builds) must be green.
4. **Duplication & Quality:** Ensure new additions maintain clean separation of concerns and do not duplicate existing device initialization or runtime logic.