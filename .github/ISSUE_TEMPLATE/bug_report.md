---
name: Bug report
about: Create a report to help reproduce and resolve an issue in gojail
title: "fix(<scope>): "
labels: ["type: bug"]
assignees: ''
---

## Description

A clear and concise description of what the bug is.

## Environment Information

* **OS / Linux Kernel:** (e.g., Ubuntu 24.04, Linux 6.8.0)
* **Go Version:** (`go version`)
* **Cgroup Version:** (Cgroups v2 / Unified Hierarchy)
* **Gojail Commit SHA / Version:**

## Steps to Reproduce

1. Execute command: `...`
2. Configuration applied:

```json
{
  "ID": "test-sandbox",
  "MemoryLimitBytes": 67108864
}
```

3. Observe behavior or error.

## Expected Behavior

A concise explanation of what you expected to happen.

## Actual Behavior / Logs

```text
Paste terminal output or stderr logs here
```

## Additional Context

Add any other context, such as custom seccomp filters or mount restrictions.