# guard-scanner Public-Safe Boundary

`guard-scanner` ships two distinct surfaces:

- `runtime-plugin`: OpenClaw hook-only control plane for `before_tool_call` blocking and local audit logging.
- `scanner-core`: CLI and report generation plane for repo-wide scans, SARIF export, CI/CD, and heavy analysis.

## Plugin Allowed

- OpenClaw manifest and hook registration
- bounded runtime payload scanning
- local audit log writes
- schema validation
- inventory and doctor checks

## Plugin Forbidden

- shell escalation
- publish or release automation
- remote admin mutation
- keychain mutation
- social posting
- unmanaged long-running jobs

## Core Required

- machine-readable JSON output
- SARIF export
- explicit exit codes for CI/CD
- repo-surface analysis separate from runtime payload scanning

## Surface Modes

- `runtime_payload_scan`: inspect tool arguments and runtime payloads only
- `repo_surface_scan`: inspect repository/package surface for code and manifest risks

Package-surface findings are valid security signals, but they are not by themselves proof that the runtime plugin is exploitable.
