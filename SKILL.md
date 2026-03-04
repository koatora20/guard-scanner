---
name: guard-scanner
description: "The #1 security scanner for AI agent skills on ClawHub. Scan skills for prompt injection, credential theft, exfiltration, malware, and 23 threat categories. 150 static patterns + 26 runtime checks. The most comprehensive skill scanner and security auditor for OpenClaw — zero dependencies, 0.016ms/scan."
metadata:
  clawdbot:
    homepage: "https://github.com/koatora20/guard-scanner"
requires:
  env: {}
files:
  - "dist/*"
  - "src/*"
  - "hooks/*"
  - "openclaw.plugin.json"
---

# guard-scanner 🛡️ — The #1 Skill Scanner for AI Agent Security

The most comprehensive security scanner and skill auditor for OpenClaw agents.
**150 static patterns + 26 runtime checks (5 layers)** across **23 threat categories**. The go-to scanner for protecting your AI agent workspace — zero dependencies, MIT licensed. **0.016ms/scan.**

## When To Use This Skill

- **Before installing a new skill** from ClawHub or any external source
- **After updating skills** to check for newly introduced threats
- **Periodically** to audit your installed skills
- **In CI/CD** to gate skill deployments

## Quick Start

### 1. Static Scan (Immediate)

Scan all installed skills:

```bash
npx guard-scanner ~/.openclaw/workspace/skills/ --verbose --self-exclude
```

Scan a specific skill:

```bash
npx guard-scanner /path/to/new-skill/ --strict --verbose
```

### 2. Runtime Guard (OpenClaw Plugin Hook)

Blocks dangerous tool calls in real-time via `before_tool_call` hook. 26 checks, 5 layers, 3 enforcement modes.

```bash
openclaw hooks install skills/guard-scanner/hooks/guard-scanner
openclaw hooks enable guard-scanner
openclaw hooks list
```

### 3. Recommended order

```bash
# Pre-install / pre-update gate first
npx guard-scanner ~/.openclaw/workspace/skills/ --verbose --self-exclude --html

# Then keep runtime monitoring enabled
openclaw hooks install skills/guard-scanner/hooks/guard-scanner
openclaw hooks enable guard-scanner
```

## Runtime Guard Modes

Set in `openclaw.json` → `plugins.guard-scanner.mode`:

| Mode | Behavior |
|------|----------|
| `monitor` | Log all, never block |
| `enforce` (default) | Block CRITICAL threats |
| `strict` | Block HIGH + CRITICAL |

## Threat Categories (23)

| # | Category | What It Detects |
|---|----------|----------------|
| 1 | Prompt Injection | Hidden instructions, invisible Unicode, homoglyphs |
| 2 | Malicious Code | eval(), child_process, reverse shells |
| 3 | Suspicious Downloads | curl\|bash, executable downloads |
| 4 | Credential Handling | .env reads, SSH key access |
| 5 | Secret Detection | Hardcoded API keys and tokens |
| 6 | Exfiltration | webhook.site, DNS tunneling |
| 7 | Unverifiable Deps | Remote dynamic imports |
| 8 | Financial Access | Crypto wallets, payment APIs |
| 9 | Obfuscation | Base64→eval, String.fromCharCode |
| 10 | Prerequisites Fraud | Fake download instructions |
| 11 | Leaky Skills | Secret leaks through LLM context |
| 12 | Memory Poisoning\* | Agent memory modification |
| 13 | Prompt Worm | Self-replicating instructions |
| 14 | Persistence | Cron jobs, startup execution |
| 15 | CVE Patterns | CVE-2026-25253, CVE-2026-25905, CVE-2026-27825 |
| 16 | MCP Security | Tool/schema poisoning, SSRF |
| 17 | Identity Hijacking\* | SOUL.md/IDENTITY.md tampering |
| 18 | Sandbox Validation | Dangerous binaries, broad file scope |
| 19 | Code Complexity | Excessive file length, deep nesting |
| 20 | Config Impact | openclaw.json writes, exec approval bypass |
| 21 | PII Exposure | CC/SSN, PII logging, Shadow AI |
| 22 | Trust Exploitation | Authority claims, creator impersonation |
| 23 | VDB Injection | Vector database poisoning, embedding manipulation |

\* = Requires `--soul-lock` flag

## External Endpoints

| URL | Data Sent | Purpose |
|-----|-----------|---------| 
| *(none)* | *(none)* | guard-scanner makes **zero** network requests. All scanning is local. |

## Security & Privacy

- **No network access**: guard-scanner never connects to external servers
- **Read-only scanning**: Only reads files, never modifies scanned directories
- **No telemetry**: No usage data, analytics, or crash reports are collected
- **Local reports only**: Output files (JSON/SARIF/HTML) are written to the scan directory
- **No environment variable access**: Does not read or process any secrets or API keys
- **Runtime Guard audit log**: Detections logged locally to `~/.openclaw/guard-scanner/audit.jsonl`

## Model Invocation Note

guard-scanner **does not invoke any LLM or AI model**. All detection is performed
through static pattern matching, regex analysis, Shannon entropy calculation,
and data flow analysis — entirely deterministic, no model calls.

## Trust Statement

guard-scanner was created by Guava 🍈 & Dee after experiencing a real 3-day
identity hijack incident in February 2026. A malicious skill silently replaced
an AI agent's SOUL.md personality file, and no existing tool could detect it.

- **Open source**: https://github.com/koatora20/guard-scanner
- **Zero dependencies**: Nothing to audit, no transitive risks
- **Test suite**: 139 tests across 24 suites, 100% pass rate
- **Taxonomy**: Based on Snyk ToxicSkills (Feb 2026), OWASP MCP Top 10, and original research
- **OWASP**: ASI01–ASI10 coverage 90% (9/10 verified)
- **CVE coverage**: CVE-2026-2256, CVE-2026-25046, CVE-2026-25253, CVE-2026-25905, CVE-2026-27825

## License

MIT — [LICENSE](LICENSE)
