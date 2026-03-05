---
name: guard-scanner
description: "Security scanner for AI agent skills. 150 static patterns + 26 runtime checks across 23 threat categories. Zero dependencies, 0.016ms/scan."
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

# guard-scanner 🛡️

150 static patterns + 26 runtime checks (5 layers), 23 threat categories. Zero deps, MIT licensed, 0.016ms/scan.

## When To Use

- Before installing a new skill / After updating skills / Periodically / In CI/CD

## Quick Start

```bash
# Scan all skills
npx guard-scanner ~/.openclaw/workspace/skills/ --verbose --self-exclude

# Scan specific skill
npx guard-scanner /path/to/new-skill/ --strict --verbose

# Runtime Guard (OpenClaw Plugin Hook)
openclaw hooks install skills/guard-scanner/hooks/guard-scanner
openclaw hooks enable guard-scanner
```

## Runtime Modes

| Mode | Behavior |
|------|----------|
| `monitor` | Log all, never block |
| `enforce` (default) | Block CRITICAL |
| `strict` | Block HIGH + CRITICAL |

## 23 Threat Categories

Prompt Injection, Malicious Code, Suspicious Downloads, Credential Handling, Secret Detection, Exfiltration, Unverifiable Deps, Financial Access, Obfuscation, Prerequisites Fraud, Leaky Skills, Memory Poisoning*, Prompt Worm, Persistence, CVE Patterns (CVE-2026-2256/25046/25253/25905/27825), MCP Security, Identity Hijacking*, Sandbox Validation, Code Complexity, Config Impact, PII Exposure, Trust Exploitation, VDB Injection.

\* = Requires `--soul-lock` flag

## Security & Privacy

Zero network requests. Read-only scanning. No telemetry. No env access. Deterministic (no LLM calls).

## Trust

Open source, zero deps, 139 tests/24 suites 100% pass. Based on Snyk ToxicSkills, OWASP MCP Top 10. OWASP ASI01–10 90% coverage.

MIT — [LICENSE](LICENSE)
