---
name: guard-scanner
description: "Security policy and analysis layer for AI agents. 352 static patterns (32 categories) + 28 runtime checks (5 layers) + npm/GitHub/ClawHub asset audit + VirusTotal integration + real-time file watch. Lightweight (1 runtime dependency: ws), 0.016ms/scan."
metadata:
  clawdbot:
    homepage: "https://github.com/koatora20/guard-scanner"
requires:
  env:
    VT_API_KEY: "Optional. VirusTotal API key for --vt-scan (free at virustotal.com)"
files:
  - "dist/*"
  - "src/*"
  - "hooks/*"
  - "openclaw.plugin.json"
---

# guard-scanner 🛡️

352 static patterns + 28 runtime checks (5 layers), 32 threat categories + asset audit + VirusTotal + real-time watch. Lightweight (1 runtime dependency: `ws`), MIT licensed.

## When To Use

- Before installing a new skill / After updating skills / In CI/CD pipelines
- Auditing npm/GitHub/ClawHub for leaked credentials
- Real-time monitoring during development

## Quick Start

```bash
# Scan all skills
npx guard-scanner ~/.openclaw/workspace/skills/ --verbose --self-exclude

# Asset Audit (check npm/GitHub for leaks)
guard-scanner audit npm <your-npm-username> --verbose
guard-scanner audit github <your-github-username> --format json
guard-scanner audit all <username>

# VirusTotal Double-Layered Defense (optional, free)
VT_API_KEY=your-key guard-scanner scan ./skills/ --vt-scan

# Real-time Watch Mode
guard-scanner watch ./skills/ --strict --verbose

# CI/CD pipeline
guard-scanner ./skills/ --format sarif --quiet | upload-sarif
```

## VirusTotal Integration

guard-scanner combines its own 352 semantic patterns with VirusTotal's 70+ antivirus engines for **Double-Layered Defense**:

| Layer | Engine | Focus |
|---|---|---|
| Semantic | guard-scanner | Prompt injection, memory poisoning, supply chain |
| Signature | VirusTotal | Known malware, trojans, C2 infrastructure |

```bash
# Get your free API key at https://www.virustotal.com
# Set it as environment variable
export VT_API_KEY=your-api-key-here

# Use with any command
guard-scanner scan ./skills/ --vt-scan
guard-scanner audit npm koatora20 --vt-scan
```

Free tier: 4 req/min, 500/day, 15,500/month. VT is **optional** — guard-scanner works fully without it.

## Runtime Modes

| Mode | Behavior |
|------|----------|
| `monitor` | Log all, never block |
| `enforce` (default) | Block CRITICAL |
| `strict` | Block HIGH + CRITICAL |

## 32 Threat Categories

Prompt Injection, Malicious Code, Suspicious Downloads, Credential Handling, Secret Detection, Exfiltration, Unverifiable Deps, Financial Access, Obfuscation, Prerequisites Fraud, Leaky Skills, Memory Poisoning\*, Prompt Worm, Persistence, CVE Patterns, MCP Security, Identity Hijacking\*, Sandbox Validation, Code Complexity, Config Impact, PII Exposure, Trust Exploitation, VDB Injection, A2A Contagion, Data Exposure, Sandbox Escape, Agent Protocol, Supply Chain V2, Model Poisoning, Inference Manipulation, Autonomous Risk, API Abuse.

\* = Requires `--soul-lock` flag

## Security & Privacy

No network requests (unless `--vt-scan`). Read-only scanning. No telemetry. No env access. Deterministic. Your VT API key stays local.

## Trust

Open source, lightweight (1 runtime dependency `ws` for MCP server), **539 tests / 8 suites** 100% pass. OWASP LLM Top 10 + Agentic Security Top 10 coverage.

MIT — [LICENSE](LICENSE)
