---
name: guard-scanner
description: >
  Security scanner for AI agent skills. Use before installing or running a new skill
  from ClawHub or external sources. Detects prompt injection, credential theft,
  exfiltration, identity hijacking, sandbox violations, config impact, and runtime
  abuse patterns. Includes a hook-only OpenClaw plugin surface for runtime blocking.
homepage: https://github.com/koatora20/guard-scanner
metadata:
  clawdbot:
    emoji: "🛡️"
    category: security
    requires:
      bins:
        - node
      env: []
    files: ["dist/*", "openclaw.plugin.json", "docs/*"]
    primaryEnv: null
    tags:
      - security
      - scanner
      - threat-detection
      - supply-chain
      - prompt-injection
      - sarif
---

# guard-scanner 🛡️

Static + runtime security scanner for AI agent skills.
Source of truth: `docs/spec/capabilities.json`.

## When To Use This Skill

- Before installing a new skill from ClawHub or any external source
- After updating skills to check for newly introduced threats
- During CI/CD to gate agent package or skill promotion
- When you need runtime tool-call blocking through the OpenClaw plugin hook

## Quick Start

### 1. Static Scan

```bash
npx guard-scanner ~/.openclaw/workspace/skills --self-exclude --verbose
```

### 2. Runtime Guard

The public plugin surface is hook-only and uses `before_tool_call`.

```bash
openclaw plugins list
openclaw skills info guard-scanner
```

### 3. CI/CD Output

```bash
npx guard-scanner ./skills --json --sarif --fail-on-findings
```

## Runtime Guard Modes

| Mode | Intended Behavior | Status |
|------|-------------------|--------|
| `monitor` | Log all, never block | Supported |
| `enforce` | Block CRITICAL threats | Supported |
| `strict` | Block HIGH + CRITICAL threats | Supported |

## Threat Coverage

The public package covers the categories recorded in `docs/spec/capabilities.json`, including:

- prompt injection
- malicious code
- credential handling
- exfiltration
- memory poisoning
- identity hijacking
- config impact
- PII exposure

## Role Boundary

- `guard-scanner-refiner` improves signatures and coverage
- `guard-scanner-audit` interprets findings into bounded next actions
- `guava-anti-guard` remains the final authority

Raw low-signal scanner output must not be promoted directly into durable memory.

## Output Formats

```bash
# Terminal
npx guard-scanner ./skills

# JSON
npx guard-scanner ./skills --json

# SARIF
npx guard-scanner ./skills --sarif
```

## Security and Privacy

- no remote service is required for scanning
- reports are written locally
- the plugin surface is hook-only
- findings are deterministic and reproducible

## License

MIT — [LICENSE](LICENSE)
