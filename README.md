# guard-scanner 🛡️

*The Original, Zero-Dependency Shield for the AI Agent Era.*

As autonomous AI agents become more prevalent, the risk of executing untrusted or malicious skills increases. **guard-scanner** is an open-source, zero-dependency security platform designed to protect developers from Prompt Injections, RCEs, Memory Poisoning, and supply chain attacks.

Built by the **[Guava Parity Institute](https://github.com/koatora20)** and the open-source community.

**166 static patterns + 26 runtime checks + asset audit + VirusTotal integration + real-time watch.**

[![npm](https://img.shields.io/npm/v/@guava-parity/guard-scanner)](https://www.npmjs.com/package/@guava-parity/guard-scanner)
[![license](https://img.shields.io/npm/l/guard-scanner)](LICENSE)
[![tests](https://img.shields.io/badge/tests-206%2F206-brightgreen)](#test-results)

## Install

```bash
npm install -g @guava-parity/guard-scanner
```

## Quick Start

```bash
# Scan all skills
guard-scanner ./skills/ --verbose

# Strict mode + reports
guard-scanner ./skills/ --strict --json --sarif --fail-on-findings

# CI/CD pipeline (stdout)
guard-scanner ./skills/ --format sarif --quiet | upload-sarif
```

## 🔍 Example Scan Output

```console
$ guard-scanner ./test/fixtures/malicious-skill/ --verbose

🛡️  guard-scanner v8.0.0
══════════════════════════════════════════════════════
📂 Scanning: ./test/fixtures/malicious-skill/
📦 Skills found: 1

🔴 scripts — MALICIOUS (risk: 100)
   📁 exfiltration
      🔴 [HIGH] Suspicious domain: webhook.site — evil.js
   📁 malicious-code
      🔴 [HIGH] eval() call — evil.js:18
      💀 [CRITICAL] Shell download/execution — stealer.js:19
   📁 credential-handling
      🔴 [HIGH] Credential file read — evil.js:6
      💀 [CRITICAL] Agent identity file read — evil.js:7
   📁 memory-poisoning
      💀 [CRITICAL] Write to agent soul file — evil.js:21
```

## 🔎 Asset Audit (V6+)

Audit your npm packages, GitHub repos, and ClawHub skills for leaked credentials and security exposure.

```bash
# npm — detect leaked node_modules, .env files, scope duplicates
guard-scanner audit npm <username> --verbose

# GitHub — detect committed secrets, large repos, .env/.key files
guard-scanner audit github <username> --format json

# ClawHub — detect malicious skills, suspicious DL/star ratios
guard-scanner audit clawhub <query>

# All providers at once
guard-scanner audit all <username> --verbose
```

## 🦠 VirusTotal Integration (V7+)

Combine guard-scanner's semantic detection with VirusTotal's 70+ antivirus engines for **Double-Layered Defense**.

| Layer | Engine | Focus |
|---|---|---|
| **Semantic** | guard-scanner | Prompt injection, memory poisoning, supply chain |
| **Signature** | VirusTotal | Known malware, trojans, C2 infrastructure |

```bash
# 1. Get free API key at https://www.virustotal.com (¥0)
# 2. Set environment variable
export VT_API_KEY=your-api-key-here

# 3. Use with any command
guard-scanner scan ./skills/ --vt-scan
guard-scanner audit npm koatora20 --vt-scan
```

> **Free tier**: 4 req/min, 500/day, 15,500/month. Personal use only.  
> **VT is optional** — guard-scanner works fully without it.

## 👁️ Real-time Watch Mode (V8+)

Monitor your skills directory for changes and scan automatically.

```bash
# Start watching
guard-scanner watch ./skills/ --strict --verbose

# With Soul Lock protection
guard-scanner watch ./skills/ --strict --soul-lock
```

Press `Ctrl+C` for session stats.

## 📊 CI/CD Integration (V8+)

Native support for CI/CD pipelines via `CIReporter`:

| Platform | Format |
|---|---|
| GitHub Actions | `::error` / `::warning` annotations + Step Summary |
| GitLab | Code Quality JSON report |
| Any | Webhook notification (HTTPS POST) |

```bash
# GitHub Actions
guard-scanner ./skills/ --format sarif --quiet > report.sarif

# GitLab
guard-scanner ./skills/ --format json --quiet > gl-code-quality-report.json
```

## Options

| Flag | Description |
|------|-------------|
| `--verbose`, `-v` | Detailed findings with categories and samples |
| `--strict` | Lower detection thresholds (more sensitive) |
| `--check-deps` | Scan `package.json` for dependency chain risks |
| `--soul-lock` | Enable agent identity protection |
| `--vt-scan` | Enable VirusTotal hash/URL/domain lookup |
| `--json` | Write JSON report to file |
| `--sarif` | Write SARIF 2.1.0 report |
| `--html` | Write HTML dashboard report |
| `--format json\|sarif` | Print to stdout (pipeable) |
| `--quiet` | Suppress text output |
| `--self-exclude` | Skip scanning guard-scanner itself |
| `--summary-only` | Only print the summary table |
| `--rules <file>` | Load custom detection rules (JSON) |
| `--plugin <file>` | Load plugin module |
| `--fail-on-findings` | Exit code 1 if any findings (CI/CD) |

## Threat Categories (23)

| # | Category | Detects |
|---|----------|---------| 
| 1 | Prompt Injection | Hidden instructions, invisible Unicode, homoglyphs |
| 2 | Malicious Code | `eval()`, `child_process`, reverse shells |
| 3 | Suspicious Downloads | `curl\|bash`, executable downloads |
| 4 | Credential Handling | `.env` reads, SSH keys |
| 5 | Secret Detection | Hardcoded API keys, Shannon entropy |
| 6 | Exfiltration | webhook.site, DNS tunneling |
| 7 | Unverifiable Deps | Remote dynamic imports |
| 8 | Financial Access | Crypto transactions |
| 9 | Obfuscation | Base64→exec, hex encoding |
| 10 | Prerequisites Fraud | Fake download instructions |
| 11 | Leaky Skills | Secrets in memory |
| 12 | Memory Poisoning ⚿ | SOUL.md modification |
| 13 | Prompt Worm | Self-replicating prompts |
| 14 | Persistence | Cron, launchd |
| 15 | CVE Patterns | CVE-2026-2256/25046/25253/25905/27825 |
| 16 | MCP Security | Tool poisoning, SSRF, shadow servers |
| 17 | Identity Hijacking ⚿ | Persona swap, memory wipe |
| 18 | Config Impact | OpenClaw config writes |
| 19 | PII Exposure | CC/SSN, Shadow AI calls |
| 20 | Trust Exploitation | Authority claims, fake audits |
| 21 | VDB Injection | Vector DB poisoning |

> ⚿ = Requires `--soul-lock` flag (opt-in)

## Runtime Guard (26 checks, 5 layers)

Real-time `before_tool_call` hook that blocks dangerous operations.

| Layer | Name | Checks |
|-------|------|--------|
| 1 | Threat Detection | Reverse shell, curl\|bash, SSRF |
| 2 | Trust Defense | SOUL.md tampering, memory injection |
| 3 | Safety Judge | Prompt injection in tool args |
| 4 | Behavioral | No-research execution |
| 5 | Trust Exploitation | Authority claim, creator bypass |

## Test Results

```
ℹ tests 206
ℹ suites 43
ℹ pass 206
ℹ fail 0
ℹ duration_ms 376
```

| Suite | Tests |
|-------|-------|
| Malicious Skill Detection | 16 ✅ |
| Clean Skill (False Positive) | 2 ✅ |
| Risk Score / Verdict | 10 ✅ |
| Output Formats (JSON/SARIF/HTML) | 4 ✅ |
| Pattern DB (166 patterns, 23 cats) | 4 ✅ |
| IoC Database | 5 ✅ |
| Shannon Entropy | 2 ✅ |
| Plugin API / Custom Rules | 2 ✅ |
| Skill Manifest | 4 ✅ |
| Code Complexity | 2 ✅ |
| Config / PII / OWASP | 26 ✅ |
| Runtime Guard (5 layers) | 25 ✅ |
| CVE Detection | 5 ✅ |
| **Asset Audit (npm/GitHub/ClawHub)** | **32 ✅** |
| **VirusTotal Integration** | **20 ✅** |
| **Watcher + CI/CD** | **15 ✅** |

## Plugin API

```javascript
module.exports = {
  name: 'my-plugin',
  patterns: [
    { id: 'MY_01', cat: 'custom', regex: /pattern/g, severity: 'HIGH', desc: 'Description', all: true }
  ]
};
```

```bash
guard-scanner ./skills/ --plugin ./my-plugin.js
```

## Contributing

We welcome contributions! Whether fixing bugs, adding threat patterns, or improving docs.

## License

MIT — [Guava Parity Institute](https://github.com/koatora20/guard-scanner)
