# Changelog

## [1.1.0] - 2026-02-17

### 🆕 New Features — Issue #18677 Feedback

#### Skill Manifest Validation (`sandbox-validation` category)
- **Dangerous binary detection**: Flags SKILL.md `requires.bins` entries like `sudo`, `rm`, `curl`, `ssh` (23 tool blocklist)
- **Overly broad file scope**: Detects `files: ["**/*"]` and similar wildcard patterns in manifest
- **Sensitive env var requirements**: Flags SECRET, PASSWORD, PRIVATE_KEY, AWS_SECRET etc. in `requires.env`
- **Exec/network capability declaration**: Warns when skills declare unrestricted exec/network access

#### Code Complexity Metrics (`complexity` category)
- **File length check**: Flags code files exceeding 1000 lines
- **Deep nesting detection**: Detects nesting depth > 5 levels via brace tracking
- **eval/exec density**: Flags high concentration of eval/exec calls (> 2% of lines, minimum 3 calls)

#### Config Impact Analysis (`config-impact` category)
- **openclaw.json write detection**: Detects code that directly writes to OpenClaw configuration
- **Exec approval bypass**: Flags `exec.approvals = "off"` and similar patterns
- **Exec host gateway**: Detects `tools.exec.host = "gateway"` (sandbox bypass)
- **Internal hooks modification**: Flags changes to `hooks.internal.entries`
- **Network wildcard**: Detects `network.allowedDomains = "*"` patterns

### Enhanced
- **6 new patterns** in `config-impact` category for pattern-based detection
- **Risk scoring**: Added multipliers for `config-impact` (x2), `sandbox-validation` combo (min 70), `complexity` + malicious-code combo (x1.5)
- **Recommendations**: Added sandbox, complexity, and config-impact recommendations to JSON output
- **Categories**: 17 → 20 categories, 170+ → 186 patterns

### Testing
- **11 new test cases** across 3 new test sections (Manifest Validation, Complexity, Config Impact)
- **3 new test fixtures**: `dangerous-manifest/`, `complex-skill/`, `config-changer/`
- Total: 56 tests across 13 sections

---

## [1.0.0] - 2026-02-17

### 🎉 Initial Release

Extracted from GuavaGuard v9.0.0 as the open-source component.

### Features
- **17 threat categories** based on Snyk ToxicSkills taxonomy + OWASP MCP Top 10
- **170+ detection patterns** covering prompt injection, malicious code, credential leaks, exfiltration, obfuscation, memory poisoning, identity hijacking, and more
- **IoC database** with known malicious IPs, domains, URLs, usernames, and typosquat skill names
- **Multiple output formats**: Text, JSON, SARIF, HTML
- **Entropy-based secret detection** (Shannon entropy analysis)
- **Lightweight JS data flow analysis** (secret read → network/exec chain detection)
- **Cross-file analysis** (phantom refs, base64 fragment assembly, load+exec chains)
- **Dependency chain scanning** (risky packages, lifecycle scripts, pinned versions)
- **Plugin API** for custom detection rules
- **Custom rules** via JSON file
- **Ignore files** (`.guard-scanner-ignore` / `.guava-guard-ignore`)
- **Zero dependencies** — runs on Node.js 18+, nothing else

### Architecture
- `src/scanner.js` — Core scanner engine (GuardScanner class)
- `src/patterns.js` — Threat pattern database
- `src/ioc-db.js` — Indicators of Compromise
- `src/cli.js` — CLI entry point

### What's NOT included (Private — GuavaSuite)
- Soul Lock integrity verification
- SoulChain on-chain verification
- Hash-based identity file watchdog
- Polygon blockchain integration
