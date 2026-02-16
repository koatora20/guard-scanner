# Changelog

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
