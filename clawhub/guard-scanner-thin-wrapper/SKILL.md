---
name: guard-scanner
description: >
  Thin ClawHub wrapper for the canonical guard-scanner package. Use when an
  OpenClaw workspace needs a skill-shaped entry that points to the canonical
  package, plugin, and MCP contract without introducing a second authority surface.
homepage: https://github.com/koatora20/guard-scanner
metadata:
  clawdbot:
    emoji: "🛡️"
    category: security
    requires:
      bins:
        - node
      env: []
    files:
      - "SKILL.md"
      - "README.md"
    primaryEnv: null
    tags:
      - security
      - openclaw
      - clawhub
      - thin-wrapper
---

# guard-scanner thin wrapper

This ClawHub skill is a thin wrapper over the canonical `guard-scanner` package.

## Canonical Source

- canonical repo: `koatora20/guard-scanner`
- canonical package: `guard-scanner@17.0.0`
- canonical source of truth: `docs/spec/capabilities.json`
- tested OpenClaw baseline: `2026.3.13`

## What This Wrapper Does

- points users to the canonical package and plugin contract
- keeps ClawHub publication skill-shaped without inventing a second authority layer
- preserves `guard_scan_path` as the public MCP tool
- keeps `guava-anti-guard` as the authority owner

## What This Wrapper Does Not Do

- does not redefine package capabilities
- does not become an authority owner
- does not promote raw findings into durable memory
- does not store private memory or secret material

## Install / Use

```bash
npx guard-scanner ./skills --json --sarif --fail-on-findings
```

For runtime blocking, use the canonical plugin surface defined by `openclaw.plugin.json` in the canonical repo.
