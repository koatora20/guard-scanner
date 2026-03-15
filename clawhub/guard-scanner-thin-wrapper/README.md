# guard-scanner ClawHub thin wrapper

This directory is the ClawHub-facing thin wrapper for the canonical `guard-scanner` package.

- It exists so ClawHub can publish a skill-shaped bundle built around `SKILL.md`.
- It must stay aligned with the canonical package and plugin contract.
- It must not introduce a second authority surface.
- Final authority remains `guava-anti-guard`.
