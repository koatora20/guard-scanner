---
name: cluster-16
description: "Skill for the Cluster_16 area of workspace-guard-scanner. 4 symbols across 1 files."
---

# Cluster_16

4 symbols | 1 files | Cohesion: 89%

## When to Use

- Working with code in `src/`
- Understanding how resolveAuditDir, resolveAuditFile, ensureAuditDir work
- Modifying cluster_16-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/runtime-plugin.ts` | resolveAuditDir, resolveAuditFile, ensureAuditDir, logAudit |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `resolveAuditDir` | Function | `src/runtime-plugin.ts` | 371 |
| `resolveAuditFile` | Function | `src/runtime-plugin.ts` | 375 |
| `ensureAuditDir` | Function | `src/runtime-plugin.ts` | 379 |
| `logAudit` | Function | `src/runtime-plugin.ts` | 387 |

## How to Explore

1. `gitnexus_context({name: "resolveAuditDir"})` — see callers and callees
2. `gitnexus_query({query: "cluster_16"})` — find related execution flows
3. Read key files listed above for implementation details
