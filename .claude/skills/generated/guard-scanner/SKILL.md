---
name: guard-scanner
description: "Skill for the Guard-scanner area of workspace-guard-scanner. 3 symbols across 1 files."
---

# Guard-scanner

3 symbols | 1 files | Cohesion: 100%

## When to Use

- Working with code in `hooks/`
- Understanding how ensureAuditDir, logAudit, handler work
- Modifying guard-scanner-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `hooks/guard-scanner/handler.ts` | ensureAuditDir, logAudit, handler |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `ensureAuditDir` | Function | `hooks/guard-scanner/handler.ts` | 128 |
| `logAudit` | Function | `hooks/guard-scanner/handler.ts` | 132 |
| `handler` | Function | `hooks/guard-scanner/handler.ts` | 139 |

## How to Explore

1. `gitnexus_context({name: "ensureAuditDir"})` — see callers and callees
2. `gitnexus_query({query: "guard-scanner"})` — find related execution flows
3. Read key files listed above for implementation details
