---
name: cluster-8
description: "Skill for the Cluster_8 area of workspace-guard-scanner. 3 symbols across 1 files."
---

# Cluster_8

3 symbols | 1 files | Cohesion: 100%

## When to Use

- Working with code in `src/`
- Understanding how collectStringValues, normalizeForMatch, toolTouchesProtectedPath work
- Modifying cluster_8-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/runtime-plugin.ts` | collectStringValues, normalizeForMatch, toolTouchesProtectedPath |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `collectStringValues` | Function | `src/runtime-plugin.ts` | 193 |
| `normalizeForMatch` | Function | `src/runtime-plugin.ts` | 213 |
| `toolTouchesProtectedPath` | Function | `src/runtime-plugin.ts` | 217 |

## How to Explore

1. `gitnexus_context({name: "collectStringValues"})` — see callers and callees
2. `gitnexus_query({query: "cluster_8"})` — find related execution flows
3. Read key files listed above for implementation details
