---
name: cluster-17
description: "Skill for the Cluster_17 area of workspace-guard-scanner. 8 symbols across 1 files."
---

# Cluster_17

8 symbols | 1 files | Cohesion: 95%

## When to Use

- Working with code in `src/`
- Understanding how computeRuntimeGuardState work
- Modifying cluster_17-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/runtime-plugin.ts` | resolveSuiteTokenPath, resolveConfigPath, isSuiteActive, loadMode, loadCoexistenceMode (+3) |

## Entry Points

Start here when exploring this area:

- **`computeRuntimeGuardState`** (Function) — `src/runtime-plugin.ts:486`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `computeRuntimeGuardState` | Function | `src/runtime-plugin.ts` | 486 |
| `resolveSuiteTokenPath` | Function | `src/runtime-plugin.ts` | 398 |
| `resolveConfigPath` | Function | `src/runtime-plugin.ts` | 402 |
| `isSuiteActive` | Function | `src/runtime-plugin.ts` | 406 |
| `loadMode` | Function | `src/runtime-plugin.ts` | 422 |
| `loadCoexistenceMode` | Function | `src/runtime-plugin.ts` | 439 |
| `loadSyncMode` | Function | `src/runtime-plugin.ts` | 453 |
| `loadSharedRunIdEnabled` | Function | `src/runtime-plugin.ts` | 467 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `RuntimeGuardPlugin → ResolveSuiteTokenPath` | cross_community | 5 |
| `RuntimeGuardPlugin → ResolveConfigPath` | cross_community | 4 |

## How to Explore

1. `gitnexus_context({name: "computeRuntimeGuardState"})` — see callers and callees
2. `gitnexus_query({query: "cluster_17"})` — find related execution flows
3. Read key files listed above for implementation details
