---
name: cluster-4
description: "Skill for the Cluster_4 area of workspace-guard-scanner. 4 symbols across 1 files."
---

# Cluster_4

4 symbols | 1 files | Cohesion: 86%

## When to Use

- Working with code in `src/`
- Understanding how resolveTargets, safeReadDirs, isSkillDir work
- Modifying cluster_4-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/scanner.ts` | resolveTargets, safeReadDirs, isSkillDir, looksLikeRepo |

## Entry Points

Start here when exploring this area:

- **`resolveTargets`** (Method) — `src/scanner.ts:431`
- **`safeReadDirs`** (Method) — `src/scanner.ts:482`
- **`isSkillDir`** (Method) — `src/scanner.ts:492`
- **`looksLikeRepo`** (Method) — `src/scanner.ts:496`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `resolveTargets` | Method | `src/scanner.ts` | 431 |
| `safeReadDirs` | Method | `src/scanner.ts` | 482 |
| `isSkillDir` | Method | `src/scanner.ts` | 492 |
| `looksLikeRepo` | Method | `src/scanner.ts` | 496 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `HandleMcpRequest → IsSkillDir` | cross_community | 5 |
| `HandleMcpRequest → SafeReadDirs` | cross_community | 5 |
| `HandleMcpRequest → LooksLikeRepo` | cross_community | 5 |
| `RunSample → IsSkillDir` | cross_community | 4 |
| `RunSample → SafeReadDirs` | cross_community | 4 |
| `RunSample → LooksLikeRepo` | cross_community | 4 |

## How to Explore

1. `gitnexus_context({name: "resolveTargets"})` — see callers and callees
2. `gitnexus_query({query: "cluster_4"})` — find related execution flows
3. Read key files listed above for implementation details
