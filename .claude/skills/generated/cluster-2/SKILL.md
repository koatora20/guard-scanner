---
name: cluster-2
description: "Skill for the Cluster_2 area of workspace-guard-scanner. 19 symbols across 1 files."
---

# Cluster_2

19 symbols | 1 files | Cohesion: 92%

## When to Use

- Working with code in `src/`
- Understanding how scanSkill, scanTarget, classifyFile work
- Modifying cluster_2-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/scanner.ts` | scanSkill, scanTarget, classifyFile, checkIoCs, checkPatterns (+14) |

## Entry Points

Start here when exploring this area:

- **`scanSkill`** (Method) — `src/scanner.ts:238`
- **`scanTarget`** (Method) — `src/scanner.ts:242`
- **`classifyFile`** (Method) — `src/scanner.ts:510`
- **`checkIoCs`** (Method) — `src/scanner.ts:519`
- **`checkPatterns`** (Method) — `src/scanner.ts:550`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `scanSkill` | Method | `src/scanner.ts` | 238 |
| `scanTarget` | Method | `src/scanner.ts` | 242 |
| `classifyFile` | Method | `src/scanner.ts` | 510 |
| `checkIoCs` | Method | `src/scanner.ts` | 519 |
| `checkPatterns` | Method | `src/scanner.ts` | 550 |
| `checkSignatures` | Method | `src/scanner.ts` | 582 |
| `checkCompactionPersistence` | Method | `src/scanner.ts` | 634 |
| `checkHardcodedSecrets` | Method | `src/scanner.ts` | 680 |
| `shannonEntropy` | Method | `src/scanner.ts` | 706 |
| `checkStructure` | Method | `src/scanner.ts` | 718 |
| `checkDependencies` | Method | `src/scanner.ts` | 737 |
| `checkSkillManifest` | Method | `src/scanner.ts` | 776 |
| `checkComplexity` | Method | `src/scanner.ts` | 829 |
| `checkConfigImpact` | Method | `src/scanner.ts` | 869 |
| `checkHiddenFiles` | Method | `src/scanner.ts` | 906 |
| `checkJSDataFlow` | Method | `src/scanner.ts` | 926 |
| `checkCrossFile` | Method | `src/scanner.ts` | 980 |
| `isBenignBase64Fragment` | Method | `src/scanner.ts` | 1095 |
| `getVerdict` | Method | `src/scanner.ts` | 1164 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `HandleMcpRequest → ClassifyFile` | cross_community | 5 |
| `HandleMcpRequest → CheckIoCs` | cross_community | 5 |
| `HandleMcpRequest → CheckSignatures` | cross_community | 5 |
| `HandleMcpRequest → CheckPatterns` | cross_community | 5 |
| `RunSample → ClassifyFile` | cross_community | 4 |
| `RunSample → CheckIoCs` | cross_community | 4 |
| `RunSample → CheckSignatures` | cross_community | 4 |
| `RunSample → CheckPatterns` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_3 | 1 calls |
| Scripts | 1 calls |

## How to Explore

1. `gitnexus_context({name: "scanSkill"})` — see callers and callees
2. `gitnexus_query({query: "cluster_2"})` — find related execution flows
3. Read key files listed above for implementation details
