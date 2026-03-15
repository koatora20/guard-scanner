---
name: cluster-3
description: "Skill for the Cluster_3 area of workspace-guard-scanner. 10 symbols across 1 files."
---

# Cluster_3

10 symbols | 1 files | Cohesion: 95%

## When to Use

- Working with code in `src/`
- Understanding how calibrateFinding, enrichFinding, getLineText work
- Modifying cluster_3-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/scanner.ts` | calibrateFinding, enrichFinding, getLineText, getLineWindow, isRepoMetadataEmailContext (+5) |

## Entry Points

Start here when exploring this area:

- **`calibrateFinding`** (Method) — `src/scanner.ts:348`
- **`enrichFinding`** (Method) — `src/scanner.ts:406`
- **`getLineText`** (Method) — `src/scanner.ts:1026`
- **`getLineWindow`** (Method) — `src/scanner.ts:1031`
- **`isRepoMetadataEmailContext`** (Method) — `src/scanner.ts:1040`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `calibrateFinding` | Method | `src/scanner.ts` | 348 |
| `enrichFinding` | Method | `src/scanner.ts` | 406 |
| `getLineText` | Method | `src/scanner.ts` | 1026 |
| `getLineWindow` | Method | `src/scanner.ts` | 1031 |
| `isRepoMetadataEmailContext` | Method | `src/scanner.ts` | 1040 |
| `isBenignPromptContext` | Method | `src/scanner.ts` | 1054 |
| `isPatternCatalogContext` | Method | `src/scanner.ts` | 1059 |
| `isFirstPartyEvidenceContext` | Method | `src/scanner.ts` | 1064 |
| `isSchemaFieldContext` | Method | `src/scanner.ts` | 1081 |
| `isBenignSecretContext` | Method | `src/scanner.ts` | 1086 |

## How to Explore

1. `gitnexus_context({name: "calibrateFinding"})` — see callers and callees
2. `gitnexus_query({query: "cluster_3"})` — find related execution flows
3. Read key files listed above for implementation details
