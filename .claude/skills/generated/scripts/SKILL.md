---
name: scripts
description: "Skill for the Scripts area of workspace-guard-scanner. 27 symbols across 7 files."
---

# Scripts

27 symbols | 7 files | Cohesion: 87%

## When to Use

- Working with code in `scripts/`
- Understanding how handleMcpRequest, scoreWithRust, calculateRisk work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/benchmark.ts` | round, runSample, parseArgs, nearestPercentile, summarize (+2) |
| `scripts/oss-release-report.ts` | loadJson, makeResult, writeJson, buildReports, renderMarkdown (+1) |
| `src/mcp.ts` | jsonRpcResult, jsonRpcError, handleMcpRequest |
| `src/scanner.ts` | calculateRisk, scoreFindings, printSummary |
| `scripts/release-gate.ts` | loadJson, smokeInstall, main |
| `scripts/audit-baseline.ts` | readJson, summarizeText, main |
| `src/rust-bridge.ts` | candidateBinaryPaths, scoreWithRust |

## Entry Points

Start here when exploring this area:

- **`handleMcpRequest`** (Function) — `src/mcp.ts:43`
- **`scoreWithRust`** (Function) — `src/rust-bridge.ts:26`
- **`calculateRisk`** (Method) — `src/scanner.ts:1104`
- **`scoreFindings`** (Method) — `src/scanner.ts:1156`
- **`printSummary`** (Method) — `src/scanner.ts:1200`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `handleMcpRequest` | Function | `src/mcp.ts` | 43 |
| `scoreWithRust` | Function | `src/rust-bridge.ts` | 26 |
| `calculateRisk` | Method | `src/scanner.ts` | 1104 |
| `scoreFindings` | Method | `src/scanner.ts` | 1156 |
| `printSummary` | Method | `src/scanner.ts` | 1200 |
| `jsonRpcResult` | Function | `src/mcp.ts` | 35 |
| `jsonRpcError` | Function | `src/mcp.ts` | 39 |
| `loadJson` | Function | `scripts/oss-release-report.ts` | 48 |
| `makeResult` | Function | `scripts/oss-release-report.ts` | 52 |
| `writeJson` | Function | `scripts/oss-release-report.ts` | 62 |
| `buildReports` | Function | `scripts/oss-release-report.ts` | 67 |
| `renderMarkdown` | Function | `scripts/oss-release-report.ts` | 221 |
| `main` | Function | `scripts/oss-release-report.ts` | 313 |
| `candidateBinaryPaths` | Function | `src/rust-bridge.ts` | 14 |
| `round` | Function | `scripts/benchmark.ts` | 8 |
| `runSample` | Function | `scripts/benchmark.ts` | 81 |
| `parseArgs` | Function | `scripts/benchmark.ts` | 12 |
| `nearestPercentile` | Function | `scripts/benchmark.ts` | 34 |
| `summarize` | Function | `scripts/benchmark.ts` | 41 |
| `aggregateByWarmth` | Function | `scripts/benchmark.ts` | 70 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `HandleMcpRequest → IsSkillDir` | cross_community | 5 |
| `HandleMcpRequest → SafeReadDirs` | cross_community | 5 |
| `HandleMcpRequest → LooksLikeRepo` | cross_community | 5 |
| `HandleMcpRequest → ClassifyFile` | cross_community | 5 |
| `HandleMcpRequest → CheckIoCs` | cross_community | 5 |
| `HandleMcpRequest → CheckSignatures` | cross_community | 5 |
| `HandleMcpRequest → CheckPatterns` | cross_community | 5 |
| `HandleMcpRequest → Round` | cross_community | 5 |
| `RunSample → IsSkillDir` | cross_community | 4 |
| `RunSample → SafeReadDirs` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Test | 3 calls |

## How to Explore

1. `gitnexus_context({name: "handleMcpRequest"})` — see callers and callees
2. `gitnexus_query({query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
