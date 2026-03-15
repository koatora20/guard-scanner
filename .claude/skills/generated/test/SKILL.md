---
name: test
description: "Skill for the Test area of workspace-guard-scanner. 18 symbols across 5 files."
---

# Test

18 symbols | 5 files | Cohesion: 83%

## When to Use

- Working with code in `src/`
- Understanding how buildAuditEntry, runtimeGuardPlugin, runMcpScan work
- Modifying test-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `src/runtime-plugin.ts` | resolveConstitutionPath, loadConstitutionPolicy, serializeParams, makeCorrelationId, shouldBlock (+2) |
| `test/plugin.test.ts` | on, shouldBlock, simulatePluginHandler, collectStringValues, toolTouchesProtectedPath |
| `src/scanner.ts` | GuardScanner, loadIgnoreFile, scanDirectory, toJSON |
| `src/mcp.ts` | runMcpScan |
| `test/scanner.test.ts` | scanFixture |

## Entry Points

Start here when exploring this area:

- **`buildAuditEntry`** (Function) — `src/runtime-plugin.ts:509`
- **`runtimeGuardPlugin`** (Function) — `src/runtime-plugin.ts:535`
- **`runMcpScan`** (Function) — `src/mcp.ts:19`
- **`GuardScanner`** (Class) — `src/scanner.ts:78`
- **`loadIgnoreFile`** (Method) — `src/scanner.ts:175`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `GuardScanner` | Class | `src/scanner.ts` | 78 |
| `buildAuditEntry` | Function | `src/runtime-plugin.ts` | 509 |
| `runtimeGuardPlugin` | Function | `src/runtime-plugin.ts` | 535 |
| `runMcpScan` | Function | `src/mcp.ts` | 19 |
| `loadIgnoreFile` | Method | `src/scanner.ts` | 175 |
| `scanDirectory` | Method | `src/scanner.ts` | 201 |
| `toJSON` | Method | `src/scanner.ts` | 1223 |
| `resolveConstitutionPath` | Function | `src/runtime-plugin.ts` | 176 |
| `loadConstitutionPolicy` | Function | `src/runtime-plugin.ts` | 182 |
| `serializeParams` | Function | `src/runtime-plugin.ts` | 209 |
| `makeCorrelationId` | Function | `src/runtime-plugin.ts` | 481 |
| `shouldBlock` | Function | `src/runtime-plugin.ts` | 502 |
| `scanFixture` | Function | `test/scanner.test.ts` | 13 |
| `shouldBlock` | Function | `test/plugin.test.ts` | 140 |
| `simulatePluginHandler` | Function | `test/plugin.test.ts` | 291 |
| `collectStringValues` | Function | `test/plugin.test.ts` | 147 |
| `toolTouchesProtectedPath` | Function | `test/plugin.test.ts` | 161 |
| `on` | Method | `test/plugin.test.ts` | 20 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `RuntimeGuardPlugin → ResolveSuiteTokenPath` | cross_community | 5 |
| `HandleMcpRequest → IsSkillDir` | cross_community | 5 |
| `HandleMcpRequest → SafeReadDirs` | cross_community | 5 |
| `HandleMcpRequest → LooksLikeRepo` | cross_community | 5 |
| `HandleMcpRequest → ClassifyFile` | cross_community | 5 |
| `HandleMcpRequest → CheckIoCs` | cross_community | 5 |
| `HandleMcpRequest → CheckSignatures` | cross_community | 5 |
| `HandleMcpRequest → CheckPatterns` | cross_community | 5 |
| `HandleMcpRequest → Round` | cross_community | 5 |
| `RuntimeGuardPlugin → ResolveConfigPath` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_4 | 1 calls |
| Cluster_2 | 1 calls |
| Scripts | 1 calls |
| Cluster_17 | 1 calls |
| Cluster_16 | 1 calls |

## How to Explore

1. `gitnexus_context({name: "buildAuditEntry"})` — see callers and callees
2. `gitnexus_query({query: "test"})` — find related execution flows
3. Read key files listed above for implementation details
