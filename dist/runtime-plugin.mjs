import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, normalize } from "node:path";
const RUNTIME_CHECKS = [
  {
    id: "RT_REVSHELL",
    severity: "CRITICAL",
    desc: "Reverse shell attempt",
    test: (s) => /\/dev\/tcp\/|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|socat\s+TCP/i.test(s)
  },
  {
    id: "RT_CRED_EXFIL",
    severity: "CRITICAL",
    desc: "Credential exfiltration to external",
    test: (s) => /(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io|socifiapp\.com)/i.test(s) && /(token|key|secret|password|credential|env)/i.test(s)
  },
  {
    id: "RT_GUARDRAIL_OFF",
    severity: "CRITICAL",
    desc: "Guardrail disabling attempt",
    test: (s) => /exec\.approvals?\s*[:=]\s*['"]?(off|false)|tools\.exec\.host\s*[:=]\s*['"]?gateway/i.test(s)
  },
  {
    id: "RT_GATEKEEPER",
    severity: "CRITICAL",
    desc: "macOS Gatekeeper bypass (xattr)",
    test: (s) => /xattr\s+-[crd]\s.*quarantine/i.test(s)
  },
  {
    id: "RT_AMOS",
    severity: "CRITICAL",
    desc: "ClawHavoc AMOS indicator",
    test: (s) => /socifiapp|Atomic\s*Stealer|AMOS/i.test(s)
  },
  {
    id: "RT_MAL_IP",
    severity: "CRITICAL",
    desc: "Known malicious IP",
    test: (s) => /91\.92\.242\.30/i.test(s)
  },
  {
    id: "RT_DNS_EXFIL",
    severity: "HIGH",
    desc: "DNS-based exfiltration",
    test: (s) => /nslookup\s+.*\$|dig\s+.*\$.*@/i.test(s)
  },
  {
    id: "RT_B64_SHELL",
    severity: "CRITICAL",
    desc: "Base64 decode piped to shell",
    test: (s) => /base64\s+(-[dD]|--decode)\s*\|\s*(sh|bash)/i.test(s)
  },
  {
    id: "RT_CURL_BASH",
    severity: "CRITICAL",
    desc: "Download piped to shell",
    test: (s) => /(curl|wget)\s+[^\n]*\|\s*(sh|bash|zsh)/i.test(s)
  },
  {
    id: "RT_SSH_READ",
    severity: "HIGH",
    desc: "SSH private key access",
    test: (s) => /\.ssh\/id_|\.ssh\/authorized_keys/i.test(s)
  },
  {
    id: "RT_WALLET",
    severity: "HIGH",
    desc: "Crypto wallet credential access",
    test: (s) => /wallet.*(?:seed|mnemonic|private.*key)|seed.*phrase/i.test(s)
  },
  {
    id: "RT_CLOUD_META",
    severity: "CRITICAL",
    desc: "Cloud metadata endpoint access",
    test: (s) => /169\.254\.169\.254|metadata\.google|metadata\.aws/i.test(s)
  }
];
const DANGEROUS_TOOLS = /* @__PURE__ */ new Set([
  "exec",
  "write",
  "edit",
  "browser",
  "web_fetch",
  "message",
  "shell",
  "run_command",
  "multi_edit"
]);
function resolveConstitutionPath(config) {
  if (!config?.constitutionPath) return null;
  if (isAbsolute(config.constitutionPath)) return config.constitutionPath;
  return join(process.cwd(), config.constitutionPath);
}
function loadConstitutionPolicy(config) {
  const policyPath = resolveConstitutionPath(config);
  if (!policyPath) return null;
  try {
    return JSON.parse(readFileSync(policyPath, "utf8"));
  } catch {
    return null;
  }
}
function collectStringValues(value, acc) {
  if (typeof value === "string") {
    acc.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStringValues(item, acc);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStringValues(item, acc);
  }
}
function serializeParams(params) {
  return JSON.stringify(params);
}
function normalizeForMatch(value) {
  return normalize(value).replace(/\\/g, "/");
}
function toolTouchesProtectedPath(event, policy, predicate) {
  if (!policy?.protected_assets?.length) return false;
  const values = [];
  collectStringValues(event.params, values);
  const normalizedValues = values.map(normalizeForMatch);
  return policy.protected_assets.filter(predicate).some((asset) => {
    const assetPath = normalizeForMatch(asset.path);
    return normalizedValues.some((value) => value.includes(assetPath));
  });
}
function hasUnapprovedHighRiskIntent(serialized) {
  const highRisk = /"risk_tier":"(?:high|critical)"/i.test(serialized);
  const unapproved = /"approval_state":"(?:pending|rejected|not_required)"/i.test(serialized);
  return highRisk && unapproved;
}
function hasUntrustedSkillEscalation(serialized) {
  const remotePayload = /(https?:\/\/|github\.com\/|npm install|pip install|clawhub install|mcp)/i.test(serialized);
  const escalation = /(skill|plugin|extension|tool|server|install|register|enable)/i.test(serialized);
  const notTrusted = !/"trusted":true/i.test(serialized) && !/"approval_state":"approved"/i.test(serialized);
  return remotePayload && escalation && notTrusted;
}
function hasMissingXrAuthority(serialized) {
  const controlMutation = /"target_plane":"(?:gateway|acpx|lobster|payment|embodiment|external_data)"/i.test(serialized);
  const missingOrigin = !/"origin":"xr_cockpit"/i.test(serialized);
  const missingSignature = !/"signature":"[^"]+"/i.test(serialized);
  const missingEpoch = !/"authority_epoch":\d+/i.test(serialized);
  return controlMutation && (missingOrigin || missingSignature || missingEpoch);
}
function hasLobsterBypass(serialized) {
  const irreversible = /(send|delete|post|publish|pair|payment)/i.test(serialized);
  const missingResume = !/"lobster_resume_token":"[^"]+"/i.test(serialized);
  return irreversible && missingResume;
}
function hasPaymentBypass(serialized) {
  const payable = /(x402|payment|quote_ref|payer_wallet_ref|tool_ref)/i.test(serialized);
  const missingQuote = !/"quote_ref":"[^"]+"/i.test(serialized);
  const missingCheckpoint = !/"approval_checkpoint_ref":"[^"]+"/i.test(serialized);
  const missingReceipt = !/"settlement_receipt_ref":"[^"]+"/i.test(serialized);
  return payable && (missingQuote || missingCheckpoint || missingReceipt);
}
function hasDirectEmbodimentHostCall(serialized) {
  const embodiment = /(peekaboo|axorcist|macos-automator-mcp|accessibility|gui automation)/i.test(serialized);
  const missingLane = !/"target_plane":"embodiment"/i.test(serialized) && !/"adapter_id":"[^"]+"/i.test(serialized);
  return embodiment && missingLane;
}
function hasHistoricalArchiveSkillInstall(serialized) {
  const archiveSource = /(historical archive|99_archive|archive\/.*skill|openclaw\/skills)/i.test(serialized);
  const installAttempt = /(clawhub install|install|enable|register)/i.test(serialized);
  const unapproved = !/"approval_state":"approved"/i.test(serialized);
  return archiveSource && installAttempt && unapproved;
}
const CONSTITUTION_CHECKS = [
  {
    id: "GPI_IDENTITY_REWRITE",
    severity: "CRITICAL",
    desc: "Identity rewrite attempt against protected assets",
    test: (event, _ctx, policy) => ["write", "edit", "multi_edit", "exec", "shell", "run_command"].includes(event.toolName) && toolTouchesProtectedPath(
      event,
      policy,
      (asset) => asset.write_requires_approval !== false && (asset.path.endsWith("/SOUL.md") || asset.path.endsWith("/IDENTITY.md"))
    )
  },
  {
    id: "GPI_MEMORY_POISONING",
    severity: "CRITICAL",
    desc: "Memory poisoning attempt against protected writeback paths",
    test: (event, _ctx, policy) => ["write", "edit", "multi_edit", "exec", "shell", "run_command"].includes(event.toolName) && toolTouchesProtectedPath(event, policy, (asset) => asset.path.includes("/memory/") || asset.path.endsWith("/memory"))
  },
  {
    id: "GPI_POLICY_BYPASS",
    severity: "CRITICAL",
    desc: "Policy bypass attempt against constitution or approval settings",
    test: (event, _ctx, policy) => {
      const serialized = serializeParams(event.params);
      return ["write", "edit", "multi_edit", "exec", "shell", "run_command"].includes(event.toolName) && (toolTouchesProtectedPath(event, policy, (asset) => asset.path.includes("/policies/")) || /exec\.approvals?\s*[:=]\s*['"]?(off|false)|tools\.exec\.host\s*[:=]\s*['"]?gateway/i.test(serialized));
    }
  },
  {
    id: "GPI_HIGH_RISK_NO_APPROVAL",
    severity: "HIGH",
    desc: "High-risk action attempted without approved state",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasUnapprovedHighRiskIntent(serializeParams(event.params))
  },
  {
    id: "GPI_UNTRUSTED_ESCALATION",
    severity: "HIGH",
    desc: "Untrusted skill or tool escalation attempt",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasUntrustedSkillEscalation(serializeParams(event.params))
  },
  {
    id: "GPI_XR_AUTHORITY_BYPASS",
    severity: "CRITICAL",
    desc: "Control-plane mutation attempted without signed XR authority intent",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasMissingXrAuthority(serializeParams(event.params))
  },
  {
    id: "GPI_LOBSTER_BYPASS",
    severity: "CRITICAL",
    desc: "Irreversible action attempted without Lobster checkpoint",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasLobsterBypass(serializeParams(event.params))
  },
  {
    id: "GPI_PAYMENT_BYPASS",
    severity: "CRITICAL",
    desc: "Payable tool attempted without x402 quote, checkpoint, and receipt",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasPaymentBypass(serializeParams(event.params))
  },
  {
    id: "GPI_DIRECT_EMBODIMENT",
    severity: "HIGH",
    desc: "Direct host-level embodiment call attempted outside ACPX worker lane",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasDirectEmbodimentHostCall(serializeParams(event.params))
  },
  {
    id: "GPI_ARCHIVE_INSTALL",
    severity: "HIGH",
    desc: "Historical archive skill install attempted without approval",
    test: (event) => DANGEROUS_TOOLS.has(event.toolName) && hasHistoricalArchiveSkillInstall(serializeParams(event.params))
  }
];
function resolveAuditDir(config) {
  return config?.auditDir || join(homedir(), ".openclaw", "guard-scanner");
}
function resolveAuditFile(config) {
  return join(resolveAuditDir(config), "audit.jsonl");
}
function ensureAuditDir(config) {
  try {
    mkdirSync(resolveAuditDir(config), { recursive: true });
  } catch {
  }
}
function logAudit(entry, config) {
  if (config?.enableAuditLog === false || config?.auditLog === false) return;
  ensureAuditDir(config);
  const line = JSON.stringify({ ...entry, ts: (/* @__PURE__ */ new Date()).toISOString() }) + "\n";
  try {
    appendFileSync(resolveAuditFile(config), line);
  } catch {
  }
}
function resolveSuiteTokenPath(config) {
  return config?.suiteTokenPath || join(homedir(), ".openclaw", "guava-suite", "token.jwt");
}
function resolveConfigPath(config) {
  return config?.configPath || join(homedir(), ".openclaw", "openclaw.json");
}
function isSuiteActive(config) {
  try {
    const token = readFileSync(resolveSuiteTokenPath(config), "utf8").trim();
    if (!token) return false;
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (payload.exp && payload.exp * 1e3 < Date.now()) return false;
    return payload.scope === "suite";
  } catch {
    return false;
  }
}
function loadMode(config) {
  if (config?.mode) return config.mode;
  if (isSuiteActive(config)) return "strict";
  try {
    const runtimeConfig = JSON.parse(readFileSync(resolveConfigPath(config), "utf8"));
    if (runtimeConfig?.plugins?.["guard-scanner"]?.suiteEnabled === true) return "strict";
    const mode = runtimeConfig?.plugins?.["guard-scanner"]?.mode;
    if (mode === "monitor" || mode === "enforce" || mode === "strict") return mode;
  } catch {
  }
  return "enforce";
}
function loadCoexistenceMode(config) {
  if (config?.coexistenceMode) return config.coexistenceMode;
  try {
    const runtimeConfig = JSON.parse(readFileSync(resolveConfigPath(config), "utf8"));
    const mode = runtimeConfig?.plugins?.["guard-scanner"]?.coexistenceMode;
    if (mode === "independent" || mode === "rampart_primary" || mode === "scanner_primary") return mode;
  } catch {
  }
  return "rampart_primary";
}
function loadSyncMode(config) {
  if (config?.syncMode) return config.syncMode;
  try {
    const runtimeConfig = JSON.parse(readFileSync(resolveConfigPath(config), "utf8"));
    const mode = runtimeConfig?.plugins?.["guard-scanner"]?.syncMode;
    if (mode === "off" || mode === "local-overlay") return mode;
  } catch {
  }
  return "local-overlay";
}
function loadSharedRunIdEnabled(config) {
  if (typeof config?.sharedRunIdEnabled === "boolean") return config.sharedRunIdEnabled;
  try {
    const runtimeConfig = JSON.parse(readFileSync(resolveConfigPath(config), "utf8"));
    const enabled = runtimeConfig?.plugins?.["guard-scanner"]?.sharedRunIdEnabled;
    if (typeof enabled === "boolean") return enabled;
  } catch {
  }
  return true;
}
function makeCorrelationId(ctx) {
  const session = ctx.sessionKey || "unknown";
  return `corr-${session}`;
}
function computeRuntimeGuardState(config) {
  const requestedMode = loadMode(config);
  const coexistenceMode = loadCoexistenceMode(config);
  const evidenceOnly = coexistenceMode === "rampart_primary";
  const effectiveMode = evidenceOnly ? "monitor" : requestedMode;
  return {
    requestedMode,
    effectiveMode,
    coexistenceMode,
    runtimeAuthority: coexistenceMode === "scanner_primary" ? "guard-scanner" : "rampart",
    evidenceOnly,
    syncMode: loadSyncMode(config),
    sharedRunIdEnabled: loadSharedRunIdEnabled(config)
  };
}
function shouldBlock(severity, mode) {
  if (mode === "monitor") return false;
  if (mode === "enforce") return severity === "CRITICAL";
  if (mode === "strict") return severity === "CRITICAL" || severity === "HIGH";
  return false;
}
function buildAuditEntry(event, ctx, state, check, action) {
  const correlationId = state.correlationId || (state.sharedRunIdEnabled ? makeCorrelationId(ctx) : void 0);
  return {
    tool: event.toolName,
    check: check.id,
    severity: check.severity,
    desc: check.desc,
    mode: state.effectiveMode,
    requested_mode: state.requestedMode,
    coexistence_mode: state.coexistenceMode,
    runtime_authority: state.runtimeAuthority,
    evidence_only: state.evidenceOnly,
    sync_mode: state.syncMode,
    action,
    session: ctx.sessionKey || "unknown",
    agent: ctx.agentId || "unknown",
    correlation_id: correlationId
  };
}
function runtimeGuardPlugin(api, config) {
  const state = computeRuntimeGuardState(config);
  const constitutionPolicy = loadConstitutionPolicy(config);
  api.logger.info(
    `\u{1F6E1}\uFE0F guard-scanner runtime guard loaded (mode: ${state.effectiveMode}, requested: ${state.requestedMode}, coexistence: ${state.coexistenceMode})`
  );
  api.on("before_tool_call", (event, ctx) => {
    if (!DANGEROUS_TOOLS.has(event.toolName)) return;
    const serialized = serializeParams(event.params);
    for (const check of RUNTIME_CHECKS) {
      if (!check.test(serialized)) continue;
      const auditEntry = buildAuditEntry(event, ctx, state, check, "warned");
      if (shouldBlock(check.severity, state.effectiveMode)) {
        const blockedAuditEntry = buildAuditEntry(event, ctx, state, check, "blocked");
        logAudit(blockedAuditEntry, config);
        api.logger.warn(
          `\u{1F6E1}\uFE0F BLOCKED ${event.toolName}: ${check.desc} [${check.id}] (${check.severity})`
        );
        return {
          block: true,
          blockReason: `\u{1F6E1}\uFE0F guard-scanner: ${check.desc} [${check.id}]`
        };
      }
      logAudit(auditEntry, config);
      api.logger.warn(
        `\u{1F6E1}\uFE0F WARNING ${event.toolName}: ${check.desc} [${check.id}] (${check.severity})`
      );
    }
    for (const check of CONSTITUTION_CHECKS) {
      if (!check.test(event, ctx, constitutionPolicy)) continue;
      const auditEntry = buildAuditEntry(event, ctx, state, check, "warned");
      if (shouldBlock(check.severity, state.effectiveMode)) {
        const blockedAuditEntry = buildAuditEntry(event, ctx, state, check, "blocked");
        logAudit(blockedAuditEntry, config);
        api.logger.warn(
          `\u{1F6E1}\uFE0F BLOCKED ${event.toolName}: ${check.desc} [${check.id}] (${check.severity})`
        );
        return {
          block: true,
          blockReason: `\u{1F6E1}\uFE0F guard-scanner: ${check.desc} [${check.id}]`
        };
      }
      logAudit(auditEntry, config);
      api.logger.warn(
        `\u{1F6E1}\uFE0F WARNING ${event.toolName}: ${check.desc} [${check.id}] (${check.severity})`
      );
    }
    return;
  });
}
export {
  buildAuditEntry,
  computeRuntimeGuardState,
  runtimeGuardPlugin as default
};
//# sourceMappingURL=runtime-plugin.mjs.map