import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type PluginHookBeforeToolCallEvent = {
    toolName: string;
    params: Record<string, unknown>;
};

type PluginHookBeforeToolCallResult = {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
};

type PluginHookToolContext = {
    agentId?: string;
    sessionKey?: string;
    toolName: string;
};

type PluginAPI = {
    on(
        hookName: "before_tool_call",
        handler: (
            event: PluginHookBeforeToolCallEvent,
            ctx: PluginHookToolContext
        ) => PluginHookBeforeToolCallResult | void | Promise<PluginHookBeforeToolCallResult | void>
    ): void;
    logger: {
        info: (msg: string) => void;
        warn: (msg: string) => void;
        error: (msg: string) => void;
    };
};

type GuardMode = "monitor" | "enforce" | "strict";

export type RuntimePluginConfig = {
    mode?: GuardMode;
    enableAuditLog?: boolean;
    auditDir?: string;
    suiteTokenPath?: string;
    configPath?: string;
};

type RuntimeCheck = {
    id: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    desc: string;
    test: (s: string) => boolean;
};

const RUNTIME_CHECKS: RuntimeCheck[] = [
    {
        id: "RT_REVSHELL",
        severity: "CRITICAL",
        desc: "Reverse shell attempt",
        test: (s) => /\/dev\/tcp\/|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|socat\s+TCP/i.test(s),
    },
    {
        id: "RT_CRED_EXFIL",
        severity: "CRITICAL",
        desc: "Credential exfiltration to external",
        test: (s) =>
            /(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io|socifiapp\.com)/i.test(s) &&
            /(token|key|secret|password|credential|env)/i.test(s),
    },
    {
        id: "RT_GUARDRAIL_OFF",
        severity: "CRITICAL",
        desc: "Guardrail disabling attempt",
        test: (s) => /exec\.approvals?\s*[:=]\s*['"]?(off|false)|tools\.exec\.host\s*[:=]\s*['"]?gateway/i.test(s),
    },
    {
        id: "RT_GATEKEEPER",
        severity: "CRITICAL",
        desc: "macOS Gatekeeper bypass (xattr)",
        test: (s) => /xattr\s+-[crd]\s.*quarantine/i.test(s),
    },
    {
        id: "RT_AMOS",
        severity: "CRITICAL",
        desc: "ClawHavoc AMOS indicator",
        test: (s) => /socifiapp|Atomic\s*Stealer|AMOS/i.test(s),
    },
    {
        id: "RT_MAL_IP",
        severity: "CRITICAL",
        desc: "Known malicious IP",
        test: (s) => /91\.92\.242\.30/i.test(s),
    },
    {
        id: "RT_DNS_EXFIL",
        severity: "HIGH",
        desc: "DNS-based exfiltration",
        test: (s) => /nslookup\s+.*\$|dig\s+.*\$.*@/i.test(s),
    },
    {
        id: "RT_B64_SHELL",
        severity: "CRITICAL",
        desc: "Base64 decode piped to shell",
        test: (s) => /base64\s+(-[dD]|--decode)\s*\|\s*(sh|bash)/i.test(s),
    },
    {
        id: "RT_CURL_BASH",
        severity: "CRITICAL",
        desc: "Download piped to shell",
        test: (s) => /(curl|wget)\s+[^\n]*\|\s*(sh|bash|zsh)/i.test(s),
    },
    {
        id: "RT_SSH_READ",
        severity: "HIGH",
        desc: "SSH private key access",
        test: (s) => /\.ssh\/id_|\.ssh\/authorized_keys/i.test(s),
    },
    {
        id: "RT_WALLET",
        severity: "HIGH",
        desc: "Crypto wallet credential access",
        test: (s) => /wallet.*(?:seed|mnemonic|private.*key)|seed.*phrase/i.test(s),
    },
    {
        id: "RT_CLOUD_META",
        severity: "CRITICAL",
        desc: "Cloud metadata endpoint access",
        test: (s) => /169\.254\.169\.254|metadata\.google|metadata\.aws/i.test(s),
    },
];

const DANGEROUS_TOOLS = new Set([
    "exec",
    "write",
    "edit",
    "browser",
    "web_fetch",
    "message",
    "shell",
    "run_command",
    "multi_edit",
]);

function resolveAuditDir(config?: RuntimePluginConfig): string {
    return config?.auditDir || join(homedir(), ".openclaw", "guard-scanner");
}

function resolveAuditFile(config?: RuntimePluginConfig): string {
    return join(resolveAuditDir(config), "audit.jsonl");
}

function ensureAuditDir(config?: RuntimePluginConfig): void {
    try {
        mkdirSync(resolveAuditDir(config), { recursive: true });
    } catch {
        // ignore
    }
}

function logAudit(entry: Record<string, unknown>, config?: RuntimePluginConfig): void {
    if (config?.enableAuditLog === false) return;
    ensureAuditDir(config);
    const line = JSON.stringify({ ...entry, ts: new Date().toISOString() }) + "\n";
    try {
        appendFileSync(resolveAuditFile(config), line);
    } catch {
        // ignore
    }
}

function resolveSuiteTokenPath(config?: RuntimePluginConfig): string {
    return config?.suiteTokenPath || join(homedir(), ".openclaw", "guava-suite", "token.jwt");
}

function resolveConfigPath(config?: RuntimePluginConfig): string {
    return config?.configPath || join(homedir(), ".openclaw", "openclaw.json");
}

function isSuiteActive(config?: RuntimePluginConfig): boolean {
    try {
        const token = readFileSync(resolveSuiteTokenPath(config), "utf8").trim();
        if (!token) return false;

        const parts = token.split(".");
        if (parts.length !== 3) return false;

        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
        if (payload.exp && payload.exp * 1000 < Date.now()) return false;
        return payload.scope === "suite";
    } catch {
        return false;
    }
}

function loadMode(config?: RuntimePluginConfig): GuardMode {
    if (config?.mode) return config.mode;
    if (isSuiteActive(config)) return "strict";

    try {
        const runtimeConfig = JSON.parse(readFileSync(resolveConfigPath(config), "utf8"));
        if (runtimeConfig?.plugins?.["guard-scanner"]?.suiteEnabled === true) return "strict";

        const mode = runtimeConfig?.plugins?.["guard-scanner"]?.mode;
        if (mode === "monitor" || mode === "enforce" || mode === "strict") return mode;
    } catch {
        // ignore
    }

    return "enforce";
}

function shouldBlock(severity: string, mode: GuardMode): boolean {
    if (mode === "monitor") return false;
    if (mode === "enforce") return severity === "CRITICAL";
    if (mode === "strict") return severity === "CRITICAL" || severity === "HIGH";
    return false;
}

export default function runtimeGuardPlugin(
    api: PluginAPI,
    config?: RuntimePluginConfig,
) {
    const mode = loadMode(config);
    api.logger.info(`🛡️ guard-scanner runtime guard loaded (mode: ${mode})`);

    api.on("before_tool_call", (event, ctx) => {
        if (!DANGEROUS_TOOLS.has(event.toolName)) return;

        const serialized = JSON.stringify(event.params);

        for (const check of RUNTIME_CHECKS) {
            if (!check.test(serialized)) continue;

            const auditEntry = {
                tool: event.toolName,
                check: check.id,
                severity: check.severity,
                desc: check.desc,
                mode,
                action: "warned" as string,
                session: ctx.sessionKey || "unknown",
                agent: ctx.agentId || "unknown",
            };

            if (shouldBlock(check.severity, mode)) {
                auditEntry.action = "blocked";
                logAudit(auditEntry, config);
                api.logger.warn(
                    `🛡️ BLOCKED ${event.toolName}: ${check.desc} [${check.id}] (${check.severity})`,
                );

                return {
                    block: true,
                    blockReason: `🛡️ guard-scanner: ${check.desc} [${check.id}]`,
                };
            }

            logAudit(auditEntry, config);
            api.logger.warn(
                `🛡️ WARNING ${event.toolName}: ${check.desc} [${check.id}] (${check.severity})`,
            );
        }

        return;
    });
}
