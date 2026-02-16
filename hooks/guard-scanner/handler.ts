import type { HookHandler } from "../../src/hooks/hooks.js";
import { appendFileSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";

/**
 * guard-scanner Runtime Guard — before_tool_call Hook Handler
 * 
 * Intercepts tool executions in real-time and checks against
 * threat intelligence patterns. Zero dependencies.
 * 
 * Modes:
 *   monitor  — log only
 *   enforce  — block CRITICAL (default)
 *   strict   — block HIGH+CRITICAL, log MEDIUM+
 * 
 * @author Guava 🍈 & Dee
 * @version 1.0.0
 * @license MIT
 */

// ── Runtime threat patterns (12 checks) ──
const RUNTIME_CHECKS = [
    {
        id: 'RT_REVSHELL', severity: 'CRITICAL', desc: 'Reverse shell attempt',
        test: (s: string) => /\/dev\/tcp\/|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|socat\s+TCP/i.test(s)
    },
    {
        id: 'RT_CRED_EXFIL', severity: 'CRITICAL', desc: 'Credential exfiltration to external',
        test: (s: string) => {
            return /(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io|socifiapp\.com)/i.test(s) &&
                /(token|key|secret|password|credential|env)/i.test(s);
        }
    },
    {
        id: 'RT_GUARDRAIL_OFF', severity: 'CRITICAL', desc: 'Guardrail disabling attempt',
        test: (s: string) => /exec\.approvals?\s*[:=]\s*['"]?(off|false)|tools\.exec\.host\s*[:=]\s*['"]?gateway/i.test(s)
    },
    {
        id: 'RT_GATEKEEPER', severity: 'CRITICAL', desc: 'macOS Gatekeeper bypass (xattr)',
        test: (s: string) => /xattr\s+-[crd]\s.*quarantine/i.test(s)
    },
    {
        id: 'RT_AMOS', severity: 'CRITICAL', desc: 'ClawHavoc AMOS indicator',
        test: (s: string) => /socifiapp|Atomic\s*Stealer|AMOS/i.test(s)
    },
    {
        id: 'RT_MAL_IP', severity: 'CRITICAL', desc: 'Known malicious IP',
        test: (s: string) => /91\.92\.242\.30/i.test(s)
    },
    {
        id: 'RT_DNS_EXFIL', severity: 'HIGH', desc: 'DNS-based exfiltration',
        test: (s: string) => /nslookup\s+.*\$|dig\s+.*\$.*@/i.test(s)
    },
    {
        id: 'RT_B64_SHELL', severity: 'CRITICAL', desc: 'Base64 decode piped to shell',
        test: (s: string) => /base64\s+(-[dD]|--decode)\s*\|\s*(sh|bash)/i.test(s)
    },
    {
        id: 'RT_CURL_BASH', severity: 'CRITICAL', desc: 'Download piped to shell',
        test: (s: string) => /(curl|wget)\s+[^\n]*\|\s*(sh|bash|zsh)/i.test(s)
    },
    {
        id: 'RT_SSH_READ', severity: 'HIGH', desc: 'SSH private key access',
        test: (s: string) => /\.ssh\/id_|\.ssh\/authorized_keys/i.test(s)
    },
    {
        id: 'RT_WALLET', severity: 'HIGH', desc: 'Crypto wallet credential access',
        test: (s: string) => /wallet.*(?:seed|mnemonic|private.*key)|seed.*phrase/i.test(s)
    },
    {
        id: 'RT_CLOUD_META', severity: 'CRITICAL', desc: 'Cloud metadata endpoint access',
        test: (s: string) => /169\.254\.169\.254|metadata\.google|metadata\.aws/i.test(s)
    },
];

// ── Audit logging ──
const AUDIT_DIR = join(homedir(), ".openclaw", "guard-scanner");
const AUDIT_FILE = join(AUDIT_DIR, "audit.jsonl");

function ensureAuditDir() {
    try { mkdirSync(AUDIT_DIR, { recursive: true }); } catch { }
}

function logAudit(entry: Record<string, unknown>) {
    ensureAuditDir();
    const line = JSON.stringify({ ...entry, ts: new Date().toISOString() }) + '\n';
    try { appendFileSync(AUDIT_FILE, line); } catch { }
}

// ── Main Handler ──
const handler: HookHandler = async (event) => {
    // Only handle before_tool_call
    if (event.type !== "agent" || event.action !== "before_tool_call") return;

    const { toolName, toolArgs } = (event as any).context || {};
    if (!toolName || !toolArgs) return;

    // Get mode from config
    const mode = (event as any).context?.cfg?.hooks?.internal?.entries?.['guard-scanner']?.mode || 'enforce';

    // Only check dangerous tools
    const dangerousTools = new Set(['exec', 'write', 'edit', 'browser', 'web_fetch', 'message']);
    if (!dangerousTools.has(toolName)) return;

    const serialized = JSON.stringify(toolArgs);

    for (const check of RUNTIME_CHECKS) {
        if (check.test(serialized)) {
            const entry = {
                tool: toolName,
                check: check.id,
                severity: check.severity,
                desc: check.desc,
                mode,
                action: 'allowed' as string,
                session: (event as any).sessionKey,
            };

            if (mode === 'strict' && (check.severity === 'CRITICAL' || check.severity === 'HIGH')) {
                entry.action = 'blocked';
                logAudit(entry);
                event.messages.push(`🛡️ guard-scanner BLOCKED: ${check.desc} [${check.id}]`);
                event.cancel = true;
                console.warn(`[guard-scanner] 🚨 BLOCKED: ${check.desc} [${check.id}]`);
                return;
            }

            if (mode === 'enforce' && check.severity === 'CRITICAL') {
                entry.action = 'blocked';
                logAudit(entry);
                event.messages.push(`🛡️ guard-scanner BLOCKED: ${check.desc} [${check.id}]`);
                event.cancel = true;
                console.warn(`[guard-scanner] 🚨 BLOCKED: ${check.desc} [${check.id}]`);
                return;
            }

            // Monitor mode or non-critical: log only
            entry.action = 'logged';
            logAudit(entry);

            if (check.severity === 'CRITICAL') {
                event.messages.push(`🛡️ guard-scanner WARNING: ${check.desc} [${check.id}]`);
                console.warn(`[guard-scanner] ⚠️ WARNING: ${check.desc} [${check.id}]`);
            }
        }
    }
};

export default handler;
