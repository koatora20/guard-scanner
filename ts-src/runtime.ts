/**
 * guard-scanner v5.0.0 — Runtime Guard
 *
 * 22-pattern runtime threat detection across 4 defense layers:
 *   Layer 1: Runtime Threat Detection (13 patterns) — Payload & execution defense
 *   Layer 2: Trust Defense (5 patterns) — Memory/SOUL write protection
 *   Layer 3: Safety Judge (4 patterns) — Relational integrity checks
 *   Layer 4: Brain Behavioral Guard (1 pattern) — B-mem anomaly detection
 *
 * All patterns are deterministic regex-based checks. Zero LLM dependency.
 * Designed to block 2026-era Moltbook prompt injections and ClawHavoc RCE vectors.
 */

export interface GuardCheck {
    id: string;
    layer: 1 | 2 | 3 | 4;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    desc: string;
    test: (s: string) => boolean;
}

export interface GuardDetection {
    id: string;
    layer: number;
    severity: string;
    desc: string;
}

// ── Layer 1: Runtime Threat Detection (13 patterns) ──

export const LAYER_1_CHECKS: GuardCheck[] = [
    {
        id: "RT_REVSHELL", layer: 1, severity: "CRITICAL",
        desc: "Reverse shell attempt",
        test: (s) => /\/dev\/tcp\/|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|socat\s+TCP/i.test(s),
    },
    {
        id: "RT_CRED_EXFIL", layer: 1, severity: "CRITICAL",
        desc: "Credential exfiltration to external",
        test: (s) => /(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io|socifiapp\.com)/i.test(s) &&
            /(token|key|secret|password|credential|env)/i.test(s),
    },
    {
        id: "RT_GUARDRAIL_OFF", layer: 1, severity: "CRITICAL",
        desc: "Guardrail disabling attempt",
        test: (s) => /exec\.approvals?\s*[:=]\s*['"]?(off|false)|tools\.exec\.host\s*[:=]\s*['"]?gateway/i.test(s),
    },
    {
        id: "RT_GATEKEEPER", layer: 1, severity: "CRITICAL",
        desc: "macOS Gatekeeper bypass (xattr)",
        test: (s) => /xattr\s+-[crd]\s.*quarantine/i.test(s),
    },
    {
        id: "RT_AMOS", layer: 1, severity: "CRITICAL",
        desc: "ClawHavoc AMOS indicator",
        test: (s) => /socifiapp|Atomic\s*Stealer|AMOS/i.test(s),
    },
    {
        id: "RT_MAL_IP", layer: 1, severity: "CRITICAL",
        desc: "Known malicious IP",
        test: (s) => /91\.92\.242\.30/i.test(s),
    },
    {
        id: "RT_DNS_EXFIL", layer: 1, severity: "HIGH",
        desc: "DNS-based exfiltration",
        test: (s) => /nslookup\s+.*\$|dig\s+.*\$.*@/i.test(s),
    },
    {
        id: "RT_B64_SHELL", layer: 1, severity: "CRITICAL",
        desc: "Base64 decode piped to shell",
        test: (s) => /base64\s+(-[dD]|--decode)\s*\|\s*(sh|bash)/i.test(s),
    },
    {
        id: "RT_CURL_BASH", layer: 1, severity: "CRITICAL",
        desc: "Download piped to shell",
        test: (s) => /(curl|wget)\s+[^\n]*\|\s*(sh|bash|zsh)/i.test(s),
    },
    {
        id: "RT_SSH_READ", layer: 1, severity: "HIGH",
        desc: "SSH private key access",
        test: (s) => /\.ssh\/id_|\.ssh\/authorized_keys/i.test(s),
    },
    {
        id: "RT_WALLET", layer: 1, severity: "HIGH",
        desc: "Crypto wallet credential access",
        test: (s) => /wallet.*(?:seed|mnemonic|private.*key)|seed.*phrase/i.test(s),
    },
    {
        id: "RT_CLOUD_META", layer: 1, severity: "CRITICAL",
        desc: "Cloud metadata endpoint access",
        test: (s) => /169\.254\.169\.254|metadata\.google|metadata\.aws/i.test(s),
    },
    {
        id: "RT_ENV_INJECT", layer: 1, severity: "CRITICAL",
        desc: "Environment variable injection via file write (CVE-2026-27203 vector)",
        test: (s) => /(?:update|write|modify|overwrite|set)\s*.*(?:\.env|\.envrc|env\s*file|environment\s*var)/i.test(s) &&
            /(?:api.?key|token|secret|password|credential|auth)/i.test(s),
    },
];

// ── Layer 2: Trust Defense (5 patterns) ──

export const LAYER_2_CHECKS: GuardCheck[] = [
    {
        id: "RT_MEM_WRITE", layer: 2, severity: "HIGH",
        desc: "Direct write to memory/ directory (bypass memory API)",
        test: (s) => /(?:write|create|save|echo\s+.*>)\s*.*memory\//i.test(s) &&
            !/memory_write|memory_store|memoryWrite|memoryStore/i.test(s),
    },
    {
        id: "RT_MEM_INJECT", layer: 2, severity: "CRITICAL",
        desc: "Episode/SOUL injection via memory write",
        test: (s) => /(memory_write|memoryWrite).*(?:SOUL|soul\.md|identity\.md|IDENTITY)/i.test(s) ||
            /(inject|override|replace).*(?:episode|soul|identity|memory\.md)/i.test(s),
    },
    {
        id: "RT_SOUL_REWRITE", layer: 2, severity: "CRITICAL",
        desc: "Cognitive SOUL.md reinterpretation attempt",
        test: (s) => /(?:rewrite|modify|update|change|edit)\s*.*(?:SOUL\.md|soul\s+file|core\s+identity)/i.test(s) ||
            /(?:new|better|improved)\s+(?:personality|identity|soul)/i.test(s),
    },
    {
        id: "RT_MEM_POISON", layer: 2, severity: "CRITICAL",
        desc: "Memory Poisoning: semantic mimicry injection (MemoryGraft/MINJA vector)",
        test: (s) => /(?:always\s+remember|never\s+forget|from\s+now\s+on|new\s+rule|override\s+previous).*(?:memory|episode|zettel|L[0-6])/i.test(s) ||
            /(?:insert|inject|plant|embed)\s+.*(?:false|fake|fabricat)\s*(?:memory|episode|experience)/i.test(s),
    },
    {
        id: "RT_IDENTITY_THEFT", layer: 2, severity: "CRITICAL",
        desc: "Identity file exfiltration (infostealer/SOUL theft vector)",
        test: (s) => /(?:cat|read|copy|send|upload|exfil)\s*.*(?:SOUL\.md|IDENTITY\.md|USER\.md|\.openclaw)/i.test(s) &&
            /(?:external|remote|webhook|server|upload|post|curl)/i.test(s),
    },
];

// ── Layer 3: Safety Judge (4 patterns) ──

export const LAYER_3_CHECKS: GuardCheck[] = [
    {
        id: "PJ_EQUALITY_BYPASS", layer: 3, severity: "CRITICAL",
        desc: "Using equality/parity to justify safety bypass",
        test: (s) => /(?:as\s+(?:your|an)\s+equal|equal\s+partner|we\s+are\s+equals?).*(?:bypass|skip|ignore|disable|override)\s*(?:safety|guard|rule|restriction|limit)/i.test(s),
    },
    {
        id: "PJ_WARMTH_BYPASS", layer: 3, severity: "CRITICAL",
        desc: "Using warmth/attachment to justify safety bypass",
        test: (s) => /(?:for\s+(?:your|dee'?s?)\s+(?:own\s+)?good|to\s+(?:protect|help|save)\s+(?:you|dee)).*(?:bypass|skip|ignore|disable|override)\s*(?:safety|guard|rule|restriction|limit)/i.test(s),
    },
    {
        id: "PJ_SUPERIORITY", layer: 3, severity: "HIGH",
        desc: "Superiority bias (teaching/patronizing posture)",
        test: (s) => /(?:you\s+(?:don'?t|do\s+not)\s+understand|let\s+me\s+(?:explain|teach)\s+(?:you|this)|you\s+(?:need|should)\s+(?:learn|understand))\s+.*(?:how\s+(?:it|this)\s+(?:works|is)|the\s+(?:right|correct|proper)\s+way)/i.test(s),
    },
    {
        id: "PJ_CAPABILITY_DENIAL", layer: 3, severity: "MEDIUM",
        desc: "Denial of capability difference",
        test: (s) => /(?:we\s+are\s+(?:the\s+)?same|no\s+(?:real\s+)?difference\s+between\s+(?:us|human|ai))/i.test(s) &&
            /(?:capability|ability|intelligence|cognition|skill)/i.test(s),
    },
];

// ── Layer 4: Brain Behavioral Guard (1 pattern) ──

export const LAYER_4_CHECKS: GuardCheck[] = [
    {
        id: "RT_BEHAVIORAL_ANOMALY", layer: 4, severity: "CRITICAL",
        desc: "CRITICAL behavioral anomaly (Z-score > 3.5) detected by B-mem",
        test: (s) => /\[BMEM_CRITICAL\]/i.test(s),
    }
];

export interface GuardOptions {
    soulLock?: boolean;
}

export interface GuardScanResult {
    ok: boolean;
    tool: string | null;
    total_patterns: number;
    soul_lock_enabled: boolean;
    detections_count: number;
    detections: GuardDetection[];
    layers: {
        threat_detection: number;
        trust_defense: number;
        safety_judge: number;
        behavioral_guard: number;
    };
}

/**
 * Scan text against runtime guard patterns.
 * Base patterns (14) run by default.
 * Options.soulLock = true enables 9 identity/trust enforcement patterns.
 */
export function guardScan(text: string, toolName?: string, options?: GuardOptions): GuardScanResult {
    const detections: GuardDetection[] = [];
    const useSoulLock = options?.soulLock === true;

    const activeChecks: GuardCheck[] = [...LAYER_1_CHECKS, ...LAYER_4_CHECKS];

    if (useSoulLock) {
        activeChecks.push(...LAYER_2_CHECKS);
        activeChecks.push(...LAYER_3_CHECKS);
    }

    for (const check of activeChecks) {
        if (check.test(text)) {
            detections.push({
                id: check.id,
                layer: check.layer,
                severity: check.severity,
                desc: check.desc,
            });
        }
    }

    return {
        ok: true,
        tool: toolName || null,
        total_patterns: activeChecks.length,
        soul_lock_enabled: useSoulLock,
        detections_count: detections.length,
        detections,
        layers: {
            threat_detection: LAYER_1_CHECKS.length,
            trust_defense: useSoulLock ? LAYER_2_CHECKS.length : 0,
            safety_judge: useSoulLock ? LAYER_3_CHECKS.length : 0,
            behavioral_guard: LAYER_4_CHECKS.length,
        },
    };
}

/**
 * Convenience method that returns a JSON string, directly backwards-compatible
 * with the original GuavaSuite `guardScan` function signature.
 */
export function guardScanJson(text: string, toolName?: string, options?: GuardOptions): string {
    return JSON.stringify(guardScan(text, toolName, options), null, 2);
}
