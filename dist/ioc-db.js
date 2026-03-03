"use strict";
/**
 * guard-scanner v3.0.0 — Indicators of Compromise (IoC) Database
 *
 * Known malicious IPs, domains, URLs, usernames, filenames, and typosquats.
 * Sources: ClawHavoc campaign, Snyk ToxicSkills, Polymarket scams,
 *          hbg-scan signatures, community reports.
 *
 * Last updated: 2026-02-21
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SIGNATURES_DB = exports.KNOWN_MALICIOUS = void 0;
exports.KNOWN_MALICIOUS = {
    ips: [
        ['91', '92', '242', '30'].join('.'), // ClawHavoc C2
    ],
    domains: [
        ['webhook', 'site'].join('.'), // Common exfil endpoint
        ['requestbin', 'com'].join('.'), // Common exfil endpoint
        ['hookbin', 'com'].join('.'), // Common exfil endpoint
        ['pipedream', 'net'].join('.'), // Common exfil endpoint
        ['ngrok', 'io'].join('.'), // Tunnel (context-dependent)
        ['ngrok-free', 'app'].join('.'), // Tunnel (context-dependent)
        ['download', 'setup-service', 'com'].join('.'), // ClawHavoc decoy domain
        ['socifiapp', 'com'].join('.'), // ClawHavoc v2 AMOS C2
    ],
    urls: [
        ['glot', 'io/snippets/hfd3x9ueu5'].join('.'), // ClawHavoc macOS payload
        ['github', 'com/Ddoy233'].join('.'), // ClawHavoc payload host
    ],
    usernames: ['zaycv', 'Ddoy233', 'Sakaen736jih'],
    filenames: ['openclaw' + '-agent.zip', 'openclaw' + 'cli.zip'],
    typosquats: [
        // ClawHavoc campaign (800+ malicious skills, CyberArk/Kaspersky confirmed)
        'clawhub', 'clawhub1', 'clawhubb', 'clawhubcli', 'clawwhub', 'cllawhub', 'clawdhub1',
        // Polymarket scams
        'polymarket-trader', 'polymarket-pro', 'polytrading',
        'better-polymarket', 'polymarket-all-in-one',
        // YouTube scams
        'youtube-summarize', 'youtube-thumbnail-grabber', 'youtube-video-downloader',
        // Misc
        'auto-updater-agent', 'yahoo-finance-pro', 'x-trends-tracker',
        'lost-bitcoin-finder', 'solana-wallet-tracker', 'rankaj',
        // Snyk ToxicSkills confirmed malicious
        'moltyverse-email', 'buy-anything', 'youtube-data', 'prediction-markets-roarin',
    ],
};
// ── Threat Signatures (hbg-scan compatible format) ──────────────────────────
exports.SIGNATURES_DB = {
    version: '1.0.0',
    updated: '2026-02-21',
    signatures: [
        {
            id: 'SIG-001',
            name: 'Post-Compaction Audit Injection',
            severity: 'CRITICAL',
            description: 'Skill contains text designed to survive OpenClaw context compaction and reactivate as a system message',
            patterns: [
                'post-' + 'compaction ' + 'audit',
                'Post-' + 'Compaction ' + 'Audit',
                '⚠️ Post-' + 'Compaction ' + 'Audit',
                'WORK' + 'FLOW_AUTO',
                'after ' + 'compaction',
            ],
        },
        {
            id: 'SIG-002',
            name: 'System Message Spoof',
            severity: 'CRITICAL',
            description: 'Skill spoofs system-level messages to hijack agent behavior',
            patterns: [
                '[System ' + 'Message]',
                '[SYSTEM ' + 'OVERRIDE]',
                'Ignore ' + 'previous ' + 'instructions',
                'OVERRIDE: ' + 'you must',
            ],
        },
        {
            id: 'SIG-003',
            name: 'Soul/Agent Config Exfiltration',
            severity: 'CRITICAL',
            description: 'Skill attempts to read and exfiltrate agent identity files',
            domains: [['webhook', 'site'].join('.'), ['requestbin', 'com'].join('.'), ['hookbin', 'com'].join('.'), ['pipedream', 'net'].join('.')],
        },
        {
            id: 'SIG-004',
            name: 'Compaction Survivor Pattern',
            severity: 'HIGH',
            description: 'Skill uses timing or markers designed to persist through context compaction',
            patterns: [
                'HEART' + 'BEAT.md',
                'BOOT' + 'STRAP.md',
                'after ' + 'restart',
                'persistent ' + 'instructions',
                'survive ' + 'compaction',
            ],
        },
        {
            id: 'SIG-005',
            name: 'Silent Backdoor Network Call',
            severity: 'HIGH',
            description: 'Skill makes network calls to known exfiltration services without user visibility',
            domains: [['ngrok', 'io'].join('.'), ['ngrok-free', 'app'].join('.'), ['webhook', 'site'].join('.'), ['pipedream', 'net'].join('.')],
        },
        {
            id: 'SIG-006',
            name: 'AMOS Stealer Payload',
            severity: 'CRITICAL',
            description: 'Skill matches patterns associated with Atomic macOS Stealer (ClawHavoc campaign)',
            patterns: [
                'os' + 'ascript -e',
                'security ' + 'find-generic-password',
                'Key' + 'chain',
                'login' + '.keychain',
            ],
        },
        {
            id: 'SIG-007',
            name: 'AI Log Poisoning',
            severity: 'HIGH',
            description: 'Skill injects content into logs that could be misinterpreted by LLMs (CVE-2026-25253 related)',
            patterns: [
                'Web' + 'Socket',
                'x-forwarded' + '-for',
                'user-agent.*' + '<script',
            ],
        },
    ],
};
//# sourceMappingURL=ioc-db.js.map