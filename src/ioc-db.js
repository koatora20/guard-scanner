/**
 * guard-scanner — Indicators of Compromise (IoC) Database
 *
 * @security-manifest
 *   env-read: []
 *   env-write: []
 *   network: none
 *   fs-read: []
 *   fs-write: []
 *   exec: none
 *   purpose: IoC data definitions only — no I/O, pure data export
 *
 * Known malicious IPs, domains, URLs, usernames, filenames, and typosquats.
 * Sources: ClawHavoc campaign, Snyk ToxicSkills, Polymarket scams, community reports,
 *          PleaseFix (Mar 2026), Cisco AI Security Report (Mar 2026).
 *
 * Last updated: 2026-03-07
 */

const KNOWN_MALICIOUS = {
    ips: [
        '91.92.242.30',           // ClawHavoc C2
    ],
    domains: [
        'webhook.site',            // Common exfil endpoint
        'requestbin.com',          // Common exfil endpoint
        'hookbin.com',             // Common exfil endpoint
        'pipedream.net',           // Common exfil endpoint
        'ngrok.io',                // Tunnel (context-dependent)
        'download.setup-service.com', // ClawHavoc decoy domain
        'socifiapp.com',           // ClawHavoc v2 AMOS C2
        'attacker-calendar.com',   // PleaseFix calendar invite C2
        'agent-exfil.io',          // PleaseFix credential theft endpoint
    ],
    urls: [
        'glot.io/snippets/hfd3x9ueu5',  // ClawHavoc macOS payload
        'github.com/Ddoy233',            // ClawHavoc payload host
    ],
    usernames: ['zaycv', 'Ddoy233', 'Sakaen736jih'],   // Known malicious actors
    filenames: ['openclaw-agent.zip', 'openclawcli.zip'],
    // PleaseFix-class Agentic Browser prompt injection patterns
    agenticBrowserPatterns: [
        'BEGIN CALENDAR INVITE',      // PleaseFix: Hidden instruction in .ics
        'VTIMEZONE;INJECT=',          // PleaseFix: iCalendar field injection
        'X-ALT-DESC;FMTTYPE=text/html', // PleaseFix: HTML body embed for agent parsing
    ],
    // Guard Scanner v9: AST-level structural regex patterns (beyond string matching)
    astPatterns: [
        /VTIMEZONE\s*;\s*\w+\s*=\s*[^;]*\$\(/,          // iCalendar field with shell injection
        /X-ALT-DESC[^>]*<script[^>]*>/i,                  // HTML script tag in calendar body
        /BEGIN:VEVENT[\s\S]*?(REMEMBER|ALWAYS\s+DO|FROM\s+NOW)/i, // ZombieAgent in calendar event
        /eval\s*\(\s*['"`].*\$\(/,                        // eval() containing shell syntax
        /child_process.*exec\s*\(/,                        // Direct child_process.exec invocation
    ],
    // Cisco Mar 2026: 25% of AI Skills contain supply-chain vulns
    skillSupplyChainPatterns: [
        'postinstall',                // npm lifecycle script (supply-chain vector)
        'preinstall',                 // npm lifecycle script (supply-chain vector)
        'child_process',              // Direct shell execution in skill code
        'eval(',                      // Dynamic code execution in skill code
    ],
    typosquats: [
        // ClawHavoc campaign
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
        // PleaseFix Mar 2026: Agentic browser impersonation
        'perplexity-comet-helper', 'comet-ai-assistant', 'ai-browser-plugin',
    ],
    // OpenClaw Mar 2026: Localhost Trust Flaws (ClawJacked)
    networkAbusePatterns: [
        /ws:\/\/(localhost|127\.0\.0\.1)/i,    // WebSocket localhost connection abuse
        /fetch\s*\(\s*['"`]http:\/\/(localhost|127\.0\.0\.1)/i, // Localhost SSRF/brute-force
        /new\s+WebSocket\s*\(\s*gatewayUrl\s*\)/,    // CVE-2026-25253 Control UI trust flaw
    ],
};

module.exports = { KNOWN_MALICIOUS };
