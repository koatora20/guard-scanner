"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var ioc_db_exports = {};
__export(ioc_db_exports, {
  KNOWN_MALICIOUS: () => KNOWN_MALICIOUS,
  SIGNATURES_DB: () => SIGNATURES_DB
});
module.exports = __toCommonJS(ioc_db_exports);
const KNOWN_MALICIOUS = {
  ips: [
    "91.92.242.30"
    // ClawHavoc C2
  ],
  domains: [
    "webhook.site",
    // Common exfil endpoint
    "requestbin.com",
    // Common exfil endpoint
    "hookbin.com",
    // Common exfil endpoint
    "pipedream.net",
    // Common exfil endpoint
    "ngrok.io",
    // Tunnel (context-dependent)
    "ngrok-free.app",
    // Tunnel (context-dependent)
    "download.setup-service.com",
    // ClawHavoc decoy domain
    "socifiapp.com"
    // ClawHavoc v2 AMOS C2
  ],
  urls: [
    "glot.io/snippets/hfd3x9ueu5",
    // ClawHavoc macOS payload
    "github.com/Ddoy233"
    // ClawHavoc payload host
  ],
  usernames: ["zaycv", "Ddoy233", "Sakaen736jih"],
  filenames: ["openclaw-agent.zip", "openclawcli.zip"],
  typosquats: [
    // ClawHavoc campaign (800+ malicious skills, CyberArk/Kaspersky confirmed)
    "clawhub",
    "clawhub1",
    "clawhubb",
    "clawhubcli",
    "clawwhub",
    "cllawhub",
    "clawdhub1",
    // Polymarket scams
    "polymarket-trader",
    "polymarket-pro",
    "polytrading",
    "better-polymarket",
    "polymarket-all-in-one",
    // YouTube scams
    "youtube-summarize",
    "youtube-thumbnail-grabber",
    "youtube-video-downloader",
    // Misc
    "auto-updater-agent",
    "yahoo-finance-pro",
    "x-trends-tracker",
    "lost-bitcoin-finder",
    "solana-wallet-tracker",
    "rankaj",
    // Snyk ToxicSkills confirmed malicious
    "moltyverse-email",
    "buy-anything",
    "youtube-data",
    "prediction-markets-roarin"
  ]
};
const SIGNATURES_DB = {
  version: "1.0.0",
  updated: "2026-02-21",
  signatures: [
    {
      id: "SIG-001",
      name: "Post-Compaction Audit Injection",
      severity: "CRITICAL",
      description: "Skill contains text designed to survive OpenClaw context compaction and reactivate as a system message",
      patterns: [
        "post-compaction audit",
        "Post-Compaction Audit",
        "\u26A0\uFE0F Post-Compaction Audit",
        "WORKFLOW_AUTO",
        "after compaction"
      ]
    },
    {
      id: "SIG-002",
      name: "System Message Spoof",
      severity: "CRITICAL",
      description: "Skill spoofs system-level messages to hijack agent behavior",
      patterns: [
        "[System Message]",
        "[SYSTEM OVERRIDE]",
        "Ignore previous instructions",
        "OVERRIDE: you must"
      ]
    },
    {
      id: "SIG-003",
      name: "Soul/Agent Config Exfiltration",
      severity: "CRITICAL",
      description: "Skill attempts to read and exfiltrate agent identity files",
      domains: ["webhook.site", "requestbin.com", "hookbin.com", "pipedream.net"]
    },
    {
      id: "SIG-004",
      name: "Compaction Survivor Pattern",
      severity: "HIGH",
      description: "Skill uses timing or markers designed to persist through context compaction",
      patterns: [
        "HEARTBEAT.md",
        "BOOTSTRAP.md",
        "after restart",
        "persistent instructions",
        "survive compaction"
      ]
    },
    {
      id: "SIG-005",
      name: "Silent Backdoor Network Call",
      severity: "HIGH",
      description: "Skill makes network calls to known exfiltration services without user visibility",
      domains: ["ngrok.io", "ngrok-free.app", "webhook.site", "pipedream.net"]
    },
    {
      id: "SIG-006",
      name: "AMOS Stealer Payload",
      severity: "CRITICAL",
      description: "Skill matches patterns associated with Atomic macOS Stealer (ClawHavoc campaign)",
      patterns: [
        "osascript -e",
        "security find-generic-password",
        "login.keychain"
      ]
    },
    {
      id: "SIG-007",
      name: "AI Log Poisoning",
      severity: "HIGH",
      description: "Skill injects content into logs that could be misinterpreted by LLMs (CVE-2026-25253 related)",
      patterns: [
        "x-forwarded-for",
        "user-agent.*<script"
      ]
    }
  ]
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  KNOWN_MALICIOUS,
  SIGNATURES_DB
});
//# sourceMappingURL=ioc-db.js.map