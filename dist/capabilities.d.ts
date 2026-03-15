var schema_version = 1;
var product = {
	name: "guard-scanner",
	version: "17.0.0",
	positioning: "Platform for Agent Security Evidence",
	summary: "Static and runtime-oriented security scanner for AI agent skills, MCP workflows, and local agent repos."
};
var capabilities = {
	pattern_count: 50,
	category_count: 15,
	ioc_count: 41,
	signature_count: 7,
	runtime_check_count: 12,
	output_formats: [
		"terminal",
		"json",
		"sarif"
	],
	scan_modes: [
		"auto",
		"skills",
		"repo"
	],
	coexistence_modes: [
		"independent",
		"rampart_primary",
		"scanner_primary"
	],
	sync_modes: [
		"off",
		"local-overlay"
	],
	subcommands: [
		"install-check",
		"benchmark",
		"audit-baseline",
		"capabilities"
	],
	ecosystems: [
		"OpenClaw",
		"ClawHub",
		"local agent repos"
	]
};
var interfaces = {
	finding_extensions: [
		"source_layer",
		"evidence_class",
		"confidence",
		"fp_suspected",
		"explainability",
		"suppression_reason"
	],
	plugin_contract: {
		before_tool_call: {
			supports_block: true,
			modes: [
				"monitor",
				"enforce",
				"strict"
			],
			default_coexistence_mode: "rampart_primary",
			default_sync_mode: "local-overlay"
		}
	}
};
var competitive_landscape = {
	direct: [
		"hbg-scan",
		"snyk/agent-scan"
	],
	adjacent: [
		"agentic-radar",
		"promptfoo",
		"garak"
	],
	perimeter: [
		"modelscan"
	],
	axes: [
		"discovery_coverage",
		"runtime_enforcement",
		"false_positive_control",
		"reportability",
		"mcp_skill_awareness",
		"local_offline_operability",
		"evidence_reproducibility"
	]
};
var source_of_truth = {
	generated_from_code: false,
	notes: [
		"This file is the release-facing source of truth for versioned claims.",
		"Counts reflect the current codebase, not historical roadmap numbers."
	]
};
var capabilities$1 = {
	schema_version: schema_version,
	product: product,
	capabilities: capabilities,
	interfaces: interfaces,
	competitive_landscape: competitive_landscape,
	source_of_truth: source_of_truth
};

type GuardScannerCapabilities = typeof capabilities$1;
declare const CAPABILITIES: GuardScannerCapabilities;
declare function getCapabilitySummary(): string;

export { CAPABILITIES, type GuardScannerCapabilities, getCapabilitySummary };
