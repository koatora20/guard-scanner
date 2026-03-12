import { createRequire } from "node:module";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";

const require = createRequire(import.meta.url);
const runtimeGuard = require("../src/runtime-guard.js") as {
    scanToolCall: (
        toolName: string,
        params: Record<string, unknown>,
        options?: {
            mode?: "monitor" | "enforce" | "strict";
            auditLog?: boolean;
            sessionKey?: string;
            sessionId?: string;
            runId?: string;
            toolCallId?: string;
            agentId?: string;
        },
    ) => {
        blocked: boolean;
        blockReason: string | null;
    };
};

type GuardMode = "monitor" | "enforce" | "strict";
type PluginHookBeforeToolCallEvent = {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
};
type PluginHookToolContext = {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    toolName: string;
    toolCallId?: string;
};

function resolveMode(pluginConfig?: Record<string, unknown>): GuardMode | undefined {
    const mode = pluginConfig?.mode;
    if (mode === "monitor" || mode === "enforce" || mode === "strict") {
        return mode;
    }
    return undefined;
}

function resolveAuditLog(pluginConfig?: Record<string, unknown>): boolean {
    return pluginConfig?.auditLog !== false;
}

function beforeToolCall(
    event: PluginHookBeforeToolCallEvent,
    ctx: PluginHookToolContext,
    api: OpenClawPluginApi,
) {
    const result = runtimeGuard.scanToolCall(event.toolName, event.params, {
        mode: resolveMode(api.pluginConfig),
        auditLog: resolveAuditLog(api.pluginConfig),
        sessionKey: ctx.sessionKey,
        sessionId: ctx.sessionId,
        runId: ctx.runId ?? event.runId,
        toolCallId: ctx.toolCallId ?? event.toolCallId,
        agentId: ctx.agentId,
    });

    if (!result.blocked) return;
    return {
        block: true,
        blockReason: result.blockReason ?? "guard-scanner blocked the tool call.",
    };
}

const plugin = {
    id: "guard-scanner",
    name: "guard-scanner",
    version: "15.0.0",
    description: "Runtime guard for OpenClaw before_tool_call hook execution.",
    register(api: OpenClawPluginApi) {
        api.on(
            "before_tool_call",
            (event: PluginHookBeforeToolCallEvent, ctx: PluginHookToolContext) => beforeToolCall(event, ctx, api),
            { priority: 90 },
        );
        api.logger.info(
            "guard-scanner registered OpenClaw before_tool_call hook (validated for v2026.3.8).",
        );
    },
};

export default plugin;
