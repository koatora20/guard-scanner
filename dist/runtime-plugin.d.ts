import { m as PluginConfig$1, n as RuntimeDecision$1 } from './types-DkNB1BjH.js';

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
    on(hookName: "before_tool_call", handler: (event: PluginHookBeforeToolCallEvent, ctx: PluginHookToolContext) => PluginHookBeforeToolCallResult | void | Promise<PluginHookBeforeToolCallResult | void>): void;
    logger: {
        info: (msg: string) => void;
        warn: (msg: string) => void;
        error: (msg: string) => void;
    };
};
type GuardMode = "monitor" | "enforce" | "strict";
type CoexistenceMode = "independent" | "rampart_primary" | "scanner_primary";
type SyncMode = "off" | "local-overlay";
type RuntimePluginConfig = PluginConfig$1;
type PluginConfig = RuntimePluginConfig;
type RuntimeDecision = RuntimeDecision$1;
type RuntimeGuardState = {
    requestedMode: GuardMode;
    effectiveMode: GuardMode;
    coexistenceMode: CoexistenceMode;
    runtimeAuthority: "rampart" | "guard-scanner";
    evidenceOnly: boolean;
    syncMode: SyncMode;
    sharedRunIdEnabled: boolean;
    correlationId?: string;
};
declare function computeRuntimeGuardState(config?: RuntimePluginConfig): RuntimeGuardState;
declare function buildAuditEntry(event: PluginHookBeforeToolCallEvent, ctx: PluginHookToolContext, state: RuntimeGuardState, check: {
    id: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    desc: string;
}, action: "warned" | "blocked"): Record<string, unknown>;
declare function runtimeGuardPlugin(api: PluginAPI, config?: RuntimePluginConfig): void;

export { type PluginConfig, type RuntimeDecision, type RuntimeGuardState, type RuntimePluginConfig, buildAuditEntry, computeRuntimeGuardState, runtimeGuardPlugin as default };
