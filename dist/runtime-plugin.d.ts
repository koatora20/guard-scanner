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
export type RuntimePluginConfig = {
    mode?: GuardMode;
    enableAuditLog?: boolean;
    auditDir?: string;
    suiteTokenPath?: string;
    configPath?: string;
};
export default function runtimeGuardPlugin(api: PluginAPI, config?: RuntimePluginConfig): void;
export {};
//# sourceMappingURL=runtime-plugin.d.ts.map