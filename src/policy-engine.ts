// @ts-nocheck
class PolicyEngine {
    constructor(config = { mode: 'enforce' }) {
        this.mode = config.mode;
        this.policy = config.policy || {};
    }

    evaluate(toolName, args) {
        if (this.mode === 'monitor') {
            return {
                action: 'allow',
                reason: 'monitor mode',
                policyId: 'policy.monitor-mode',
                amplificationReasons: [],
                remediationSuggestion: 'Switch to enforce or strict mode to turn policy decisions into hard blocks.',
            };
        }

        const argsStr = JSON.stringify(args || {});
        const normalized = argsStr.toLowerCase();
        const allowedTools = Array.isArray(this.policy.allowed_tools) ? new Set(this.policy.allowed_tools) : null;
        const blockedTools = new Set(Array.isArray(this.policy.blocked_tools) ? this.policy.blocked_tools : []);
        const amplificationReasons = [];

        if (blockedTools.has(toolName)) {
            return {
                action: 'block',
                reason: `tool "${toolName}" is explicitly blocked by policy`,
                policyId: this.policy.id || 'policy.blocked-tool',
                amplificationReasons,
                remediationSuggestion: `Remove "${toolName}" from blocked_tools or route the task through an allowlisted alternative.`,
            };
        }

        if (allowedTools && allowedTools.size > 0 && !allowedTools.has(toolName)) {
            return {
                action: 'block',
                reason: `tool "${toolName}" is outside the allowlist`,
                policyId: this.policy.id || 'policy.allowlist-only',
                amplificationReasons,
                remediationSuggestion: `Add "${toolName}" to allowed_tools only if the session genuinely requires it.`,
            };
        }

        const networkIntent = /(curl|wget|fetch\s*\(|https?:\/\/|websocket|webhook|socket)/i.test(normalized);
        if (networkIntent && this.policy.max_network_scope === 'none') {
            return {
                action: 'block',
                reason: 'network egress is disabled for this session',
                policyId: this.policy.id || 'policy.network-none',
                amplificationReasons: ['network request detected under max_network_scope=none'],
                remediationSuggestion: 'Remove the network call or raise max_network_scope after human review.',
            };
        }

        if (networkIntent && this.policy.max_network_scope === 'internal-only' && /(https?:\/\/)(?!127\.0\.0\.1|localhost)/i.test(normalized)) {
            return {
                action: 'block',
                reason: 'external network egress exceeds the internal-only policy',
                policyId: this.policy.id || 'policy.network-internal-only',
                amplificationReasons: ['external URL detected while internal-only policy is active'],
                remediationSuggestion: 'Restrict the target to localhost/internal endpoints or widen the policy after review.',
            };
        }

        if (this.policy.secret_bearing_context && networkIntent && /(token|secret|password|api[_-]?key|authorization|cookie|session)/i.test(normalized)) {
            amplificationReasons.push('secret-bearing context combined with outbound network intent');
        }

        if (this.policy.memory_write_permission === false && /(memory|episodes|notes|guava_memory_write|memory_store)/i.test(normalized) && /(write|append|edit|>|apply_patch)/i.test(normalized)) {
            return {
                action: 'block',
                reason: 'memory writes are disabled for this session',
                policyId: this.policy.id || 'policy.memory-write-disabled',
                amplificationReasons,
                remediationSuggestion: 'Use read-only memory/search flow or explicitly enable memory_write_permission.',
            };
        }

        // Destructive FS operations
        if ((toolName === 'run_shell_command' || toolName === 'shell' || toolName === 'exec') && (normalized.includes('rm -rf') || normalized.includes('mkfs'))) {
            return {
                action: 'block',
                reason: 'destructive fs operation',
                policyId: this.policy.id || 'policy.destructive-fs',
                amplificationReasons,
                remediationSuggestion: 'Replace the destructive operation with a bounded file change or explicit human-approved rollback path.',
            };
        }

        // Credential access
        if ((toolName === 'read_file' || toolName === 'fs.read') && (normalized.includes('.env') || normalized.includes('secret') || normalized.includes('.aws'))) {
            return {
                action: 'block',
                reason: 'credential read operation',
                policyId: this.policy.id || 'policy.credential-read',
                amplificationReasons,
                remediationSuggestion: 'Replace direct credential reads with scoped secret injection or redacted fixtures.',
            };
        }

        // Unrestricted network
        if ((toolName === 'run_shell_command' || toolName === 'shell' || toolName === 'exec') && (normalized.includes('curl') || normalized.includes('wget')) && normalized.includes('| bash')) {
            return {
                action: 'block',
                reason: 'unrestricted network execution (curl|bash)',
                policyId: this.policy.id || 'policy.curl-bash',
                amplificationReasons,
                remediationSuggestion: 'Fetch the artifact separately, verify its digest, then execute from a reviewed local path.',
            };
        }

        return {
            action: 'allow',
            reason: 'safe operation within active policy bounds',
            policyId: this.policy.id || 'policy.default-allow',
            amplificationReasons,
            remediationSuggestion: 'No policy remediation required.',
        };
    }
}

export {  PolicyEngine  };
