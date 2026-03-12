import capabilities from '../docs/spec/capabilities.json';

export type GuardScannerCapabilities = typeof capabilities;

export const CAPABILITIES: GuardScannerCapabilities = capabilities;

export function getCapabilitySummary(): string {
    return [
        `${CAPABILITIES.capabilities.pattern_count} patterns`,
        `${CAPABILITIES.capabilities.category_count} categories`,
        `${CAPABILITIES.capabilities.runtime_check_count} runtime checks`,
    ].join(' / ');
}

