import type { Finding } from './types.js';
export type RustScoreResult = {
    engine: 'rust';
    risk: number;
    degradedCount: number;
    note?: string;
};
export declare function scoreWithRust(findings: Finding[]): RustScoreResult | null;
//# sourceMappingURL=rust-bridge.d.ts.map