import { c as Finding } from './types-DkNB1BjH.mjs';

type RustScoreResult = {
    engine: 'rust';
    risk: number;
    degradedCount: number;
    note?: string;
};
declare function scoreWithRust(findings: Finding[]): RustScoreResult | null;

export { type RustScoreResult, scoreWithRust };
