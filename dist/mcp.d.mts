import { M as McpRequest, f as ScannerOptions, J as JSONReport } from './types-DkNB1BjH.mjs';

type JsonRpcId = string | number | null;
type JsonRpcResponse = {
    jsonrpc: "2.0";
    id: JsonRpcId;
    result?: unknown;
    error?: {
        code: number;
        message: string;
    };
};
type ScanParams = ScannerOptions & {
    path: string;
};
declare function runMcpScan(params: ScanParams): JSONReport;
declare function handleMcpRequest(request: McpRequest): JsonRpcResponse;

export { handleMcpRequest, runMcpScan };
