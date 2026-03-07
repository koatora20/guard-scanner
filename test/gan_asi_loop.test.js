const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { MCPServer } = require('../src/mcp-server.js');

function getTaskIdFromText(text) {
  const line = String(text).split('\n').find((l) => l.startsWith('taskId='));
  return line ? line.split('=')[1] : '';
}

describe('ASI-GAN TDD Loop (3 loops)', () => {
  it('Loop 1 / Discriminator: reject malformed cron expression', async () => {
    const server = new MCPServer();
    const out = [];
    server._send = (msg) => out.push(msg);

    await server._handleMessage({
      jsonrpc: '2.0',
      id: 701,
      method: 'tools/call',
      params: {
        name: 'cron_glm5_config',
        arguments: { name: 'bad', cron: '*/5 * *', message: 'x' },
      },
    });

    assert.equal(out.length, 1);
    assert.equal(out[0].result.isError, true);
    assert.ok(out[0].result.content[0].text.includes('cron must be 5 fields'));
  });

  it('Loop 2 / Generator constraint: cron config pins model to zai/glm-5', async () => {
    const server = new MCPServer();
    const out = [];
    server._send = (msg) => out.push(msg);

    await server._handleMessage({
      jsonrpc: '2.0',
      id: 702,
      method: 'tools/call',
      params: {
        name: 'cron_glm5_config',
        arguments: {
          name: 'nightly',
          cron: '0 3 * * *',
          tz: 'Asia/Tokyo',
          message: 'model=other should be ignored',
        },
      },
    });

    const text = out[0].result.content[0].text;
    assert.ok(text.includes('zai/glm-5'));
    assert.ok(text.includes('openclaw cron add'));
  });

  it('Loop 3 / Closed-loop runtime: run_async -> status/result converges', async () => {
    const server = new MCPServer();
    const out = [];
    server._send = (msg) => out.push(msg);

    await server._handleMessage({
      jsonrpc: '2.0',
      id: 703,
      method: 'tools/call',
      params: { name: 'run_async', arguments: { tool: 'get_stats', args: {} } },
    });

    const text = out[0].result.content[0].text;
    const taskId = getTaskIdFromText(text);
    assert.ok(taskId.length > 0);

    await new Promise((r) => setTimeout(r, 40));

    await server._handleMessage({
      jsonrpc: '2.0',
      id: 704,
      method: 'tools/call',
      params: { name: 'task_result', arguments: { taskId } },
    });

    const resText = out[out.length - 1].result.content[0].text;
    assert.ok(resText.includes('guard-scanner'));
  });
});
