/**
 * A2UI + AG-UI Module Tests — TDD Red Phase
 * 
 * 5 suites, ~26 tests
 * Tests written BEFORE implementation (Red → Green → Refactor)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');

const SKILLS_DIR = path.join(os.homedir(), '.openclaw/workspace/skills');
const PROJECTS_DIR = path.join(os.homedir(), '.openclaw/workspace/projects');

// ═══════════════════════════════════════════════════════════════════
// Suite 1: A2UI Payload Generator (v0.9 spec) — 8 tests
// ═══════════════════════════════════════════════════════════════════

const {
    createSurface,
    updateComponents,
    updateDataModel,
    deleteSurface,
    A2UI_MSG,
} = require('../src/a2ui-payload.js');

const {
    SkillCatalog,
    ProjectInventory,
    ComparisonEngine,
} = require('../src/project-manager.js');

function loadLiveData() {
    const cat = new SkillCatalog();
    const inv = new ProjectInventory();
    cat.loadFromDisk(SKILLS_DIR);
    inv.loadFromDisk(PROJECTS_DIR);
    const cmp = new ComparisonEngine(cat, inv);
    return cmp.generateReport();
}

describe('A2UI Payload — v0.9 Spec', () => {
    it('createSurface returns valid A2UI message with surfaceId', () => {
        const msg = createSurface('gpi-dashboard');
        assert.equal(msg.type, 'createSurface');
        assert.equal(msg.surfaceId, 'gpi-dashboard');
        assert.ok(msg.metadata, 'Should have metadata');
    });

    it('updateComponents generates flat adjacency list', () => {
        const report = loadLiveData();
        const msg = updateComponents('gpi-dashboard', report);
        assert.equal(msg.type, 'updateComponents');
        assert.equal(msg.surfaceId, 'gpi-dashboard');
        assert.ok(Array.isArray(msg.components), 'Components should be array');
        assert.ok(msg.components.length > 0, 'Should have components');
    });

    it('components have id, type, and props', () => {
        const report = loadLiveData();
        const msg = updateComponents('gpi-dashboard', report);
        for (const c of msg.components) {
            assert.ok(c.id, `Component missing id: ${JSON.stringify(c)}`);
            assert.ok(c.type, `Component missing type: ${c.id}`);
            assert.ok(c.props !== undefined, `Component missing props: ${c.id}`);
        }
    });

    it('components include dominance score metric', () => {
        const report = loadLiveData();
        const msg = updateComponents('gpi-dashboard', report);
        const dom = msg.components.find(c => c.id === 'dominance-score');
        assert.ok(dom, 'Should have dominance-score component');
        assert.equal(dom.type, 'metric');
        assert.ok(dom.props.value > 500, 'Score should be > 500');
    });

    it('updateDataModel contains skills and projects', () => {
        const report = loadLiveData();
        const msg = updateDataModel('gpi-dashboard', report);
        assert.equal(msg.type, 'updateDataModel');
        assert.ok(msg.dataModel.skills, 'Should have skills data');
        assert.ok(msg.dataModel.projects, 'Should have projects data');
    });

    it('deleteSurface is valid', () => {
        const msg = deleteSurface('gpi-dashboard');
        assert.equal(msg.type, 'deleteSurface');
        assert.equal(msg.surfaceId, 'gpi-dashboard');
    });

    it('A2UI_MSG constants match v0.9 spec', () => {
        assert.equal(A2UI_MSG.CREATE_SURFACE, 'createSurface');
        assert.equal(A2UI_MSG.UPDATE_COMPONENTS, 'updateComponents');
        assert.equal(A2UI_MSG.UPDATE_DATA_MODEL, 'updateDataModel');
        assert.equal(A2UI_MSG.DELETE_SURFACE, 'deleteSurface');
    });

    it('all components pass guard-scanner injection check', () => {
        const { scanForInjection } = require('../src/project-manager.js');
        const report = loadLiveData();
        const msg = updateComponents('gpi-dashboard', report);
        const json = JSON.stringify(msg);
        const scan = scanForInjection(json);
        assert.ok(scan.safe, `Injection detected: ${JSON.stringify(scan.matches)}`);
    });
});

// ═══════════════════════════════════════════════════════════════════
// Suite 2: AG-UI Events — 6 tests
// ═══════════════════════════════════════════════════════════════════

const {
    AGUI_EVENT,
    createEvent,
    serializeEvent,
} = require('../src/agui-events.js');

describe('AG-UI Events', () => {
    it('AGUI_EVENT has all 5 lifecycle types', () => {
        assert.ok(AGUI_EVENT.RUN_STARTED);
        assert.ok(AGUI_EVENT.STEP_STARTED);
        assert.ok(AGUI_EVENT.STEP_FINISHED);
        assert.ok(AGUI_EVENT.RUN_FINISHED);
        assert.ok(AGUI_EVENT.RUN_ERROR);
    });

    it('AGUI_EVENT has state types', () => {
        assert.ok(AGUI_EVENT.STATE_SNAPSHOT);
        assert.ok(AGUI_EVENT.STATE_DELTA);
    });

    it('createEvent returns valid event object', () => {
        const event = createEvent(AGUI_EVENT.RUN_STARTED, { runId: 'test-run' });
        assert.equal(event.type, 'RUN_STARTED');
        assert.equal(event.runId, 'test-run');
        assert.ok(event.timestamp, 'Should have timestamp');
    });

    it('serializeEvent returns valid JSON string', () => {
        const event = createEvent(AGUI_EVENT.STATE_SNAPSHOT, { data: { x: 1 } });
        const json = serializeEvent(event);
        const parsed = JSON.parse(json);
        assert.equal(parsed.type, 'STATE_SNAPSHOT');
    });

    it('STATE_SNAPSHOT event contains data field', () => {
        const data = { dominanceScore: 532.48, skills: { total: 84 } };
        const event = createEvent(AGUI_EVENT.STATE_SNAPSHOT, { data });
        assert.deepStrictEqual(event.data, data);
    });

    it('event timestamp is ISO 8601', () => {
        const event = createEvent(AGUI_EVENT.RUN_STARTED, {});
        assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(event.timestamp), 'Timestamp should be ISO 8601');
    });
});

// ═══════════════════════════════════════════════════════════════════
// Suite 3: A2UI Server — HTTP API — 5 tests
// ═══════════════════════════════════════════════════════════════════

const { createA2UIServer } = require('../src/a2ui-server.js');
const http = require('node:http');

describe('A2UI Server — HTTP API', () => {
    let server;
    const TEST_PORT = 29793;

    it('server starts on configured port', async () => {
        server = createA2UIServer({ port: TEST_PORT, wsPort: TEST_PORT + 1, skillsDir: SKILLS_DIR, projectsDir: PROJECTS_DIR });
        await new Promise((resolve) => server.httpServer.listen(TEST_PORT, resolve));
        assert.ok(server.httpServer.listening, 'Server should be listening');
    });

    it('GET /api/data returns JSON with dominanceScore', async () => {
        const data = await httpGet(`http://localhost:${TEST_PORT}/api/data`);
        const json = JSON.parse(data);
        assert.ok(json.dominanceScore, 'Should have dominanceScore');
        assert.ok(json.gpi, 'Should have gpi');
        assert.ok(json.gpi.totalSkills, 'Should have totalSkills');
    });

    it('GET /api/a2ui returns A2UI surface', async () => {
        const data = await httpGet(`http://localhost:${TEST_PORT}/api/a2ui`);
        const json = JSON.parse(data);
        assert.equal(json.type, 'updateComponents');
        assert.ok(Array.isArray(json.components));
    });

    it('GET / returns HTML with WebSocket client', async () => {
        const html = await httpGet(`http://localhost:${TEST_PORT}/`);
        assert.ok(html.includes('<!DOCTYPE html'), 'Should return HTML');
        assert.ok(html.includes('WebSocket'), 'Should inject WebSocket client');
    });

    it('GET /unknown returns 404', async () => {
        try {
            await httpGet(`http://localhost:${TEST_PORT}/unknown`);
            assert.fail('Should have thrown');
        } catch (e) {
            assert.equal(e.statusCode, 404);
        }
    });

    // Cleanup
    it('server stops cleanly', async () => {
        server.httpServer.close();
        server.wss.close();
        assert.ok(true);
    });
});

// Helper
function httpGet(url) {
    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            if (res.statusCode >= 400) {
                const err = new Error(`HTTP ${res.statusCode}`);
                err.statusCode = res.statusCode;
                reject(err);
                return;
            }
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => resolve(data));
        }).on('error', reject);
    });
}

// ═══════════════════════════════════════════════════════════════════
// Suite 4: A2UI Server — WebSocket — 4 tests
// ═══════════════════════════════════════════════════════════════════

describe('A2UI Server — WebSocket Events', () => {
    let server;
    const WS_PORT_TEST = 29895;

    it('WebSocket server accepts connections', async () => {
        server = createA2UIServer({ port: WS_PORT_TEST - 1, wsPort: WS_PORT_TEST, skillsDir: SKILLS_DIR, projectsDir: PROJECTS_DIR });
        await new Promise((resolve) => server.httpServer.listen(WS_PORT_TEST - 1, resolve));
        // WebSocket server starts automatically — just verify it exists
        assert.ok(server.wss, 'Should have WebSocket server');
    });

    it('WebSocket sends RUN_STARTED on connect', async () => {
        const WebSocket = require('ws');
        const ws = new WebSocket(`ws://localhost:${WS_PORT_TEST}`);
        const msg = await new Promise((resolve) => {
            ws.on('message', (data) => resolve(JSON.parse(data.toString())));
        });
        assert.equal(msg.type, 'RUN_STARTED');
        ws.close();
    });

    it('WebSocket sends STATE_SNAPSHOT after RUN_STARTED', async () => {
        const WebSocket = require('ws');
        const ws = new WebSocket(`ws://localhost:${WS_PORT_TEST}`);
        const msgs = [];
        await new Promise((resolve) => {
            ws.on('message', (data) => {
                msgs.push(JSON.parse(data.toString()));
                if (msgs.length >= 2) resolve();
            });
        });
        assert.equal(msgs[1].type, 'STATE_SNAPSHOT');
        assert.ok(msgs[1].data, 'STATE_SNAPSHOT should have data');
        ws.close();
    });

    it('STATE_SNAPSHOT data has live skill count', async () => {
        const WebSocket = require('ws');
        const ws = new WebSocket(`ws://localhost:${WS_PORT_TEST}`);
        const msgs = [];
        await new Promise((resolve) => {
            ws.on('message', (data) => {
                msgs.push(JSON.parse(data.toString()));
                if (msgs.length >= 2) resolve();
            });
        });
        assert.ok(msgs[1].data.gpi.totalSkills >= 80, 'Should have 80+ skills');
        ws.close();
        // Cleanup
        server.httpServer.close();
        server.wss.close();
    });
});

// ═══════════════════════════════════════════════════════════════════
// Suite 5: Integration — Live Data — 3 tests
// ═══════════════════════════════════════════════════════════════════

describe('Integration — Live Data Flow', () => {
    it('full pipeline: load → A2UI surface → valid JSON', () => {
        const report = loadLiveData();
        const surface = createSurface('test');
        const components = updateComponents('test', report);
        const dataModel = updateDataModel('test', report);

        // All valid JSON
        assert.ok(JSON.stringify(surface));
        assert.ok(JSON.stringify(components));
        assert.ok(JSON.stringify(dataModel));
    });

    it('A2UI + AG-UI combined payload is under 50KB', () => {
        const report = loadLiveData();
        const components = updateComponents('gpi-dashboard', report);
        const event = createEvent(AGUI_EVENT.STATE_SNAPSHOT, { data: report });
        const totalBytes = Buffer.byteLength(JSON.stringify(components)) + Buffer.byteLength(serializeEvent(event));
        assert.ok(totalBytes < 50000, `Payload too large: ${totalBytes} bytes`);
    });

    it('pipelines count matches GPI_PIPELINES', () => {
        const { GPI_PIPELINES } = require('../src/project-manager.js');
        const report = loadLiveData();
        const components = updateComponents('gpi-dashboard', report);
        const pipelineComponents = components.components.filter(c => c.id.startsWith('pipeline-'));
        assert.equal(pipelineComponents.length, GPI_PIPELINES.length, 'Pipeline count should match');
    });
});
