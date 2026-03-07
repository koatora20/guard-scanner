/**
 * A2UI Server — HTTP + WebSocket (AG-UI events)
 * UNIX philosophy: 1 module = 1 responsibility (server orchestration)
 * Imports: a2ui-payload.js (surface gen), agui-events.js (event emit)
 * OpenClaw Canvas compatible (port 18793/18794)
 *
 * @version 2.0.0
 */

const http = require('node:http');
const { WebSocketServer } = require('ws');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { createSurface, updateComponents, updateDataModel, A2UI_MSG } = require('./a2ui-payload.js');
const { AGUI_EVENT, createEvent, serializeEvent } = require('./agui-events.js');
const { SkillCatalog, ProjectInventory, ComparisonEngine } = require('./project-manager.js');

// ─── Config ─────────────────────────────────────────────────────────

const DEFAULT_PORT = 18793;
const DEFAULT_WS_PORT = 18794;
const DASHBOARD_HTML_PATH = path.join(
    os.homedir(), '.gemini/antigravity/scratch/gpi-dashboard/index.html'
);

// ─── Data Loader ────────────────────────────────────────────────────

function loadReport(skillsDir, projectsDir) {
    const cat = new SkillCatalog();
    const inv = new ProjectInventory();
    cat.loadFromDisk(skillsDir);
    inv.loadFromDisk(projectsDir);
    const cmp = new ComparisonEngine(cat, inv);
    return cmp.generateReport();
}

// ─── Server Factory ─────────────────────────────────────────────────

/**
 * Create A2UI server with HTTP + WebSocket.
 * @param {object} opts
 * @returns {{ httpServer, wss }}
 */
function createA2UIServer(opts = {}) {
    const port = opts.port || DEFAULT_PORT;
    const wsPort = opts.wsPort || DEFAULT_WS_PORT;
    const skillsDir = opts.skillsDir || path.join(os.homedir(), '.openclaw/workspace/skills');
    const projectsDir = opts.projectsDir || path.join(os.homedir(), '.openclaw/workspace/projects');

    // ─── HTTP Server ────────────────────────────────────
    const httpServer = http.createServer((req, res) => {
        // GET / — Serve dashboard HTML with WS client injection
        if (req.url === '/' || req.url === '/index.html') {
            let html = '';
            try {
                html = fs.readFileSync(DASHBOARD_HTML_PATH, 'utf8');
            } catch {
                html = '<!DOCTYPE html><html><body><h1>GPI Dashboard</h1><p>HTML not found</p></body></html>';
            }

            const wsInjection = `<script>
(function(){
  var ws = new WebSocket('ws://localhost:${wsPort}');
  ws.onopen = function() {
    var el = document.getElementById('statusText');
    if(el) { el.textContent = 'LIVE'; el.style.color = '#22C55E'; }
  };
  ws.onmessage = function(e) {
    var msg = JSON.parse(e.data);
    if(msg.type === 'STATE_SNAPSHOT' || msg.type === 'STATE_DELTA') {
      if(msg.data && typeof animateCounter === 'function') {
        var d = msg.data;
        if(d.dominanceScore) animateCounter(document.getElementById('dominanceScore'), d.dominanceScore);
        if(d.gpi && d.gpi.totalSkills) animateCounter(document.getElementById('skillCount'), d.gpi.totalSkills);
        if(d.gpi && d.gpi.totalProjects) animateCounter(document.getElementById('projectCount'), d.gpi.totalProjects);
      }
    }
  };
  ws.onclose = function() {
    var el = document.getElementById('statusText');
    if(el) { el.textContent = 'RECONNECTING'; el.style.color = '#F59E0B'; }
    setTimeout(function(){ location.reload(); }, 3000);
  };
})();
</script>`;

            html = html.replace('</body>', wsInjection + '\n</body>');
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            return;
        }

        // GET /api/data — Raw JSON data
        if (req.url === '/api/data') {
            const report = loadReport(skillsDir, projectsDir);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(report));
            return;
        }

        // GET /api/a2ui — A2UI surface components
        if (req.url === '/api/a2ui') {
            const report = loadReport(skillsDir, projectsDir);
            const msg = updateComponents('gpi-dashboard', report);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(msg));
            return;
        }

        // 404
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    });

    // ─── WebSocket Server (AG-UI events) ────────────────
    const wss = new WebSocketServer({ port: wsPort });

    wss.on('connection', (ws) => {
        // RUN_STARTED
        const runEvent = createEvent(AGUI_EVENT.RUN_STARTED, { runId: 'gpi-dashboard-live' });
        ws.send(serializeEvent(runEvent));

        // STATE_SNAPSHOT with live data
        const report = loadReport(skillsDir, projectsDir);
        const snapEvent = createEvent(AGUI_EVENT.STATE_SNAPSHOT, { data: report });
        ws.send(serializeEvent(snapEvent));

        // Periodic STATE_DELTA every 10s
        const interval = setInterval(() => {
            if (ws.readyState !== ws.OPEN) { clearInterval(interval); return; }
            const fresh = loadReport(skillsDir, projectsDir);
            const deltaEvent = createEvent(AGUI_EVENT.STATE_DELTA, { data: fresh });
            ws.send(serializeEvent(deltaEvent));
        }, 10000);

        ws.on('close', () => clearInterval(interval));
    });

    return { httpServer, wss };
}

// ─── Standalone Start ───────────────────────────────────────────────

function start(opts = {}) {
    const port = opts.port || DEFAULT_PORT;
    const server = createA2UIServer(opts);
    server.httpServer.listen(port, () => {
        console.log(`\n🍈 GPI A2UI Server v2.0.0`);
        console.log(`   HTTP:      http://localhost:${port}`);
        console.log(`   WebSocket: ws://localhost:${opts.wsPort || DEFAULT_WS_PORT}`);
        console.log(`   API:       http://localhost:${port}/api/data`);
        console.log(`   A2UI:      http://localhost:${port}/api/a2ui\n`);
    });
    return server;
}

// ─── Exports ────────────────────────────────────────────────────────

module.exports = { createA2UIServer, start, DEFAULT_PORT, DEFAULT_WS_PORT };

if (require.main === module) { start(); }
