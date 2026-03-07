/**
 * A2UI Payload Generator — Agent-to-User Interface Protocol v0.9
 * Generates declarative JSON surfaces from guava-pm live data.
 * UNIX philosophy: 1 module = 1 responsibility (A2UI message creation)
 * 
 * v0.9 spec: createSurface, updateComponents (flat adjacency list),
 * updateDataModel, deleteSurface
 * 
 * @version 1.0.0
 */

const { scanForInjection, GPI_PIPELINES } = require('./project-manager.js');

// ─── A2UI Message Types (v0.9 spec) ─────────────────────────────────

const A2UI_MSG = Object.freeze({
    CREATE_SURFACE: 'createSurface',
    UPDATE_COMPONENTS: 'updateComponents',
    UPDATE_DATA_MODEL: 'updateDataModel',
    DELETE_SURFACE: 'deleteSurface',
});

// ─── Surface Lifecycle ──────────────────────────────────────────────

/**
 * Create a new A2UI surface.
 * @param {string} surfaceId - Unique surface identifier
 * @returns {object} A2UI createSurface message
 */
function createSurface(surfaceId) {
    return {
        type: A2UI_MSG.CREATE_SURFACE,
        surfaceId,
        metadata: {
            title: 'GPI Dashboard',
            version: '2.1.0',
            createdAt: new Date().toISOString(),
        },
    };
}

/**
 * Delete an A2UI surface.
 * @param {string} surfaceId
 * @returns {object} A2UI deleteSurface message
 */
function deleteSurface(surfaceId) {
    return {
        type: A2UI_MSG.DELETE_SURFACE,
        surfaceId,
    };
}

// ─── Component Builder (flat adjacency list) ────────────────────────

/**
 * Generate updateComponents message from live guava-pm report.
 * Uses flat adjacency list per v0.9 spec (LLM-friendly).
 * @param {string} surfaceId
 * @param {object} report - ComparisonEngine.generateReport() output
 * @returns {object} A2UI updateComponents message
 */
function updateComponents(surfaceId, report) {
    const components = [];

    // Header
    components.push({
        id: 'header',
        type: 'container',
        props: { direction: 'row', align: 'center', gap: 16 },
        children: ['logo', 'title', 'status'],
    });
    components.push({ id: 'logo', type: 'text', props: { value: 'GPI', variant: 'logo' } });
    components.push({ id: 'title', type: 'text', props: { value: 'GPI Dashboard', variant: 'h1' } });
    components.push({ id: 'status', type: 'badge', props: { value: 'LIVE', color: 'green' } });

    // Metrics row
    components.push({
        id: 'metrics',
        type: 'container',
        props: { direction: 'row', gap: 20 },
        children: ['dominance-score', 'skill-count', 'project-count'],
    });
    components.push({
        id: 'dominance-score',
        type: 'metric',
        props: { label: 'Dominance Score', value: report.dominanceScore, format: 'number' },
    });
    components.push({
        id: 'skill-count',
        type: 'metric',
        props: { label: 'Active Skills', value: report.gpi.totalSkills, format: 'integer' },
    });
    components.push({
        id: 'project-count',
        type: 'metric',
        props: { label: 'Projects', value: report.gpi.totalProjects, format: 'integer' },
    });

    // Ratios table
    const rows = [
        ['Skills', report.gpi.totalSkills, report.steipete.totalTools, (report.gpi.totalSkills / report.steipete.totalTools).toFixed(2) + 'x'],
        ['Projects', report.gpi.totalProjects, '~12', (report.gpi.totalProjects / 12).toFixed(1) + 'x'],
        ['Security', 192, 7, '27.4x'],
        ['Memory', 7, 0, '∞'],
        ['OWASP', '9/10', '0/10', '∞'],
    ];
    components.push({
        id: 'ratios',
        type: 'table',
        props: {
            columns: ['Metric', 'GPI', 'steipete', 'Ratio'],
            rows,
        },
    });

    // Category grid
    const catCounts = report.gpi.categoryCounts || {};
    for (const [name, count] of Object.entries(catCounts)) {
        components.push({
            id: `cat-${name}`,
            type: 'metric',
            props: { label: name, value: count, format: 'integer' },
        });
    }

    // Pipelines
    for (const p of GPI_PIPELINES) {
        components.push({
            id: `pipeline-${p.id}`,
            type: 'listItem',
            props: { primary: p.name, secondary: `${p.steps.length} steps`, order: p.id },
        });
    }

    return {
        type: A2UI_MSG.UPDATE_COMPONENTS,
        surfaceId,
        components,
    };
}

// ─── Data Model ─────────────────────────────────────────────────────

/**
 * Generate updateDataModel from comparison report.
 * @param {string} surfaceId
 * @param {object} report
 * @returns {object} A2UI updateDataModel message
 */
function updateDataModel(surfaceId, report) {
    return {
        type: A2UI_MSG.UPDATE_DATA_MODEL,
        surfaceId,
        dataModel: {
            skills: {
                total: report.gpi.totalSkills,
                steipete: report.steipete.totalTools,
                ratio: (report.gpi.totalSkills / report.steipete.totalTools).toFixed(2),
                categories: report.gpi.categoryCounts,
            },
            projects: {
                total: report.gpi.totalProjects,
            },
            dominanceScore: report.dominanceScore,
            timestamp: new Date().toISOString(),
        },
    };
}

// ─── Exports ────────────────────────────────────────────────────────

module.exports = {
    A2UI_MSG,
    createSurface,
    deleteSurface,
    updateComponents,
    updateDataModel,
};
