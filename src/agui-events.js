/**
 * AG-UI Event Module — Agent-User Interaction Protocol
 * CopilotKit compatible, 16 event types
 * UNIX philosophy: 1 module = 1 responsibility (event creation + serialization)
 * 
 * @version 1.0.0
 */

// ─── AG-UI Event Types (CopilotKit v1.50 spec) ─────────────────────

const AGUI_EVENT = Object.freeze({
    // Lifecycle
    RUN_STARTED: 'RUN_STARTED',
    STEP_STARTED: 'STEP_STARTED',
    STEP_FINISHED: 'STEP_FINISHED',
    RUN_FINISHED: 'RUN_FINISHED',
    RUN_ERROR: 'RUN_ERROR',
    // Text
    TEXT_MESSAGE_START: 'TEXT_MESSAGE_START',
    TEXT_MESSAGE_CONTENT: 'TEXT_MESSAGE_CONTENT',
    TEXT_MESSAGE_END: 'TEXT_MESSAGE_END',
    // Tool
    TOOL_CALL_START: 'TOOL_CALL_START',
    TOOL_CALL_ARGS: 'TOOL_CALL_ARGS',
    TOOL_CALL_END: 'TOOL_CALL_END',
    TOOL_CALL_RESULT: 'TOOL_CALL_RESULT',
    // State
    STATE_SNAPSHOT: 'STATE_SNAPSHOT',
    STATE_DELTA: 'STATE_DELTA',
    MESSAGES_SNAPSHOT: 'MESSAGES_SNAPSHOT',
    // Special
    RAW: 'RAW',
    CUSTOM: 'CUSTOM',
});

// ─── Event Factory ──────────────────────────────────────────────────

/**
 * Create an AG-UI event object.
 * @param {string} type - One of AGUI_EVENT values
 * @param {object} payload - Event-specific data
 * @returns {object} AG-UI event
 */
function createEvent(type, payload = {}) {
    if (!Object.values(AGUI_EVENT).includes(type)) {
        throw new Error(`Unknown AG-UI event type: ${type}`);
    }
    return {
        type,
        timestamp: new Date().toISOString(),
        ...payload,
    };
}

/**
 * Serialize an AG-UI event to JSON string.
 * @param {object} event
 * @returns {string}
 */
function serializeEvent(event) {
    return JSON.stringify(event);
}

// ─── Exports ────────────────────────────────────────────────────────

module.exports = {
    AGUI_EVENT,
    createEvent,
    serializeEvent,
};
