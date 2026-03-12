"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CAPABILITIES = void 0;
exports.getCapabilitySummary = getCapabilitySummary;
const capabilities_json_1 = __importDefault(require("../docs/spec/capabilities.json"));
exports.CAPABILITIES = capabilities_json_1.default;
function getCapabilitySummary() {
    return [
        `${exports.CAPABILITIES.capabilities.pattern_count} patterns`,
        `${exports.CAPABILITIES.capabilities.category_count} categories`,
        `${exports.CAPABILITIES.capabilities.runtime_check_count} runtime checks`,
    ].join(' / ');
}
//# sourceMappingURL=capabilities.js.map