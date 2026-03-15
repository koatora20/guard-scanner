import capabilities from "../docs/spec/capabilities.json";
const CAPABILITIES = capabilities;
function getCapabilitySummary() {
  return [
    `${CAPABILITIES.capabilities.pattern_count} patterns`,
    `${CAPABILITIES.capabilities.category_count} categories`,
    `${CAPABILITIES.capabilities.runtime_check_count} runtime checks`
  ].join(" / ");
}
export {
  CAPABILITIES,
  getCapabilitySummary
};
//# sourceMappingURL=capabilities.mjs.map