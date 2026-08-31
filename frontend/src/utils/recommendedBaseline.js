// Recommended-baseline reference values (P2 item 8 of the WAAP console
// teardown roadmap). See RecommendedFlag.jsx's own docstring for why this
// is deliberately scoped to settings where "more secure" has no real
// operational downside, not a blanket "everything should be on" list.
//
// Split out of RecommendedFlag.jsx (rather than co-located with the
// component that consumes it) for the same reason kpiPrefs.js is split
// from Overview.jsx — a component file may only export components under
// Vite's fast-refresh rule.
export const RECOMMENDED_BASELINE = {
  waf: { secRuleEngine: 'On', detectionMode: 'Blocking' },
  logs: { auditEnabled: true },
  hardening: { hsts_enabled: true, server_cloaking: true },
};
