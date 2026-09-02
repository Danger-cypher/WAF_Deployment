/**
 * The optimistic, per-event increment applied to Overview's KPI cards as
 * each new blocked request arrives over the live WebSocket stream —
 * pulled out as a pure function so it's unit-testable without mounting
 * the full Overview page (see Overview.kpiPrefs.test.jsx's own note on
 * why that page isn't mounted in tests: a dozen unrelated API calls to
 * mock for one behavior).
 *
 * Mirrors clickhouse_service.get_stats' own predicates exactly —
 * BLOCKED_HTTP_CODES and the sqli/xss attack_type match — so the live
 * nudge and the authoritative poll that reconciles it agree on what
 * counts.
 */
export const BLOCKED_HTTP_CODES = new Set(['401', '403', '405', '406', '415', '429', '444']);

/**
 * @param {object} prevStats - current stats state
 * @param {object} logEventData - the `data` payload of a `{type:"log"}` WS message
 * @returns {object} a new stats object, or `prevStats` unchanged if this
 *   event isn't a blocked request (nothing to count).
 */
export function applyLiveStatsBump(prevStats, logEventData) {
  const httpCode = String(logEventData?.http_code);
  if (!BLOCKED_HTTP_CODES.has(httpCode)) return prevStats;

  const attackType = (logEventData?.attack_type || '').toLowerCase();
  return {
    ...prevStats,
    total_requests: prevStats.total_requests + 1,
    total_blocked: prevStats.total_blocked + 1,
    sqli_count: prevStats.sqli_count + (attackType === 'sql injection' ? 1 : 0),
    xss_count: prevStats.xss_count + (attackType === 'xss' ? 1 : 0),
  };
}
