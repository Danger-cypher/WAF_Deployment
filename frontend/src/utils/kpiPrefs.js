// Configurable KPI cards — P1 item 6 of the WAAP console teardown roadmap
// (Cloudflare's custom-dashboards pattern, scaled down to "reorder/hide the
// existing 6 cards" rather than a full widget builder — the roadmap's own
// "even a simple version" framing). Each admin gets their own arrangement:
// persisted to localStorage keyed by username, not a shared/global setting,
// so it doesn't clash with the admin-only General Settings (refreshInterval
// etc.) which really is system-wide.
//
// Split out of Overview.jsx (rather than co-located with the component that
// uses it) because a page file may only export components — mixing in plain
// constants/functions there breaks Vite's fast-refresh for the whole page.
export const DEFAULT_KPI_ORDER = ['total_requests', 'blocked_threats', 'block_rate', 'sqli', 'xss', 'unique_attackers'];

export const KPI_LABELS = {
  total_requests: 'Total Requests',
  blocked_threats: 'Blocked Threats',
  block_rate: 'Block Rate',
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  unique_attackers: 'Unique Attackers',
};

function kpiPrefsKey(username) {
  return `waf_kpi_layout_v1:${username || 'anonymous'}`;
}

export function loadKpiPrefs(username) {
  try {
    const raw = localStorage.getItem(kpiPrefsKey(username));
    if (!raw) return { order: DEFAULT_KPI_ORDER, hidden: [] };
    const parsed = JSON.parse(raw);
    // Reconcile against the real card set — a card added/removed from the
    // codebase since this was saved must not silently vanish or crash the
    // page on a stale/malformed id.
    const validOrder = (parsed.order || []).filter((id) => DEFAULT_KPI_ORDER.includes(id));
    const missing = DEFAULT_KPI_ORDER.filter((id) => !validOrder.includes(id));
    const validHidden = (parsed.hidden || []).filter((id) => DEFAULT_KPI_ORDER.includes(id));
    return { order: [...validOrder, ...missing], hidden: validHidden };
  } catch {
    return { order: DEFAULT_KPI_ORDER, hidden: [] };
  }
}

export function saveKpiPrefs(username, prefs) {
  try {
    localStorage.setItem(kpiPrefsKey(username), JSON.stringify(prefs));
  } catch {
    // Private-browsing/storage-full — the layout just won't persist across
    // reloads; not worth surfacing an error for a cosmetic preference.
  }
}
