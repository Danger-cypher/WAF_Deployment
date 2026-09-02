import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle as AlertTriangleIcon, Code, Database, Globe, Lock, ShieldAlert,
  CheckCircle2, XCircle, AlertCircle, ShieldCheck, History, ArrowRight,
  SlidersHorizontal, ChevronUp, ChevronDown, RotateCcw, X as CloseIcon,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Sector,
} from 'recharts';
import {
  getStats, getTimeline, getAttackTypes, getTopIPs, getTopRules, getSeverityDistribution,
  getGeneralSettings, getHealth, getBackgroundTasksHealth, getAuditLog, getStatsTrend, getTopUris,
  getLiveStreamWsUrl,
} from '../services/api';
import { NoTrafficEmptyState, FetchErrorState } from '../components/EmptyStates';
import { DEFAULT_KPI_ORDER, KPI_LABELS, loadKpiPrefs, saveKpiPrefs } from '../utils/kpiPrefs';
import { applyLiveStatsBump } from '../utils/liveStatsBump';

function AnimatedNumber({ value = 0 }) {
  const safeValue = value || 0;
  const [displayValue, setDisplayValue] = React.useState(safeValue);

  React.useEffect(() => {
    let start = displayValue;
    const end = safeValue;
    if (start === end) return;

    const duration = 800; // ms
    const startTime = performance.now();

    let animationFrame;
    const updateNumber = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // easeOutQuad
      const easeProgress = progress * (2 - progress);
      const current = Math.floor(start + (end - start) * easeProgress);

      setDisplayValue(current);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(updateNumber);
      } else {
        setDisplayValue(end);
      }
    };

    animationFrame = requestAnimationFrame(updateNumber);
    return () => cancelAnimationFrame(animationFrame);
  }, [safeValue]);

  return <span>{(displayValue || 0).toLocaleString()}</span>;
}

// Small inline skeleton for a single section (metric card, chart, or table)
// while its own data is still in flight — scoped to just that card instead
// of blocking the whole page like the old top-level skeleton did.
function SectionSkeleton({ variant = 'card' }) {
  if (variant === 'metric') {
    return (
      <div className="animate-pulse" style={{ opacity: 0.7 }}>
        <div style={{ width: '60%', height: '28px', background: 'var(--surface-strong)', borderRadius: '6px', marginTop: '16px' }} />
        <div style={{ width: '30%', height: '10px', background: 'var(--border-subtle)', borderRadius: '3px', marginTop: '12px' }} />
      </div>
    );
  }
  if (variant === 'pie') {
    return (
      <div className="animate-pulse" style={{ opacity: 0.7, display: 'flex', justifyContent: 'center', padding: '20px 0' }}>
        <div style={{ width: '120px', height: '120px', borderRadius: '50%', border: '8px solid var(--surface-subtle)' }} />
      </div>
    );
  }
  if (variant === 'table') {
    return (
      <div className="animate-pulse" style={{ opacity: 0.7, display: 'flex', flexDirection: 'column', gap: '10px', paddingTop: '10px' }}>
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} style={{ width: `${90 - i * 10}%`, height: '14px', background: 'var(--surface-hover)', borderRadius: '4px' }} />
        ))}
      </div>
    );
  }
  // 'card' — generic chart-shaped placeholder
  return (
    <div className="animate-pulse" style={{ opacity: 0.7 }}>
      <div style={{ width: '100%', height: '240px', background: 'var(--surface-subtle)', borderRadius: '8px' }} />
    </div>
  );
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--chart-tooltip-bg)', border: '1px solid var(--border-strong)', borderRadius: '8px', padding: '10px 14px', fontSize: '12px' }}>
      <div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
          <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: p.color }} />
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{p.name}: {p.value?.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

// One chip in the config-health strip. `neutral` is for a feature that's
// simply off by design (e.g. ML engine not configured) — status by icon
// shape as well as color, not color alone (an amber dot reads the same to
// a colorblind viewer as a green one without the shape difference).
function HealthChip({ label, ok, neutral = false, okLabel = 'Healthy', downLabel = 'Unreachable' }) {
  const Icon = neutral ? AlertCircle : ok ? CheckCircle2 : XCircle;
  const color = neutral ? 'var(--text-muted)' : ok ? 'var(--success-color)' : 'var(--danger-color)';
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
      <Icon size={13} color={color} />
      <span>{label}:</span>
      <span style={{ fontWeight: 600, color }}>{neutral ? downLabel : ok ? okLabel : downLabel}</span>
    </span>
  );
}

// Real KPI trend badge — replaces the 4 metric cards' old static, hardcoded
// arrow+label ("Active blocking", "Inbound vectors"...) that never actually
// reflected data, always pointed the same direction. `trend-up`/`trend-down`
// are existing CSS classes already colored correctly for THIS domain (up in
// attack volume is red/bad, down is green/good — the opposite of a typical
// growth-metric dashboard), so this only needed to compute a real delta and
// reuse them, not invent new styling.
function TrendBadge({ current, previous }) {
  if (current == null || previous == null) return null; // ClickHouse was unavailable for the trend query
  if (previous === 0) {
    if (current === 0) {
      return <div className="metric-trend" style={{ color: 'var(--text-muted)' }}><span>No change vs. prior 24h</span></div>;
    }
    return (
      <div className="metric-trend trend-up">
        <span className="trend-arrow">↑</span>
        <span>+{current.toLocaleString()} new vs. prior 24h</span>
      </div>
    );
  }
  const deltaPct = ((current - previous) / previous) * 100;
  const rounded = Math.round(Math.abs(deltaPct));
  if (rounded === 0) {
    return <div className="metric-trend" style={{ color: 'var(--text-muted)' }}><span>Flat vs. prior 24h</span></div>;
  }
  const isUp = deltaPct > 0;
  return (
    <div className={`metric-trend ${isUp ? 'trend-up' : 'trend-down'}`}>
      <span className="trend-arrow">{isUp ? '↑' : '↓'}</span>
      <span>{rounded}% vs. prior 24h</span>
    </div>
  );
}

// The customize panel — a lightweight popover (button + up/down + checkbox
// per card), not a drag-and-drop builder. Deliberately no drag library:
// keyboard-operable for free, and reorder-by-6-items-at-most doesn't need
// the complexity a real drag interaction brings.
export function KpiCustomizePanel({ order, hidden, onChange, onClose }) {
  const move = (id, dir) => {
    const idx = order.indexOf(id);
    const swapWith = idx + dir;
    if (swapWith < 0 || swapWith >= order.length) return;
    const next = [...order];
    [next[idx], next[swapWith]] = [next[swapWith], next[idx]];
    onChange({ order: next, hidden });
  };

  const toggle = (id) => {
    const isHidden = hidden.includes(id);
    if (!isHidden && hidden.length >= order.length - 1) return; // keep at least one card visible
    onChange({ order, hidden: isHidden ? hidden.filter((h) => h !== id) : [...hidden, id] });
  };

  const reset = () => onChange({ order: DEFAULT_KPI_ORDER, hidden: [] });

  return (
    <div
      role="dialog"
      aria-label="Customize KPI cards"
      style={{
        position: 'absolute', top: 'calc(100% + 8px)', right: 0, zIndex: 30, width: '280px',
        background: 'var(--surface, var(--bg-secondary))', border: '1px solid var(--border-strong)',
        borderRadius: '10px', boxShadow: '0 12px 32px rgba(0,0,0,0.25)', padding: '12px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-secondary)' }}>Customize cards</span>
        <button type="button" onClick={onClose} aria-label="Close" style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', padding: '2px' }}>
          <CloseIcon size={14} />
        </button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {order.map((id, idx) => {
          const isHidden = hidden.includes(id);
          const lastVisible = !isHidden && hidden.length >= order.length - 1;
          return (
            <div key={id} style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 2px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, fontSize: '12.5px', color: isHidden ? 'var(--text-muted)' : 'var(--text-primary)', cursor: lastVisible ? 'not-allowed' : 'pointer' }}>
                <input type="checkbox" checked={!isHidden} disabled={lastVisible} onChange={() => toggle(id)} />
                {KPI_LABELS[id]}
              </label>
              <button type="button" onClick={() => move(id, -1)} disabled={idx === 0} aria-label={`Move ${KPI_LABELS[id]} up`}
                style={{ background: 'none', border: 'none', color: idx === 0 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: idx === 0 ? 'default' : 'pointer', display: 'flex', padding: '2px' }}>
                <ChevronUp size={13} />
              </button>
              <button type="button" onClick={() => move(id, 1)} disabled={idx === order.length - 1} aria-label={`Move ${KPI_LABELS[id]} down`}
                style={{ background: 'none', border: 'none', color: idx === order.length - 1 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: idx === order.length - 1 ? 'default' : 'pointer', display: 'flex', padding: '2px' }}>
                <ChevronDown size={13} />
              </button>
            </div>
          );
        })}
      </div>
      <button type="button" onClick={reset} style={{ display: 'flex', alignItems: 'center', gap: '5px', marginTop: '10px', background: 'none', border: 'none', color: 'var(--accent-color)', fontSize: '11.5px', cursor: 'pointer', padding: 0 }}>
        <RotateCcw size={11} /> Reset to default
      </button>
    </div>
  );
}

export default function ThreatAnalytics({ userRole, username, onNavigateToActivityLog, onFilterEvents }) {
  const [stats, setStats] = useState({
    total_requests: 0,
    total_blocked: 0,
    sqli_count: 0,
    xss_count: 0,
    top_attack_type: '-',
    total_unique_ips: 0
  });
  const [attackDistribution, setAttackDistribution] = useState([]);
  const [severityDistribution, setSeverityDistributionData] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [topRules, setTopRules] = useState([]);
  const [topIPs, setTopIPs] = useState([]);
  const [topUris, setTopUris] = useState([]);
  const [kpiPrefs, setKpiPrefs] = useState(() => loadKpiPrefs(username));
  const [showKpiCustomizer, setShowKpiCustomizer] = useState(false);
  const kpiCustomizerRef = React.useRef(null);

  const updateKpiPrefs = (next) => {
    setKpiPrefs(next);
    saveKpiPrefs(username, next);
  };

  useEffect(() => {
    if (!showKpiCustomizer) return;
    const handlePointerDown = (e) => {
      if (kpiCustomizerRef.current && !kpiCustomizerRef.current.contains(e.target)) setShowKpiCustomizer(false);
    };
    const handleKeyDown = (e) => { if (e.key === 'Escape') setShowKpiCustomizer(false); };
    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [showKpiCustomizer]);
  // Previously one `loading` flag gated the ENTIRE page behind
  // Promise.allSettled of all 6 API calls — the whole dashboard stayed on
  // the skeleton until the SLOWEST of the six resolved, even when the other
  // five came back instantly. Split into one flag per section so each part
  // of the page renders the moment its own request resolves.
  const [statsLoading, setStatsLoading] = useState(true);
  const [timelineLoading, setTimelineLoading] = useState(true);
  const [severityLoading, setSeverityLoading] = useState(true);
  const [distributionLoading, setDistributionLoading] = useState(true);
  const [topRulesLoading, setTopRulesLoading] = useState(true);
  const [topIPsLoading, setTopIPsLoading] = useState(true);
  const [topUrisLoading, setTopUrisLoading] = useState(true);
  // "Has the first fetch cycle finished at all" — used only to decide
  // whether it's safe to show a terminal empty/error state (must not flash
  // "no traffic" before the first real answer has come back).
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [liveUpdates, setLiveUpdates] = useState(true);
  // KPI trend badges — current vs. previous 24h window, from ClickHouse
  // directly (not derived from `stats`, which is an all-time total with no
  // window to compare against). {current, previous} or null.
  const [statsTrend, setStatsTrend] = useState(null);

  // Config-health rollup — connectivity + background-task status, already
  // computed by the backend (health.py / heartbeat_registry.py) but never
  // surfaced anywhere in the UI before. Polled far less often than traffic
  // stats (service up/down doesn't change second-to-second) and kept
  // separate from that polling cycle so a slow health check never delays
  // the KPI cards.
  const [health, setHealth] = useState(null);
  const [backgroundHealth, setBackgroundHealth] = useState(null);
  // "What changed" — the last few admin actions (GET /settings/audit-log
  // is require_admin, so this only ever fetches for admins), reusing the
  // same audit trail Settings > Activity Log already reads. Answers
  // "what's different since I last looked," which the KPI cards alone
  // don't — they're just current totals, not a diff.
  const [recentChanges, setRecentChanges] = useState([]);
  const isAdmin = userRole === 'admin';

  // Date.now() can't be called during render (React's purity rule) since it
  // isn't a function of props/state — capture it as state instead, ticked
  // periodically, so "what changed"'s relative timestamps ("2m ago") still
  // advance without the render itself reading the live clock.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 60000);
    return () => clearInterval(interval);
  }, []);

  const [showFlash, setShowFlash] = useState(false);
  const [activeVectorIndex, setActiveVectorIndex] = useState(null);
  const prevBlockedRef = React.useRef(0);
  // setInterval fires unconditionally regardless of whether the previous
  // fetchAnalytics() call (6 parallel API requests) has actually resolved.
  // Under any backend/ClickHouse latency, cycles start overlapping and pile
  // up — each stacked cycle adds more concurrent load, making the next
  // cycle even slower, a polling death-spiral that shows up as "the
  // dashboard feels slow" independent of any single request's real cost.
  const isFetchingRef = React.useRef(false);

  useEffect(() => {
    getGeneralSettings().then(settings => {
      if (settings.refreshInterval) {
        if (settings.refreshInterval === 'off') setRefreshInterval(0);
        else setRefreshInterval(parseInt(settings.refreshInterval) * 1000 || 5000);
      }
      if (settings.liveUpdates !== undefined) setLiveUpdates(settings.liveUpdates);
    }).catch(err => console.error("Failed to load general settings", err));
  }, []);

  const fetchAnalytics = () => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    // Each request is handled independently — its own state (and its own
    // loading flag) updates the instant THAT request resolves, instead of
    // waiting for every other one to finish first. All 6 still fire in
    // parallel (same network behavior/backend load as before), only the
    // "when do we act on the result" behavior changed.
    const statsPromise = getStats()
      .then(value => {
        if (prevBlockedRef.current && value.total_blocked > prevBlockedRef.current) {
          setShowFlash(true);
          setTimeout(() => setShowFlash(false), 800);
        }
        prevBlockedRef.current = value.total_blocked;
        setStats(value);
        setFetchError(null);
      })
      .catch(err => {
        console.error("Failed to fetch core stats", err);
        setFetchError(err?.message || 'Failed to reach the backend API.');
      })
      .finally(() => setStatsLoading(false));

    const distPromise = getAttackTypes()
      .then(value => {
        const mappedDist = value
          .filter(d => d.attack_type && d.attack_type !== 'Unknown')
          .map(d => ({ name: d.attack_type, value: d.count }));
        setAttackDistribution(mappedDist);
      })
      .catch(err => console.error("Failed to fetch attack type distribution", err))
      .finally(() => setDistributionLoading(false));

    const sevPromise = getSeverityDistribution()
      .then(value => {
        const mappedSev = value.map(s => ({ name: s.severity, value: s.count }));
        setSeverityDistributionData(mappedSev);
      })
      .catch(err => console.error("Failed to fetch severity distribution", err))
      .finally(() => setSeverityLoading(false));

    const timePromise = getTimeline()
      .then(value => {
        const mappedTime = value.data.map(t => {
          let displayTime = t.time;
          if (displayTime.includes('T')) {
            displayTime = displayTime.split('T')[1];
          } else if (displayTime.includes(' ')) {
            const parts = displayTime.split(' ');
            displayTime = parts[parts.length - 1];
          }
          return { time: displayTime, attacks: t.count };
        });
        setTimelineData(mappedTime);
      })
      .catch(err => console.error("Failed to fetch attack timeline", err))
      .finally(() => setTimelineLoading(false));

    const rulesPromise = getTopRules()
      .then(value => setTopRules(value.slice(0, 5)))
      .catch(err => console.error("Failed to fetch top rules", err))
      .finally(() => setTopRulesLoading(false));

    const ipsPromise = getTopIPs()
      .then(value => setTopIPs(value.slice(0, 5)))
      .catch(err => console.warn('Top IPs unavailable (Redis may be unreachable):', err))
      .finally(() => setTopIPsLoading(false));

    const urisPromise = getTopUris()
      .then(value => setTopUris(value.slice(0, 5)))
      .catch(err => console.error("Failed to fetch top targeted endpoints", err))
      .finally(() => setTopUrisLoading(false));

    Promise.allSettled([statsPromise, distPromise, sevPromise, timePromise, rulesPromise, ipsPromise, urisPromise])
      .finally(() => {
        setLoading(false);
        isFetchingRef.current = false;
      });
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchAnalytics();
    }, 0);
    if (refreshInterval > 0 && liveUpdates) {
      const interval = setInterval(fetchAnalytics, refreshInterval);
      return () => {
        clearTimeout(timer);
        clearInterval(interval);
      };
    }
    return () => clearTimeout(timer);
  }, [refreshInterval, liveUpdates]);

  // Optimistic live counters — /api/stats itself is Redis-cached for 30s
  // server-side (deliberately, to keep ClickHouse load bounded across every
  // connected dashboard session), so pure polling alone means a KPI card
  // can sit on the same number for up to 30s after a real attack before it
  // visibly moves, even though refetches are firing every few seconds.
  // Bumping the displayed count instantly off the same live event stream
  // the notification bell already uses gives the "moves the moment it
  // happens" feel without shortening that cache (and its ClickHouse-load
  // protection) for every viewer. fetchAnalytics's next poll still
  // reconciles these to the authoritative server total, so a missed or
  // duplicated WS frame can't drift the displayed number permanently.
  useEffect(() => {
    if (!liveUpdates) return undefined;
    const ws = new WebSocket(getLiveStreamWsUrl());
    ws.onmessage = (evt) => {
      let msg;
      try {
        msg = JSON.parse(evt.data);
      } catch {
        return;
      }
      if (msg.type !== 'log') return;
      setStats((prev) => applyLiveStatsBump(prev, msg.data));
    };
    return () => ws.close();
  }, [liveUpdates]);

  useEffect(() => {
    const fetchHealth = () => {
      getHealth().then(setHealth).catch(err => console.error("Failed to fetch health status", err));
      // Trend badges compare 24h windows — no need to refetch on the fast
      // (3s) traffic-stats cycle, so it rides along with the slow 30s
      // health poll instead, same reasoning as health/backgroundHealth above.
      getStatsTrend(24).then(setStatsTrend).catch(err => console.error("Failed to fetch stats trend", err));
      if (isAdmin) {
        getBackgroundTasksHealth().then(setBackgroundHealth).catch(err => console.error("Failed to fetch background task health", err));
        getAuditLog(1, 5, null, 24)
          .then(res => setRecentChanges(res?.data || []))
          .catch(err => console.error("Failed to fetch recent changes", err));
      }
    };
    const timer = setTimeout(fetchHealth, 0);
    const interval = setInterval(fetchHealth, 30000);
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [isAdmin]);


  // Previously this returned a full-page skeleton and rendered NOTHING else
  // until every section had data. Now the real grid below renders
  // immediately (first paint of the page shell isn't gated on any network
  // call at all) and each section shows its own small skeleton internally
  // via its *Loading flag — so five fast sections can appear right away
  // while a sixth, slower one is still in flight, instead of the whole
  // page waiting on the slowest call.

  // A failed core-stats fetch must never render identically to a quiet,
  // genuinely-empty dashboard — otherwise a down backend looks like "0 attacks".
  if (!loading && fetchError && stats.total_requests === 0) {
    return <FetchErrorState message={fetchError} onRetry={fetchAnalytics} />;
  }

  // Show empty state if no traffic has been analyzed yet
  if (!loading && stats.total_requests === 0 && timelineData.length === 0) {
    return <NoTrafficEmptyState />;
  }

  const SIEM_COLORS = {
    'SQL Injection': 'var(--sev-high)',
    'XSS': 'var(--pink-color)',
    'RCE': 'var(--danger-color)',
    'Protocol Violation': 'var(--accent-color)',
    'LFI/RFI': 'var(--ml-color)',
    'PHP Injection': 'var(--danger-color)',
    'Scanner/Recon': 'var(--sev-medium)',
    'Anomaly Detected': 'var(--text-secondary)',
    'Anomaly Threshold Exceeded': 'var(--text-secondary)',
  };

  const SEV_COLORS = { Critical: 'var(--danger-color)', High: 'var(--sev-high)', Medium: 'var(--sev-medium)', Low: 'var(--sev-low)' };

  const blockedPct = stats.total_requests > 0
    ? ((stats.total_blocked / stats.total_requests) * 100).toFixed(1)
    : '0.0';

  const getFlagEmoji = (code) => {
    if (!code || code === 'Unknown' || code === 'Internal') return '🌐';
    try {
      return String.fromCodePoint(...code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0)));
    } catch { return '🌐'; }
  };

  const maxIP = topIPs[0]?.count || 1;

  // Posture: derived only from real, already-fetched current data — no
  // invented trend/spike threshold. "Degraded" is a hard fact (a core
  // service reporting down); "Active Threats" is a hard fact too (at
  // least one Critical-severity event in the current window), not a
  // guess about whether that count is unusually high.
  const criticalCount = severityDistribution.find(s => s.name === 'Critical')?.value || 0;
  const downServices = health ? [
    health.redis_connected === false && 'Redis',
    health.clickhouse_connected === false && 'ClickHouse',
    health.db_initialized === false && 'Database',
  ].filter(Boolean) : [];
  const backgroundStale = isAdmin && backgroundHealth && !backgroundHealth.all_healthy
    ? Object.values(backgroundHealth.tasks || {}).filter(t => t.stale).length
    : 0;

  let posture = null; // 'protected' | 'attention' | 'degraded'
  if (health) {
    if (downServices.length > 0 || backgroundStale > 0) posture = 'degraded';
    else if (criticalCount > 0) posture = 'attention';
    else posture = 'protected';
  }

  const POSTURE = {
    protected: {
      icon: ShieldCheck, color: 'var(--success-color)', bg: 'var(--success-bg)',
      label: 'Protected',
      detail: 'All systems healthy, no critical-severity events in the current window.',
    },
    attention: {
      icon: AlertTriangleIcon, color: 'var(--sev-high)', bg: 'var(--sev-high-bg, var(--danger-bg))',
      label: 'Active Threats',
      detail: `${criticalCount} critical-severity event${criticalCount === 1 ? '' : 's'} blocked in the current window.`,
    },
    degraded: {
      icon: XCircle, color: 'var(--danger-color)', bg: 'var(--danger-bg)',
      label: 'Degraded',
      detail: [
        downServices.length > 0 ? `${downServices.join(', ')} unreachable` : null,
        backgroundStale > 0 ? `${backgroundStale} background task${backgroundStale === 1 ? '' : 's'} stale` : null,
      ].filter(Boolean).join(' · '),
    },
  }[posture];

  const timeAgo = (rawString) => {
    if (!rawString) return '';
    // Same UTC-normalization as formatLocalTime in utils/helpers.js — the
    // backend sends space-separated "YYYY-MM-DD HH:MM:SS" with no
    // timezone marker (implicitly UTC), not real ISO 8601.
    const cleanStr = String(rawString).trim().replace('T', ' ').replace('Z', '');
    const date = new Date(cleanStr + 'Z');
    if (isNaN(date.getTime())) return '';
    const mins = Math.round((now - date.getTime()) / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.round(hrs / 24)}d ago`;
  };

  // log_admin_action's `details` is stored (and returned) as a JSON string,
  // e.g. '{"status": "Reviewed"}' — without this, two genuinely different
  // actions on the same record (say, a status flipped from Pending to
  // Reviewed a second apart) render as identical-looking lines, since
  // "update_status false_positive #<id>" alone doesn't say what changed.
  // Only `status` is surfaced (the one field common enough across action
  // types to be worth a generic suffix); anything else stays silent rather
  // than guessing at a shape that doesn't apply to this action.
  const changeDetailSuffix = (rawDetails) => {
    if (!rawDetails) return '';
    try {
      const parsed = JSON.parse(rawDetails);
      return parsed?.status ? ` → ${parsed.status}` : '';
    } catch {
      return '';
    }
  };

  // Some entity types (false positives, exclusions) key off a full UUID —
  // fine in the full Activity Log table, but it eats most of a line in
  // this compact strip. Short numeric ids (rules, apps, users) pass
  // through unchanged since there's nothing to shorten. Full value stays
  // reachable via the title tooltip either way.
  const shortId = (id) => (id && id.length > 8 ? `${id.slice(0, 8)}…` : id);

  return (
    <motion.div
      className="dashboard-grid animate-fade-in"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Posture banner — leads with a single state instead of making the
          admin infer it from six KPI numbers. Same "only once real data
          exists" guard as the health strip below. */}
      {POSTURE && (
        <div style={{
          gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: '12px',
          padding: '14px 18px', borderRadius: 'var(--radius-lg, 12px)',
          background: POSTURE.bg, border: `1px solid ${POSTURE.color}`,
        }}>
          <POSTURE.icon size={22} color={POSTURE.color} style={{ flexShrink: 0 }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', minWidth: 0 }}>
            <span style={{ fontSize: '15px', fontWeight: 700, color: POSTURE.color }}>{POSTURE.label}</span>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{POSTURE.detail}</span>
          </div>
        </div>
      )}

      {/* Health + "what changed" — one merged panel instead of two stacked
          glass-panel bars. Both are peripheral-awareness strips (as opposed
          to the posture banner above, which is the primary state and reads
          better standing alone) — separately bordered/shadowed boxes for
          each was reading as a wall of banners before reaching the KPI
          cards. Each row renders independently off its own data, so a
          non-admin (no "what changed" access, that endpoint is
          require_admin) or a still-loading health check never leaves an
          empty second row or a divider with nothing under it. */}
      {(health || (isAdmin && recentChanges.length > 0)) && (
        <div className="glass-panel" style={{ gridColumn: '1 / -1', padding: 0 }}>
          {health && (
            <div style={{ padding: '10px 18px', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '18px', fontSize: '12px' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.05em' }}>
                System Health
              </span>
              <HealthChip label="Redis" ok={health.redis_connected} />
              <HealthChip label="ClickHouse" ok={health.clickhouse_connected} />
              <HealthChip label="Database" ok={health.db_initialized} />
              <HealthChip label="ML Engine" ok={health.ml_enabled} okLabel="Enabled" downLabel="Disabled" neutral={!health.ml_enabled} />
              {isAdmin && backgroundHealth && (
                <HealthChip
                  label="Background Tasks"
                  ok={backgroundHealth.all_healthy}
                  okLabel="All on schedule"
                  downLabel={`${Object.values(backgroundHealth.tasks || {}).filter(t => t.stale).length} stale`}
                />
              )}
            </div>
          )}
          {isAdmin && recentChanges.length > 0 && (
            <div style={{
              padding: '10px 18px', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '14px', fontSize: '12px',
              borderTop: health ? '1px solid var(--border-color)' : 'none',
            }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.05em', flexShrink: 0 }}>
                <History size={13} /> What Changed
              </span>
              {recentChanges.slice(0, 3).map((entry) => (
                <span key={entry.id} style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                  <strong style={{ color: 'var(--text-primary)' }}>{entry.username}</strong> {entry.action} {entry.entity_type} #<span title={entry.entity_id}>{shortId(entry.entity_id)}</span>
                  {changeDetailSuffix(entry.details) && (
                    <strong style={{ color: 'var(--accent-color)' }}>{changeDetailSuffix(entry.details)}</strong>
                  )}
                  <span style={{ color: 'var(--text-muted)' }}> · {timeAgo(entry.timestamp)}</span>
                </span>
              ))}
              {onNavigateToActivityLog && (
                <button
                  onClick={onNavigateToActivityLog}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '4px', marginLeft: 'auto', flexShrink: 0,
                    background: 'transparent', border: 'none', color: 'var(--accent-color)', fontSize: '11px',
                    fontWeight: 600, cursor: 'pointer', padding: 0,
                  }}
                >
                  View full history <ArrowRight size={12} />
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Row 1: KPI Stat Cards — configurable (P1 item 6). Each visible
          card gets flex:1 instead of a fixed 12-col grid span, so any
          count from 1-6 (any subset can be hidden) distributes evenly
          without leftover gaps a fixed span-2 grid would leave. */}
      <div ref={kpiCustomizerRef} style={{ gridColumn: '1 / -1', position: 'relative' }}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '8px' }}>
          <button
            type="button"
            onClick={() => setShowKpiCustomizer((v) => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: '5px', background: 'none',
              border: '1px solid var(--border-color)', borderRadius: '6px', padding: '4px 10px',
              fontSize: '11px', color: 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            <SlidersHorizontal size={12} /> Customize
          </button>
          {showKpiCustomizer && (
            <KpiCustomizePanel
              order={kpiPrefs.order}
              hidden={kpiPrefs.hidden}
              onChange={updateKpiPrefs}
              onClose={() => setShowKpiCustomizer(false)}
            />
          )}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
          {kpiPrefs.order.filter((id) => !kpiPrefs.hidden.includes(id)).map((id) => (
            <div key={id} style={{ flex: '1 1 160px', minWidth: 0 }}>
              {id === 'total_requests' && (
                <div className="metric-card cyan">
                  <div className="metric-header">
                    <span className="metric-header-label">Total Requests</span>
                    <div className="metric-icon-wrapper cyan"><Activity size={14} /></div>
                  </div>
                  {statsLoading ? <SectionSkeleton variant="metric" /> : (
                    <>
                      <div className="metric-value" style={{ color: 'var(--cyan-color)' }}><AnimatedNumber value={stats.total_requests} /></div>
                      <div className="metric-sublabel">All analyzed traffic</div>
                      <div className="metric-trend">
                        <div className="pulse-dot" style={{ width: '6px', height: '6px' }} />
                        <span>Live capture</span>
                      </div>
                    </>
                  )}
                </div>
              )}
              {id === 'blocked_threats' && (
                <div className="metric-card danger" style={{ animation: stats.recent_threats > 0 ? 'dangerPulse 2s infinite' : 'none' }}>
                  <div className="metric-header">
                    <span className="metric-header-label">Blocked Threats</span>
                    <div className="metric-icon-wrapper red"><ShieldAlert size={14} /></div>
                  </div>
                  {statsLoading ? <SectionSkeleton variant="metric" /> : (
                    <>
                      <div className="metric-value" style={{ color: 'var(--danger-color)' }}><AnimatedNumber value={stats.total_blocked} /></div>
                      <div className="metric-sublabel">HTTP 403 responses</div>
                      <TrendBadge current={statsTrend?.current?.total_blocked} previous={statsTrend?.previous?.total_blocked} />
                    </>
                  )}
                </div>
              )}
              {id === 'block_rate' && (
                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-header-label">Block Rate</span>
                    <div className="metric-icon-wrapper purple"><Lock size={14} /></div>
                  </div>
                  {statsLoading ? <SectionSkeleton variant="metric" /> : (
                    <>
                      <div className="metric-value" style={{ color: 'var(--ml-color)' }}>
                        {blockedPct}<span style={{ fontSize: '18px', fontWeight: 400, opacity: 0.7 }}>%</span>
                      </div>
                      <div className="metric-sublabel">Of all requests blocked</div>
                      <div style={{ width: '100%', height: '4px', background: 'var(--border-color)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min(parseFloat(blockedPct), 100)}%`, height: '100%', background: 'var(--ml-color)', borderRadius: '2px', transition: 'width 0.8s ease' }} />
                      </div>
                    </>
                  )}
                </div>
              )}
              {id === 'sqli' && (
                <div className="metric-card warning">
                  <div className="metric-header">
                    <span className="metric-header-label">SQL Injection</span>
                    <div className="metric-icon-wrapper orange"><Database size={14} /></div>
                  </div>
                  {statsLoading ? <SectionSkeleton variant="metric" /> : (
                    <>
                      <div className="metric-value" style={{ color: 'var(--warning-color)' }}><AnimatedNumber value={stats.sqli_count} /></div>
                      <div className="metric-sublabel">Blocked SQLi attempts</div>
                      <TrendBadge current={statsTrend?.current?.sqli_count} previous={statsTrend?.previous?.sqli_count} />
                    </>
                  )}
                </div>
              )}
              {id === 'xss' && (
                <div className="metric-card pink">
                  <div className="metric-header">
                    <span className="metric-header-label">Cross-Site Scripting</span>
                    <div className="metric-icon-wrapper pink"><Code size={14} /></div>
                  </div>
                  {statsLoading ? <SectionSkeleton variant="metric" /> : (
                    <>
                      <div className="metric-value" style={{ color: 'var(--pink-color)' }}><AnimatedNumber value={stats.xss_count} /></div>
                      <div className="metric-sublabel">Blocked XSS attacks</div>
                      <TrendBadge current={statsTrend?.current?.xss_count} previous={statsTrend?.previous?.xss_count} />
                    </>
                  )}
                </div>
              )}
              {id === 'unique_attackers' && (
                <div className="metric-card">
                  <div className="metric-header">
                    <span className="metric-header-label">Unique Attackers</span>
                    <div className="metric-icon-wrapper blue"><Globe size={14} /></div>
                  </div>
                  {statsLoading ? <SectionSkeleton variant="metric" /> : (
                    <>
                      <div className="metric-value" style={{ color: 'var(--accent-color)' }}><AnimatedNumber value={stats.total_unique_ips} /></div>
                      <div className="metric-sublabel">Distinct source IPs blocked</div>
                      <TrendBadge current={statsTrend?.current?.total_unique_ips} previous={statsTrend?.previous?.total_unique_ips} />
                    </>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Row 2: Timeline + Severity */}

      <div className="chart-card" style={{ gridColumn: 'span 8', position: 'relative' }}>
        {showFlash && (
          <div style={{ position: 'absolute', inset: 0, background: 'color-mix(in srgb, var(--danger-color) 6%, transparent)', border: '1px solid var(--danger-color)', borderRadius: '10px', pointerEvents: 'none', zIndex: 10 }} />
        )}
        <div className="card-title">
          <Activity size={14} color="var(--accent-color)" />
          Attack Timeline
          <div className="card-title-right">
            <div className="pulse-container"><div className="pulse-dot" /><span>Live Sync</span></div>
          </div>
        </div>
        <div className="chart-container" style={{ minHeight: '260px' }}>
          {timelineLoading ? <SectionSkeleton variant="card" /> : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
                <defs>
                  <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--danger-color)" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="var(--danger-color)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--surface-subtle)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--chart-axis)" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={60} />
                <YAxis stroke="var(--chart-axis)" fontSize={10} tickLine={false} axisLine={false} />
                <RechartsTooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="attacks" name="Blocked" stroke="var(--danger-color)" strokeWidth={2} fillOpacity={1} fill="url(#gradBlocked)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Severity Distribution */}
      <div className="chart-card" style={{ gridColumn: 'span 4' }}>
        <div className="card-title">
          <AlertTriangleIcon size={14} color="var(--warning-color)" />
          Threat Severity
        </div>
        <div className="chart-container" style={{ minHeight: '260px', display: 'flex', flexDirection: 'column', gap: '14px', justifyContent: 'center' }}>
          {severityLoading ? <SectionSkeleton variant="table" /> : severityDistribution.length === 0 ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center' }}>No data</div>
          ) : (() => {
            const maxSev = Math.max(...severityDistribution.map(s => s.value), 1);
            return severityDistribution.map((s) => {
              const pct = ((s.value / maxSev) * 100).toFixed(0);
              const color = SEV_COLORS[s.name] || 'var(--accent-color)';
              return (
                <button
                  key={s.name}
                  type="button"
                  onClick={() => onFilterEvents?.({ severity: s.name })}
                  title={`View ${s.name}-severity events`}
                  style={{
                    display: 'block', width: '100%', background: 'none', border: 'none', padding: 0,
                    font: 'inherit', textAlign: 'left', cursor: onFilterEvents ? 'pointer' : 'default',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: color, flexShrink: 0 }} />
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500 }}>{s.name}</span>
                    </div>
                    <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color }}>{s.value.toLocaleString()}</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'var(--surface-hover)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: '3px', transition: 'width 0.7s ease', opacity: 0.85 }} />
                  </div>
                </button>
              );
            });
          })()}
          {severityDistribution.length > 0 && (
            <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Total Blocked</span>
              <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                {severityDistribution.reduce((a, s) => a + s.value, 0).toLocaleString()}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Attack Vectors + Top IPs + Top Rules */}

      {/* Attack Vector Distribution */}
      <div className="chart-card" style={{ gridColumn: 'span 4' }}>
        <div className="card-title">
          <ShieldAlert size={14} color="var(--sev-high)" />
          Attack Vectors
        </div>
        <div className="chart-container" style={{ minHeight: '280px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          {distributionLoading ? <SectionSkeleton variant="pie" /> : attackDistribution.length === 0 ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center' }}>No data</div>
          ) : (() => {
            const total = attackDistribution.reduce((s, d) => s + d.value, 0);
            const aColors = ['var(--danger-color)','var(--sev-high)','var(--warning-color)','var(--accent-color)','var(--ml-color)','var(--cyan-color)','var(--pink-color)','var(--text-secondary)'];
            return (
              <>
                <div style={{ height: '150px', width: '100%', position: 'relative' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={attackDistribution}
                        cx="50%" cy="50%"
                        innerRadius={44} outerRadius={68}
                        paddingAngle={2}
                        dataKey="value"
                        activeIndex={activeVectorIndex}
                        activeShape={(props) => {
                          const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
                          return (
                            <g>
                              <Sector cx={cx} cy={cy} innerRadius={innerRadius - 3} outerRadius={outerRadius + 8} startAngle={startAngle} endAngle={endAngle} fill={fill} style={{ filter: `drop-shadow(0 0 8px ${fill}88)` }} />
                              <Sector cx={cx} cy={cy} innerRadius={outerRadius + 12} outerRadius={outerRadius + 14} startAngle={startAngle} endAngle={endAngle} fill={fill} opacity={0.4} />
                            </g>
                          );
                        }}
                        onMouseEnter={(_, i) => setActiveVectorIndex(i)}
                        onMouseLeave={() => setActiveVectorIndex(null)}
                        onClick={(data) => onFilterEvents?.({ attackType: data.name })}
                        style={{ cursor: onFilterEvents ? 'pointer' : 'default' }}
                        strokeWidth={0}
                      >
                        {attackDistribution.map((entry, index) => (
                          <Cell key={index} fill={SIEM_COLORS[entry.name] || aColors[index % aColors.length]} opacity={activeVectorIndex != null && activeVectorIndex !== index ? 0.4 : 1} />
                        ))}
                      </Pie>
                      <RechartsTooltip contentStyle={{ background: 'var(--chart-tooltip-bg)', border: '1px solid var(--surface-strong)', borderRadius: '8px', fontSize: '12px' }} itemStyle={{ color: 'var(--text-primary)' }} formatter={(v, n) => [`${v} (${((v/total)*100).toFixed(1)}%)`, n]} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', textAlign: 'center', pointerEvents: 'none' }}>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{total.toLocaleString()}</div>
                    <div style={{ fontSize: '9px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>blocked</div>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', marginTop: '10px' }}>
                  {attackDistribution.slice(0, 5).map((entry, index) => {
                    const color = SIEM_COLORS[entry.name] || aColors[index % aColors.length];
                    const pct = ((entry.value / total) * 100).toFixed(0);
                    return (
                      <button
                        key={entry.name}
                        type="button"
                        onMouseEnter={() => setActiveVectorIndex(index)}
                        onMouseLeave={() => setActiveVectorIndex(null)}
                        onClick={() => onFilterEvents?.({ attackType: entry.name })}
                        title={`View ${entry.name} events`}
                        style={{
                          display: 'flex', alignItems: 'center', gap: '8px', width: '100%',
                          padding: '4px 6px', borderRadius: '5px', border: 'none', font: 'inherit', textAlign: 'left',
                          cursor: onFilterEvents ? 'pointer' : 'default',
                          background: activeVectorIndex === index ? `${color}12` : 'transparent', transition: 'background 0.15s',
                        }}
                      >
                        <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, flexShrink: 0 }} />
                        <span style={{ flex: 1, fontSize: '11.5px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.name}</span>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color }}>{pct}%</span>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', minWidth: '40px', textAlign: 'right' }}>{entry.value.toLocaleString()}</span>
                      </button>
                    );
                  })}
                </div>
              </>
            );
          })()}
        </div>
      </div>

      {/* Top Attacking IPs */}
      <div className="chart-card" style={{ gridColumn: 'span 4' }}>
        <div className="card-title">
          <Globe size={14} color="var(--cyan-color)" />
          Top Attackers
        </div>
        <div className="chart-container" style={{ minHeight: '280px' }}>
          {topIPsLoading ? <SectionSkeleton variant="table" /> : topIPs.length === 0 ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center', paddingTop: '40px' }}>No malicious IPs recorded.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>#</th>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 8px', letterSpacing: '0.6px', fontWeight: 600 }}>IP Address</th>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'right', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Hits</th>
                </tr>
              </thead>
              <tbody>
                {topIPs.map((ip, idx) => (
                  <tr key={ip.ip || idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '7px 0', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', width: '20px', verticalAlign: 'top' }}>{idx + 1}</td>
                    <td style={{ padding: '7px 8px', verticalAlign: 'top' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                        <span style={{ fontSize: '13px' }} title={ip.country}>{getFlagEmoji(ip.country)}</span>
                        <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--cyan-color)', fontWeight: 600 }}>{ip.ip}</span>
                      </div>
                      <div style={{ width: '100%', height: '3px', background: 'var(--border-color)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min((ip.count / maxIP) * 100, 100)}%`, height: '100%', background: 'var(--danger-color)', borderRadius: '2px', opacity: 0.75 }} />
                      </div>
                    </td>
                    <td style={{ padding: '7px 0', textAlign: 'right', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--danger-color)', fontWeight: 700, verticalAlign: 'top' }}>{ip.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Most Active OWASP Rules */}
      <div className="chart-card" style={{ gridColumn: 'span 4' }}>
        <div className="card-title">
          <ShieldAlert size={14} color="var(--danger-color)" />
          Top OWASP Rules
        </div>
        <div className="chart-container" style={{ minHeight: '280px' }}>
          {topRulesLoading ? <SectionSkeleton variant="table" /> : topRules.length === 0 ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center', paddingTop: '40px' }}>No rules triggered.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Rule ID</th>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'right', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Triggers</th>
                </tr>
              </thead>
              <tbody>
                {topRules.map((rule) => {
                  const maxCount = topRules[0]?.count || 1;
                  const pct = ((rule.count / maxCount) * 100).toFixed(0);
                  return (
                    <tr key={rule.rule_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '7px 0', verticalAlign: 'top' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--ml-color)', fontWeight: 700, background: 'var(--ml-bg)', padding: '2px 6px', borderRadius: '4px' }}>{rule.rule_id}</span>
                          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>OWASP CRS</span>
                        </div>
                        <div style={{ width: '100%', height: '3px', background: 'var(--border-color)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: 'var(--ml-color)', borderRadius: '2px', opacity: 0.7 }} />
                        </div>
                      </td>
                      <td style={{ padding: '7px 0', textAlign: 'right', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--warning-color)', fontWeight: 700, verticalAlign: 'top' }}>{rule.count.toLocaleString()}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Row 4: Top Targeted Endpoints — "by target" counterpart to Top
          Attackers' "by source", closing out the aggregate-charts ->
          top-offenders investigation flow (WAAP console teardown roadmap,
          P0 item 3). Full-width: URIs run longer than IPs or rule IDs and
          deserve the room. */}
      <div className="chart-card" style={{ gridColumn: 'span 12' }}>
        <div className="card-title">
          <ShieldAlert size={14} color="var(--warning-color)" />
          Top Targeted Endpoints
        </div>
        <div className="chart-container" style={{ minHeight: '160px' }}>
          {topUrisLoading ? <SectionSkeleton variant="table" /> : topUris.length === 0 ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center', paddingTop: '40px' }}>No endpoints targeted.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Endpoint</th>
                  <th style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'right', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Blocked Hits</th>
                </tr>
              </thead>
              <tbody>
                {topUris.map((u) => {
                  const maxCount = topUris[0]?.count || 1;
                  const pct = ((u.count / maxCount) * 100).toFixed(0);
                  const openInEvents = () => onFilterEvents?.({ value: u.uri });
                  return (
                    <tr
                      key={u.uri}
                      role={onFilterEvents ? 'button' : undefined}
                      tabIndex={onFilterEvents ? 0 : undefined}
                      onClick={onFilterEvents ? openInEvents : undefined}
                      onKeyDown={onFilterEvents ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openInEvents(); } } : undefined}
                      title={onFilterEvents ? `View events for ${u.uri}` : undefined}
                      style={{ borderBottom: '1px solid var(--border-subtle)', cursor: onFilterEvents ? 'pointer' : 'default' }}
                    >
                      <td style={{ padding: '7px 0', verticalAlign: 'top' }}>
                        <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', marginBottom: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '520px' }}>{u.uri}</div>
                        <div style={{ width: '100%', height: '3px', background: 'var(--border-color)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: 'var(--warning-color)', borderRadius: '2px', opacity: 0.7 }} />
                        </div>
                      </td>
                      <td style={{ padding: '7px 0', textAlign: 'right', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--warning-color)', fontWeight: 700, verticalAlign: 'top' }}>{u.count.toLocaleString()}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </motion.div>
  );
}

