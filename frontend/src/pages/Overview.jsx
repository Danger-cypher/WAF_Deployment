import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle as AlertTriangleIcon, Code, Database, Globe, Lock, ShieldAlert,
  CheckCircle2, XCircle, AlertCircle,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Sector,
} from 'recharts';
import {
  getStats, getTimeline, getAttackTypes, getTopIPs, getTopRules, getSeverityDistribution,
  getGeneralSettings, getHealth, getBackgroundTasksHealth,
} from '../services/api';
import { NoTrafficEmptyState, FetchErrorState } from '../components/EmptyStates';

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

export default function ThreatAnalytics({ userRole }) {
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
  // "Has the first fetch cycle finished at all" — used only to decide
  // whether it's safe to show a terminal empty/error state (must not flash
  // "no traffic" before the first real answer has come back).
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [liveUpdates, setLiveUpdates] = useState(true);

  // Config-health rollup — connectivity + background-task status, already
  // computed by the backend (health.py / heartbeat_registry.py) but never
  // surfaced anywhere in the UI before. Polled far less often than traffic
  // stats (service up/down doesn't change second-to-second) and kept
  // separate from that polling cycle so a slow health check never delays
  // the KPI cards.
  const [health, setHealth] = useState(null);
  const [backgroundHealth, setBackgroundHealth] = useState(null);
  const isAdmin = userRole === 'admin';

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

    Promise.allSettled([statsPromise, distPromise, sevPromise, timePromise, rulesPromise, ipsPromise])
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

  useEffect(() => {
    const fetchHealth = () => {
      getHealth().then(setHealth).catch(err => console.error("Failed to fetch health status", err));
      if (isAdmin) {
        getBackgroundTasksHealth().then(setBackgroundHealth).catch(err => console.error("Failed to fetch background task health", err));
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

  return (
    <motion.div
      className="dashboard-grid animate-fade-in"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Config-health rollup — a single compact strip, not another wall of
          cards (six KPI cards below already cover traffic; this is purely
          "is the platform itself healthy"). Only rendered once the first
          health poll has come back, so it never flashes a false "down"
          before data exists. */}
      {health && (
        <div className="glass-panel" style={{
          gridColumn: '1 / -1', padding: '10px 18px', display: 'flex',
          flexWrap: 'wrap', alignItems: 'center', gap: '18px', fontSize: '12px',
        }}>
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

      {/* Row 1: 6 KPI Stat Cards */}

      {/* Total Requests */}
      <div className="metric-card cyan" style={{ gridColumn: 'span 2' }}>
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

      {/* Blocked Threats */}
      <div className="metric-card danger" style={{ gridColumn: 'span 2', animation: stats.recent_threats > 0 ? 'dangerPulse 2s infinite' : 'none' }}>
        <div className="metric-header">
          <span className="metric-header-label">Blocked Threats</span>
          <div className="metric-icon-wrapper red"><ShieldAlert size={14} /></div>
        </div>
        {statsLoading ? <SectionSkeleton variant="metric" /> : (
          <>
            <div className="metric-value" style={{ color: 'var(--danger-color)' }}><AnimatedNumber value={stats.total_blocked} /></div>
            <div className="metric-sublabel">HTTP 403 responses</div>
            <div className="metric-trend trend-up">
              <span className="trend-arrow">↑</span>
              <span>Active blocking</span>
            </div>
          </>
        )}
      </div>

      {/* Block Rate */}
      <div className="metric-card" style={{ gridColumn: 'span 2' }}>
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

      {/* SQL Injection */}
      <div className="metric-card warning" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">SQL Injection</span>
          <div className="metric-icon-wrapper orange"><Database size={14} /></div>
        </div>
        {statsLoading ? <SectionSkeleton variant="metric" /> : (
          <>
            <div className="metric-value" style={{ color: 'var(--warning-color)' }}><AnimatedNumber value={stats.sqli_count} /></div>
            <div className="metric-sublabel">Blocked SQLi attempts</div>
            <div className="metric-trend trend-down">
              <span className="trend-arrow">↓</span>
              <span>Inbound vectors</span>
            </div>
          </>
        )}
      </div>

      {/* XSS */}
      <div className="metric-card pink" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">Cross-Site Scripting</span>
          <div className="metric-icon-wrapper pink"><Code size={14} /></div>
        </div>
        {statsLoading ? <SectionSkeleton variant="metric" /> : (
          <>
            <div className="metric-value" style={{ color: 'var(--pink-color)' }}><AnimatedNumber value={stats.xss_count} /></div>
            <div className="metric-sublabel">Blocked XSS attacks</div>
            <div className="metric-trend trend-down">
              <span className="trend-arrow">↓</span>
              <span>App shields active</span>
            </div>
          </>
        )}
      </div>

      {/* Unique Attackers */}
      <div className="metric-card" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">Unique Attackers</span>
          <div className="metric-icon-wrapper blue"><Globe size={14} /></div>
        </div>
        {statsLoading ? <SectionSkeleton variant="metric" /> : (
          <>
            <div className="metric-value" style={{ color: 'var(--accent-color)' }}><AnimatedNumber value={stats.total_unique_ips} /></div>
            <div className="metric-sublabel">Distinct source IPs blocked</div>
            <div className="metric-trend trend-up">
              <span className="trend-arrow">↑</span>
              <Globe size={10} />
              <span>Global distribution</span>
            </div>
          </>
        )}
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
                <div key={s.name}>
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
                </div>
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
                      <div key={entry.name} onMouseEnter={() => setActiveVectorIndex(index)} onMouseLeave={() => setActiveVectorIndex(null)}
                        style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 6px', borderRadius: '5px', cursor: 'default', background: activeVectorIndex === index ? `${color}12` : 'transparent', transition: 'background 0.15s' }}>
                        <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: color, flexShrink: 0 }} />
                        <span style={{ flex: 1, fontSize: '11.5px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.name}</span>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color }}>{pct}%</span>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', minWidth: '40px', textAlign: 'right' }}>{entry.value.toLocaleString()}</span>
                      </div>
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
    </motion.div>
  );
}

