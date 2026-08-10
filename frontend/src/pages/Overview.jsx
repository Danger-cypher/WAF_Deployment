import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle as AlertTriangleIcon, Code, Database, Globe, Lock, ShieldAlert,
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Sector,
} from 'recharts';
import {
  getStats, getTimeline, getAttackTypes, getTopIPs, getTopRules, getSeverityDistribution,
  getGeneralSettings,
} from '../services/api';
import { NoTrafficEmptyState } from '../components/EmptyStates';

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

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', padding: '10px 14px', fontSize: '12px' }}>
      <div style={{ color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
          <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: p.color }} />
          <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{p.name}: {p.value?.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

export default function ThreatAnalytics() {
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
  const [loading, setLoading] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [liveUpdates, setLiveUpdates] = useState(true);

  const [showFlash, setShowFlash] = useState(false);
  const [activeVectorIndex, setActiveVectorIndex] = useState(null);
  const prevBlockedRef = React.useRef(0);

  useEffect(() => {
    getGeneralSettings().then(settings => {
      if (settings.refreshInterval) {
        if (settings.refreshInterval === 'off') setRefreshInterval(0);
        else setRefreshInterval(parseInt(settings.refreshInterval) * 1000 || 5000);
      }
      if (settings.liveUpdates !== undefined) setLiveUpdates(settings.liveUpdates);
    }).catch(err => console.error("Failed to load general settings", err));
  }, []);

  const fetchAnalytics = async () => {
    try {
      const [statsRes, distRes, sevRes, timeRes, rulesRes, ipsRes] = await Promise.allSettled([
        getStats(),
        getAttackTypes(),
        getSeverityDistribution(),
        getTimeline(),
        getTopRules(),
        getTopIPs()
      ]);

      if (statsRes.status === 'fulfilled') {
        if (prevBlockedRef.current && statsRes.value.total_blocked > prevBlockedRef.current) {
          setShowFlash(true);
          setTimeout(() => setShowFlash(false), 800);
        }
        prevBlockedRef.current = statsRes.value.total_blocked;
        setStats(statsRes.value);
      }

      if (distRes.status === 'fulfilled') {
        const mappedDist = distRes.value
          .filter(d => d.attack_type && d.attack_type !== 'Unknown')
          .map(d => ({ name: d.attack_type, value: d.count }));
        setAttackDistribution(mappedDist);
      }

      if (sevRes.status === 'fulfilled') {
        const mappedSev = sevRes.value.map(s => ({ name: s.severity, value: s.count }));
        setSeverityDistributionData(mappedSev);
      }

      if (timeRes.status === 'fulfilled') {
        const mappedTime = timeRes.value.data.map(t => {
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
      }

      if (rulesRes.status === 'fulfilled') {
        setTopRules(rulesRes.value.slice(0, 5));
      }

      if (ipsRes.status === 'fulfilled') {
        setTopIPs(ipsRes.value.slice(0, 5));
      } else {
        console.warn('Top IPs unavailable (Redis may be unreachable):', ipsRes.reason);
      }

    } catch (err) {
      console.error("Failed to fetch analytics data", err);
    } finally {
      setLoading(false);
    }
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


  if (loading && timelineData.length === 0) {
    return (
      <div className="dashboard-grid animate-pulse" style={{ opacity: 0.7 }}>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="metric-card glass-panel" style={{ gridColumn: i === 1 || i === 4 ? 'span 3' : 'span 2', minHeight: '120px' }}>
            <div style={{ width: '40%', height: '12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px' }} />
            <div style={{ width: '60%', height: '28px', background: 'rgba(255,255,255,0.08)', borderRadius: '6px', marginTop: '16px' }} />
            <div style={{ width: '30%', height: '10px', background: 'rgba(255,255,255,0.04)', borderRadius: '3px', marginTop: '12px' }} />
          </div>
        ))}
        <div className="chart-card glass-panel" style={{ gridColumn: 'span 8', minHeight: '350px' }}>
          <div style={{ width: '30%', height: '16px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', marginBottom: '24px' }} />
          <div style={{ width: '100%', height: '240px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }} />
        </div>
        <div className="chart-card glass-panel" style={{ gridColumn: 'span 4', minHeight: '350px' }}>
          <div style={{ width: '40%', height: '16px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', marginBottom: '24px' }} />
          <div style={{ width: '120px', height: '120px', borderRadius: '50%', border: '8px solid rgba(255,255,255,0.03)', margin: '40px auto' }} />
        </div>
      </div>
    );
  }

  // Show empty state if no traffic has been analyzed yet
  if (!loading && stats.total_requests === 0 && timelineData.length === 0) {
    return <NoTrafficEmptyState />;
  }

  const SIEM_COLORS = {
    'SQL Injection': '#fb923c',
    'XSS': '#f472b6',
    'RCE': '#ef4444',
    'Protocol Violation': '#818cf8',
    'LFI/RFI': '#a78bfa',
    'PHP Injection': '#f43f5e',
    'Scanner/Recon': '#eab308',
    'Anomaly Detected': '#64748b',
    'Anomaly Threshold Exceeded': '#64748b',
  };

  const SEV_COLORS = { Critical: '#f43f5e', High: '#f97316', Medium: '#eab308', Low: '#3b82f6' };

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
      {/* Row 1: 6 KPI Stat Cards */}

      {/* Total Requests */}
      <div className="metric-card cyan" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">Total Requests</span>
          <div className="metric-icon-wrapper cyan"><Activity size={14} /></div>
        </div>
        <div className="metric-value" style={{ color: '#22d3ee' }}><AnimatedNumber value={stats.total_requests} /></div>
        <div className="metric-sublabel">All analyzed traffic</div>
        <div className="metric-trend">
          <div className="pulse-dot" style={{ width: '6px', height: '6px' }} />
          <span>Live capture</span>
        </div>
      </div>

      {/* Blocked Threats */}
      <div className="metric-card danger" style={{ gridColumn: 'span 2', animation: stats.recent_threats > 0 ? 'dangerPulse 2s infinite' : 'none' }}>
        <div className="metric-header">
          <span className="metric-header-label">Blocked Threats</span>
          <div className="metric-icon-wrapper red"><ShieldAlert size={14} /></div>
        </div>
        <div className="metric-value" style={{ color: '#f43f5e' }}><AnimatedNumber value={stats.total_blocked} /></div>
        <div className="metric-sublabel">HTTP 403 responses</div>
        <div className="metric-trend trend-up">
          <span className="trend-arrow">↑</span>
          <span>Active blocking</span>
        </div>
      </div>

      {/* Block Rate */}
      <div className="metric-card" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">Block Rate</span>
          <div className="metric-icon-wrapper purple"><Lock size={14} /></div>
        </div>
        <div className="metric-value" style={{ color: '#a78bfa' }}>
          {blockedPct}<span style={{ fontSize: '18px', fontWeight: 400, opacity: 0.7 }}>%</span>
        </div>
        <div className="metric-sublabel">Of all requests blocked</div>
        <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
          <div style={{ width: `${Math.min(parseFloat(blockedPct), 100)}%`, height: '100%', background: '#a78bfa', borderRadius: '2px', transition: 'width 0.8s ease' }} />
        </div>
      </div>

      {/* SQL Injection */}
      <div className="metric-card warning" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">SQL Injection</span>
          <div className="metric-icon-wrapper orange"><Database size={14} /></div>
        </div>
        <div className="metric-value" style={{ color: '#f59e0b' }}><AnimatedNumber value={stats.sqli_count} /></div>
        <div className="metric-sublabel">Blocked SQLi attempts</div>
        <div className="metric-trend trend-down">
          <span className="trend-arrow">↓</span>
          <span>Inbound vectors</span>
        </div>
      </div>

      {/* XSS */}
      <div className="metric-card pink" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">Cross-Site Scripting</span>
          <div className="metric-icon-wrapper pink"><Code size={14} /></div>
        </div>
        <div className="metric-value" style={{ color: '#f472b6' }}><AnimatedNumber value={stats.xss_count} /></div>
        <div className="metric-sublabel">Blocked XSS attacks</div>
        <div className="metric-trend trend-down">
          <span className="trend-arrow">↓</span>
          <span>App shields active</span>
        </div>
      </div>

      {/* Unique Attackers */}
      <div className="metric-card" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span className="metric-header-label">Unique Attackers</span>
          <div className="metric-icon-wrapper blue"><Globe size={14} /></div>
        </div>
        <div className="metric-value" style={{ color: '#818cf8' }}><AnimatedNumber value={stats.total_unique_ips} /></div>
        <div className="metric-sublabel">Distinct source IPs blocked</div>
        <div className="metric-trend trend-up">
          <span className="trend-arrow">↑</span>
          <Globe size={10} />
          <span>Global distribution</span>
        </div>
      </div>

      {/* Row 2: Timeline + Severity */}

      <div className="chart-card" style={{ gridColumn: 'span 8', position: 'relative' }}>
        {showFlash && (
          <div style={{ position: 'absolute', inset: 0, background: 'rgba(244,63,94,0.06)', border: '1px solid #f43f5e', borderRadius: '10px', pointerEvents: 'none', zIndex: 10 }} />
        )}
        <div className="card-title">
          <Activity size={14} color="#818cf8" />
          Attack Timeline
          <div className="card-title-right">
            <div className="pulse-container"><div className="pulse-dot" /><span>Live Sync</span></div>
          </div>
        </div>
        <div className="chart-container" style={{ minHeight: '260px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
              <XAxis dataKey="time" stroke="#334155" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={60} />
              <YAxis stroke="#334155" fontSize={10} tickLine={false} axisLine={false} />
              <RechartsTooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="attacks" name="Blocked" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#gradBlocked)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Severity Distribution */}
      <div className="chart-card" style={{ gridColumn: 'span 4' }}>
        <div className="card-title">
          <AlertTriangleIcon size={14} color="#f59e0b" />
          Threat Severity
        </div>
        <div className="chart-container" style={{ minHeight: '260px', display: 'flex', flexDirection: 'column', gap: '14px', justifyContent: 'center' }}>
          {severityDistribution.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '13px', textAlign: 'center' }}>No data</div>
          ) : (() => {
            const maxSev = Math.max(...severityDistribution.map(s => s.value), 1);
            return severityDistribution.map((s) => {
              const pct = ((s.value / maxSev) * 100).toFixed(0);
              const color = SEV_COLORS[s.name] || '#818cf8';
              return (
                <div key={s.name}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: color, flexShrink: 0 }} />
                      <span style={{ fontSize: '12px', color: '#94a3b8', fontWeight: 500 }}>{s.name}</span>
                    </div>
                    <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color }}>{s.value.toLocaleString()}</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: '3px', transition: 'width 0.7s ease', opacity: 0.85 }} />
                  </div>
                </div>
              );
            });
          })()}
          {severityDistribution.length > 0 && (
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: '#475569', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Total Blocked</span>
              <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f1f5f9' }}>
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
          <ShieldAlert size={14} color="#f97316" />
          Attack Vectors
        </div>
        <div className="chart-container" style={{ minHeight: '280px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          {attackDistribution.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '13px', textAlign: 'center' }}>No data</div>
          ) : (() => {
            const total = attackDistribution.reduce((s, d) => s + d.value, 0);
            const aColors = ['#f43f5e','#f97316','#f59e0b','#818cf8','#a78bfa','#22d3ee','#f472b6','#64748b'];
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
                      <RechartsTooltip contentStyle={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', fontSize: '12px' }} itemStyle={{ color: '#f1f5f9' }} formatter={(v, n) => [`${v} (${((v/total)*100).toFixed(1)}%)`, n]} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', textAlign: 'center', pointerEvents: 'none' }}>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: '#f1f5f9', fontFamily: 'var(--font-mono)' }}>{total.toLocaleString()}</div>
                    <div style={{ fontSize: '9px', color: '#475569', textTransform: 'uppercase', letterSpacing: '0.8px' }}>blocked</div>
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
                        <span style={{ flex: 1, fontSize: '11.5px', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.name}</span>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color }}>{pct}%</span>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#475569', minWidth: '40px', textAlign: 'right' }}>{entry.value.toLocaleString()}</span>
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
          <Globe size={14} color="#22d3ee" />
          Top Attackers
        </div>
        <div className="chart-container" style={{ minHeight: '280px' }}>
          {topIPs.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '13px', textAlign: 'center', paddingTop: '40px' }}>No malicious IPs recorded.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ fontSize: '10px', color: '#334155', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>#</th>
                  <th style={{ fontSize: '10px', color: '#334155', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 8px', letterSpacing: '0.6px', fontWeight: 600 }}>IP Address</th>
                  <th style={{ fontSize: '10px', color: '#334155', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'right', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Hits</th>
                </tr>
              </thead>
              <tbody>
                {topIPs.map((ip, idx) => (
                  <tr key={ip.ip || idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '7px 0', fontSize: '11px', color: '#334155', fontFamily: 'var(--font-mono)', width: '20px', verticalAlign: 'top' }}>{idx + 1}</td>
                    <td style={{ padding: '7px 8px', verticalAlign: 'top' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                        <span style={{ fontSize: '13px' }} title={ip.country}>{getFlagEmoji(ip.country)}</span>
                        <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#22d3ee', fontWeight: 600 }}>{ip.ip}</span>
                      </div>
                      <div style={{ width: '100%', height: '3px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min((ip.count / maxIP) * 100, 100)}%`, height: '100%', background: '#f43f5e', borderRadius: '2px', opacity: 0.75 }} />
                      </div>
                    </td>
                    <td style={{ padding: '7px 0', textAlign: 'right', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#f43f5e', fontWeight: 700, verticalAlign: 'top' }}>{ip.count.toLocaleString()}</td>
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
          <ShieldAlert size={14} color="#f43f5e" />
          Top OWASP Rules
        </div>
        <div className="chart-container" style={{ minHeight: '280px' }}>
          {topRules.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '13px', textAlign: 'center', paddingTop: '40px' }}>No rules triggered.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ fontSize: '10px', color: '#334155', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'left', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Rule ID</th>
                  <th style={{ fontSize: '10px', color: '#334155', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', textAlign: 'right', padding: '0 0 10px 0', letterSpacing: '0.6px', fontWeight: 600 }}>Triggers</th>
                </tr>
              </thead>
              <tbody>
                {topRules.map((rule) => {
                  const maxCount = topRules[0]?.count || 1;
                  const pct = ((rule.count / maxCount) * 100).toFixed(0);
                  return (
                    <tr key={rule.rule_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <td style={{ padding: '7px 0', verticalAlign: 'top' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#a78bfa', fontWeight: 700, background: 'rgba(167,139,250,0.1)', padding: '2px 6px', borderRadius: '4px' }}>{rule.rule_id}</span>
                          <span style={{ fontSize: '11px', color: '#475569' }}>OWASP CRS</span>
                        </div>
                        <div style={{ width: '100%', height: '3px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ width: `${pct}%`, height: '100%', background: '#a78bfa', borderRadius: '2px', opacity: 0.7 }} />
                        </div>
                      </td>
                      <td style={{ padding: '7px 0', textAlign: 'right', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#f59e0b', fontWeight: 700, verticalAlign: 'top' }}>{rule.count.toLocaleString()}</td>
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

