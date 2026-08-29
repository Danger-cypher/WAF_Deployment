import { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { motion } from 'framer-motion';
import { Activity, AlertTriangle, BarChart2, Clock, FileUp, Globe, RefreshCw, Shield, ShieldCheck, ShieldOff, Trash2, X } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import {
  getApiProtectionAnalytics, getDiscoveredEndpoints, getRecentlyDiscoveredEndpoints, getStaleEndpoints,
  getDdosBotSettings, saveDdosBotSettings,
  getBlockedEndpoints, blockEndpoint, unblockEndpoint,
  getApiSpec, uploadApiSpec, deleteApiSpec, getApiDrift, reconcileDataStores,
} from '../services/api';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { FetchErrorState } from '../components/EmptyStates';
import Button from '../components/Button';

// Strips a leading ^ / trailing $ so a stored rule pattern and a raw
// endpoint URI can be compared regardless of whether the pattern was
// anchored — good enough for the "already protected" badge; it doesn't
// need to replicate nginx's regex engine, just catch the common case.
const stripAnchors = (v) => (v || '').replace(/^\^/, '').replace(/\$$/, '');

// Headroom multiplier applied to an endpoint's own observed request rate.
// A slow/expensive endpoint can be overwhelmed by far fewer concurrent
// requests than a fast one (available backend capacity divided by a
// larger per-request cost), so it gets a tighter margin — same latency
// breakpoints calculate_endpoint_score already scores against
// (api_protection.py), reused here for consistency rather than inventing
// a second set of thresholds.
function headroomForLatency(avgResponseTimeMs) {
  const ms = avgResponseTimeMs || 0;
  if (ms > 2000) return 1.5;
  if (ms > 500) return 2;
  if (ms > 200) return 2.5;
  return 3;
}

// Suggests a rate limit generous enough not to block real traffic (headroom
// over the endpoint's own observed rate, tightened for slower endpoints,
// floored at a sane minimum) rather than a one-size-fits-all default —
// computed from what this endpoint has actually seen, not guessed.
function suggestLimits(ep) {
  const first = ep.first_seen ? new Date(ep.first_seen.replace(' ', 'T')).getTime() : null;
  const last = ep.last_seen ? new Date(ep.last_seen.replace(' ', 'T')).getTime() : null;
  let observedRps = 0;
  if (first && last && last > first) {
    const durationSeconds = Math.max(60, (last - first) / 1000);
    observedRps = (ep.hit_count || 0) / durationSeconds;
  }
  const headroom = headroomForLatency(ep.avg_response_time_ms);
  const rps = Math.max(5, Math.ceil(observedRps * headroom));
  const burst = rps * 2;
  return { rps, burst };
}

export default function ApiProtection() {
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [recentlyDiscovered, setRecentlyDiscovered] = useState([]);
  const [staleEndpoints, setStaleEndpoints] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [activeTab, setActiveTab] = useState('inventory'); // 'inventory', 'recent', 'stale'
  const [topListTab, setTopListTab] = useState('consumed'); // 'consumed', 'resource'

  // Protect-this-endpoint state — reuses DDoS & Bot Shield's existing
  // advanced_rules mechanism (same backend, same nginx_manager.py apply
  // path) rather than inventing a separate enforcement engine.
  const [ddosSettings, setDdosSettings] = useState(null);
  const [protectTarget, setProtectTarget] = useState(null);
  useEscapeToClose(() => setProtectTarget(null), !!protectTarget);
  const [ruleName, setRuleName] = useState('');
  const [rulePattern, setRulePattern] = useState('');
  const [ruleRps, setRuleRps] = useState(10);
  const [ruleBurst, setRuleBurst] = useState(20);
  const [savingRule, setSavingRule] = useState(false);

  // Block-this-endpoint state — a separate, blunter action from rate
  // limiting: generates a ModSecurity deny rule for the exact method+URI.
  const [blockedEndpoints, setBlockedEndpoints] = useState([]);
  const [blockingKey, setBlockingKey] = useState(null); // "METHOD uri" currently in flight

  // OpenAPI spec upload + drift detection
  const [apiSpec, setApiSpec] = useState(null); // metadata, or null if none uploaded
  const [drift, setDrift] = useState(null);
  const [driftTab, setDriftTab] = useState('shadow'); // 'shadow', 'undocumented'
  const [uploadingSpec, setUploadingSpec] = useState(false);
  const specFileInputRef = useRef(null);
  const [reconciling, setReconciling] = useState(false);

  const { toast, showToast } = useToast();
  const confirm = useConfirm();

  const isFetchingRef = useRef(false);

  const fetchData = async () => {
    // setInterval fires unconditionally regardless of whether the previous
    // 5-call fetch resolved — guard against overlapping cycles piling up
    // under any backend latency.
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    try {
      const [epsData, recentData, staleData, analyticsData, ddosData, blockedData, specData, driftData] = await Promise.all([
        getDiscoveredEndpoints(),
        getRecentlyDiscoveredEndpoints(),
        getStaleEndpoints(),
        getApiProtectionAnalytics(),
        getDdosBotSettings(),
        getBlockedEndpoints(),
        getApiSpec(),
        getApiDrift(),
      ]);
      setEndpoints(epsData);
      setRecentlyDiscovered(recentData);
      setStaleEndpoints(staleData);
      setAnalytics(analyticsData);
      setDdosSettings(ddosData);
      setBlockedEndpoints(blockedData);
      setApiSpec(specData);
      setDrift(driftData);
      setFetchError(null);
    } catch (err) {
      console.error("Failed to fetch API protection data", err);
      setFetchError(err.message || 'Failed to reach the backend API.');
    } finally {
      setLoading(false);
      isFetchingRef.current = false;
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchData();
    }, 0);
    const interval = setInterval(fetchData, 10000); // refresh every 10 seconds
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, []);

  const isProtected = (ep) => {
    const rules = ddosSettings?.advanced_rules || [];
    return rules.some(
      (r) => r.enabled && r.parameter_type === 'URI' && stripAnchors(r.parameter_value) === ep.uri
    );
  };

  const openProtectModal = (ep) => {
    const { rps, burst } = suggestLimits(ep);
    setProtectTarget(ep);
    setRuleName(`Protect ${ep.method} ${ep.uri}`);
    setRulePattern(`^${ep.uri}$`);
    setRuleRps(rps);
    setRuleBurst(burst);
  };

  const closeProtectModal = () => setProtectTarget(null);

  const handleCreateRule = async (e) => {
    e.preventDefault();
    if (!ruleName.trim() || !rulePattern.trim()) {
      showToast('Rule name and match pattern are required.', 'error');
      return;
    }
    setSavingRule(true);
    try {
      const current = await getDdosBotSettings();
      const existingRules = current.advanced_rules || [];
      if (existingRules.some((r) => r.parameter_type === 'URI' && r.parameter_value === rulePattern.trim())) {
        showToast('A rule with this exact pattern already exists — edit it from DDoS & Bot Shield instead.', 'error');
        setSavingRule(false);
        return;
      }
      const newRule = {
        id: 'rule_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        name: ruleName.trim(),
        parameter_type: 'URI',
        parameter_value: rulePattern.trim(),
        rate_limit_rps: ruleRps,
        burst_tolerance: ruleBurst,
        enabled: true,
      };
      const updated = { ...current, advanced_rules: [...existingRules, newRule] };
      await saveDdosBotSettings(updated);
      setDdosSettings(updated);
      showToast('Rate limit rule created and applied to NGINX.');
      closeProtectModal();
    } catch (err) {
      showToast('Failed to create rule: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setSavingRule(false);
    }
  };

  const isBlocked = (ep) =>
    blockedEndpoints.some((b) => b.method === ep.method && b.uri === ep.uri);

  const handleBlock = async (ep) => {
    if (!(await confirm({
      title: 'Block endpoint',
      message: `Block ALL traffic to ${ep.method} ${ep.uri}? Every request matching this exact method and path will be denied (403) at the WAF, immediately and for every client — including legitimate users. This is more aggressive than rate limiting.`,
      confirmLabel: 'Block',
      danger: true,
    }))) {
      return;
    }
    const key = `${ep.method} ${ep.uri}`;
    setBlockingKey(key);
    try {
      await blockEndpoint(ep.method, ep.uri);
      setBlockedEndpoints((prev) => [...prev, { method: ep.method, uri: ep.uri }]);
      showToast(`${ep.method} ${ep.uri} is now blocked.`);
    } catch (err) {
      showToast('Failed to block endpoint: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setBlockingKey(null);
    }
  };

  const handleUnblock = async (ep) => {
    if (!(await confirm({
      title: 'Unblock endpoint',
      message: `Remove the block on ${ep.method} ${ep.uri} and restore access?`,
      confirmLabel: 'Unblock',
    }))) {
      return;
    }
    const key = `${ep.method} ${ep.uri}`;
    setBlockingKey(key);
    try {
      await unblockEndpoint(ep.method, ep.uri);
      setBlockedEndpoints((prev) => prev.filter((b) => !(b.method === ep.method && b.uri === ep.uri)));
      showToast(`${ep.method} ${ep.uri} is no longer blocked.`);
    } catch (err) {
      showToast('Failed to unblock endpoint: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setBlockingKey(null);
    }
  };

  const handleSpecFileSelected = async (e) => {
    const file = e.target.files?.[0];
    // Clear the input immediately so selecting the same file again still fires onChange
    if (specFileInputRef.current) specFileInputRef.current.value = '';
    if (!file) return;

    setUploadingSpec(true);
    try {
      const content = await file.text();
      const result = await uploadApiSpec(file.name, content);
      showToast(`Spec uploaded: ${result.endpoint_count} operations found in ${file.name}.`);
      const [specData, driftData] = await Promise.all([getApiSpec(), getApiDrift()]);
      setApiSpec(specData);
      setDrift(driftData);
    } catch (err) {
      showToast('Failed to upload spec: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setUploadingSpec(false);
    }
  };

  const handleDeleteSpec = async () => {
    if (!(await confirm({
      title: 'Remove API spec',
      message: 'Remove the active OpenAPI/Swagger spec? Shadow-endpoint and undocumented-endpoint drift detection will stop until a new one is uploaded.',
      confirmLabel: 'Remove',
      danger: true,
    }))) {
      return;
    }
    try {
      await deleteApiSpec();
      setApiSpec(null);
      const driftData = await getApiDrift();
      setDrift(driftData);
      showToast('Spec removed.');
    } catch (err) {
      showToast('Failed to remove spec: ' + (err.message || 'Unknown error'), 'error');
    }
  };

  const handleReconcile = async () => {
    if (!(await confirm({
      title: 'Reconcile data stores',
      message: 'Backfill ClickHouse with any discovered endpoints SQLite knows about but ClickHouse is missing — typically needed after a ClickHouse outage. Safe to run anytime; it\'s a no-op if the two stores are already in sync.',
      confirmLabel: 'Reconcile',
    }))) {
      return;
    }
    setReconciling(true);
    try {
      const result = await reconcileDataStores();
      showToast(result.message);
      await fetchData();
    } catch (err) {
      showToast('Failed to reconcile data stores: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setReconciling(false);
    }
  };

  if (loading && !analytics) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: 'var(--text-secondary)', gap: '12px' }}>
        <Activity className="animate-spin" size={24} color="var(--sev-low)" />
        <span>Loading API Protection statistics & inventory...</span>
      </div>
    );
  }

  if (!loading && fetchError && !analytics) {
    return <FetchErrorState message={fetchError} onRetry={fetchData} />;
  }

  // Define grade colors
  const getGradeStyle = (grade) => {
    switch (grade) {
      case 'A': return { color: 'var(--success-color)', backgroundColor: 'rgba(16, 185, 129, 0.1)' };
      case 'B': return { color: 'var(--sev-low)', backgroundColor: 'var(--sev-low-bg)' };
      case 'C': return { color: 'var(--sev-medium)', backgroundColor: 'rgba(251, 191, 36, 0.1)' };
      case 'D': return { color: 'var(--sev-high)', backgroundColor: 'var(--sev-high-bg)' };
      default: return { color: 'var(--danger-color)', backgroundColor: 'var(--danger-bg)' };
    }
  };

  const getMethodStyle = (method) => {
    switch (method) {
      case 'GET': return { color: 'var(--success-color)', fontWeight: 'bold' };
      case 'POST': return { color: 'var(--sev-low)', fontWeight: 'bold' };
      case 'PUT': return { color: 'var(--sev-medium)', fontWeight: 'bold' };
      case 'DELETE': return { color: 'var(--danger-color)', fontWeight: 'bold' };
      default: return { color: 'var(--text-secondary)', fontWeight: 'bold' };
    }
  };

  const trafficData = analytics ? [
    { name: 'Normal', value: analytics.traffic_bands.normal, color: 'var(--success-color)' },
    { name: 'Suspicious', value: analytics.traffic_bands.suspicious, color: 'var(--sev-medium)' },
    { name: 'Malicious', value: analytics.traffic_bands.malicious, color: 'var(--danger-color)' }
  ] : [];

  const activeRows = activeTab === 'inventory' ? endpoints : activeTab === 'recent' ? recentlyDiscovered : staleEndpoints;
  const emptyStateMessage = activeTab === 'stale'
    ? "No stale endpoints — nothing discovered has gone 30+ days without traffic."
    : 'No discovered endpoints listed.';

  return (
    <motion.div
      className="api-protection-container animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
    >
      {/* Analytics Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'var(--sev-low-bg)', color: 'var(--sev-low)' }}>
            <Globe size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Total Discovered Endpoints</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>{analytics?.total_endpoints_count || 0}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: 'var(--success-color)' }}>
            <Clock size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Avg API Response Time</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>{analytics?.avg_response_time_ms || 0} ms</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'var(--danger-bg)', color: 'var(--danger-color)' }}>
            <ShieldCheck size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>WAF Intercepts (Malicious)</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)' }}>{analytics?.traffic_bands.malicious || 0}</div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        {/* Traffic Bands Chart */}
        <div className="glass-panel chart-card" style={{ gridColumn: 'span 5', padding: '20px' }}>
          <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <ShieldCheck size={18} color="var(--success-color)" />
            <span>Traffic Classification Bands</span>
          </div>
          <div style={{ height: '200px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            {trafficData.some(d => d.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficData.filter(d => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {trafficData.filter(d => d.value > 0).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: 'rgba(15, 16, 22, 0.95)', border: '1px solid var(--surface-strong)', borderRadius: '8px' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>No traffic data available</div>
            )}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '16px' }}>
            {trafficData.map(t => (
              <div key={t.name} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: t.color }}></div>
                <span style={{ color: 'var(--text-secondary)' }}>{t.name}:</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{t.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Lists Card */}
        <div className="glass-panel" style={{ gridColumn: 'span 7', padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BarChart2 size={18} color="var(--sev-low)" />
              <span>Endpoint Analytics Overview</span>
            </div>
            <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px' }}>
              <button
                className={`tab-btn ${topListTab === 'consumed' ? 'active' : ''}`}
                onClick={() => setTopListTab('consumed')}
                style={{
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  backgroundColor: topListTab === 'consumed' ? 'var(--sev-low-border)' : 'transparent',
                  color: topListTab === 'consumed' ? 'var(--sev-low)' : 'var(--text-secondary)',
                  fontWeight: topListTab === 'consumed' ? 600 : 500
                }}
              >
                Most Consumed
              </button>
              <button
                className={`tab-btn ${topListTab === 'resource' ? 'active' : ''}`}
                onClick={() => setTopListTab('resource')}
                style={{
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  backgroundColor: topListTab === 'resource' ? 'var(--sev-low-border)' : 'transparent',
                  color: topListTab === 'resource' ? 'var(--sev-low)' : 'var(--text-secondary)',
                  fontWeight: topListTab === 'resource' ? 600 : 500
                }}
              >
                Slowest (Resource-Intensive)
              </button>
            </div>
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px', justifyContent: 'center' }}>
            {topListTab === 'consumed' ? (
              analytics?.most_consumed.length > 0 ? (
                analytics.most_consumed.map((ep, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: 'var(--text-primary)', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Hits: <strong style={{ color: 'var(--text-primary)' }}>{ep.hit_count}</strong></span>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, ...getGradeStyle(ep.grade) }}>Grade {ep.grade}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center' }}>No endpoints discovered yet</div>
              )
            ) : (
              analytics?.resource_intensive.length > 0 ? (
                analytics.resource_intensive.map((ep, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: 'var(--text-primary)', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Latency: <strong style={{ color: 'var(--danger-color)' }}>{ep.avg_response_time_ms} ms</strong></span>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, ...getGradeStyle(ep.grade) }}>Grade {ep.grade}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: 'var(--text-secondary)', fontSize: '13px', textAlign: 'center' }}>No resource-intensive endpoints detected</div>
              )
            )}
          </div>
        </div>
      </div>

      {/* Main Inventory Section */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px' }}>
            <button
              className={`tab-btn ${activeTab === 'inventory' ? 'active' : ''}`}
              onClick={() => setActiveTab('inventory')}
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'inventory' ? 'var(--sev-low-border)' : 'transparent',
                color: activeTab === 'inventory' ? 'var(--sev-low)' : 'var(--text-secondary)',
                fontWeight: activeTab === 'inventory' ? 600 : 500
              }}
            >
              API Inventory
            </button>
            <button
              className={`tab-btn ${activeTab === 'recent' ? 'active' : ''}`}
              onClick={() => setActiveTab('recent')}
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'recent' ? 'var(--sev-low-border)' : 'transparent',
                color: activeTab === 'recent' ? 'var(--sev-low)' : 'var(--text-secondary)',
                fontWeight: activeTab === 'recent' ? 600 : 500
              }}
            >
              Recently Discovered (Last 48h)
            </button>
            <button
              className={`tab-btn ${activeTab === 'stale' ? 'active' : ''}`}
              onClick={() => setActiveTab('stale')}
              title="Endpoints that used to receive traffic but haven't in 30+ days — possible deprecated/forgotten routes"
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'stale' ? 'var(--sev-low-border)' : 'transparent',
                color: activeTab === 'stale' ? 'var(--sev-low)' : 'var(--text-secondary)',
                fontWeight: activeTab === 'stale' ? 600 : 500
              }}
            >
              Stale / Zombie (30d+){staleEndpoints.length > 0 ? ` (${staleEndpoints.length})` : ''}
            </button>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="refresh-btn"
              onClick={handleReconcile}
              disabled={reconciling}
              title="Backfill ClickHouse with endpoints SQLite knows about but ClickHouse is missing — needed after a ClickHouse outage. Safe to run anytime."
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--surface-strong)', backgroundColor: 'transparent', color: 'var(--text-primary)', cursor: 'pointer', fontSize: '12px' }}
            >
              <RefreshCw size={12} className={reconciling ? 'animate-spin' : ''} /> {reconciling ? 'Reconciling...' : 'Reconcile Data Stores'}
            </button>
            <button className="refresh-btn" onClick={fetchData} style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--surface-strong)', backgroundColor: 'transparent', color: 'var(--text-primary)', cursor: 'pointer', fontSize: '12px' }}>
              Scan Logs Now
            </button>
          </div>
        </div>

        {/* Table representation — scrolls within its own fixed-height area
            instead of pushing the rest of the page down, since inventory
            can run into the hundreds of rows. */}
        <div style={{ maxHeight: '520px', overflowY: 'auto', overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--surface-strong)', color: 'var(--text-secondary)', position: 'sticky', top: 0, zIndex: 1, backgroundColor: 'var(--glass-bg)' }}>
                <th style={{ padding: '12px 8px' }}>Method</th>
                <th style={{ padding: '12px 8px' }}>Endpoint URI</th>
                <th style={{ padding: '12px 8px' }}>Avg Latency</th>
                <th style={{ padding: '12px 8px' }}>Requests</th>
                <th style={{ padding: '12px 8px' }}>Traffic Source</th>
                <th style={{ padding: '12px 8px' }}>TLS</th>
                <th style={{ padding: '12px 8px' }}>Compression</th>
                <th style={{ padding: '12px 8px' }}>Score</th>
                <th style={{ padding: '12px 8px' }}>Grade</th>
                <th style={{ padding: '12px 8px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {activeRows.length > 0 ? (
                activeRows.map((ep, idx) => {
                  // Traffic Source badge styles
                  const trafficSource = ep.traffic_source || 'Unknown';
                  const trafficBadgeStyle = (() => {
                    switch (trafficSource) {
                      case 'External': return { color: 'var(--sev-low)', background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)' };
                      case 'Internal': return { color: 'var(--success-color)', background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)' };
                      case 'Mixed': return { color: 'var(--sev-medium)', background: 'rgba(251,191,36,0.12)', border: '1px solid rgba(251,191,36,0.3)' };
                      default: return { color: 'var(--text-muted)', background: 'rgba(113,113,122,0.12)', border: '1px solid rgba(113,113,122,0.3)' };
                    }
                  })();
                  const trafficIcon = { External: '🌐', Internal: '🏠', Mixed: '🔀', Unknown: '❓' }[trafficSource] || '❓';

                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                      <td style={{ padding: '12px 8px', ...getMethodStyle(ep.method) }}>{ep.method}</td>
                      <td style={{ padding: '12px 8px', fontFamily: 'monospace' }}>
                        <div>{ep.uri}</div>
                        {ep.sensitive_params?.length > 0 && (
                          <div
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '4px', padding: '2px 8px', borderRadius: '6px', fontSize: '10px', fontWeight: 600, fontFamily: 'inherit', color: 'var(--sev-medium)', background: 'rgba(251,191,36,0.12)', border: '1px solid rgba(251,191,36,0.3)' }}
                            title={`Query param name(s) look sensitive — values are never captured, only names. Worth a human look, not an automatic finding: ${ep.sensitive_params.join(', ')}`}
                          >
                            <AlertTriangle size={10} /> {ep.sensitive_params.length} sensitive param{ep.sensitive_params.length > 1 ? 's' : ''}: {ep.sensitive_params.join(', ')}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '12px 8px' }}>
                        <div>{ep.avg_response_time_ms} ms</div>
                        {(ep.p95_response_time_ms > 0 || ep.p99_response_time_ms > 0) && (
                          <div
                            style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}
                            title="95th/99th percentile of this endpoint's per-interval average latency — approximates tail latency without per-request storage, so it distinguishes occasional slow windows from consistently slow ones. Not a true per-request percentile."
                          >
                            p95 {ep.p95_response_time_ms}ms · p99 {ep.p99_response_time_ms}ms
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '12px 8px' }}>{ep.hit_count}</td>
                      <td style={{ padding: '12px 8px' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '3px 10px',
                          borderRadius: '6px',
                          fontSize: '11px',
                          fontWeight: 600,
                          ...trafficBadgeStyle,
                        }}>
                          {trafficIcon} {trafficSource}
                        </span>
                      </td>
                      <td style={{ padding: '12px 8px', color: ep.has_https === 1 ? 'var(--success-color)' : ep.has_https === 0 ? 'var(--danger-color)' : 'var(--text-muted)' }}>
                        {ep.has_https === 1 ? 'HTTPS' : ep.has_https === 0 ? 'HTTP' : 'Unknown'}
                      </td>
                      <td style={{ padding: '12px 8px', color: ep.content_encoding === 'unknown' ? 'var(--text-muted)' : (ep.content_encoding ? 'var(--success-color)' : 'var(--text-secondary)') }}>
                        {ep.content_encoding === 'unknown' ? 'Unknown' : (ep.content_encoding || 'none')}
                      </td>
                      <td style={{ padding: '12px 8px', fontWeight: 600 }}>{ep.score} / 100</td>
                      <td style={{ padding: '12px 8px' }}>
                        <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 700, ...getGradeStyle(ep.grade) }}>
                          {ep.grade}
                        </span>
                      </td>
                      <td style={{ padding: '12px 8px' }}>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                          {isProtected(ep) ? (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--success-color)', background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)' }}>
                              <ShieldCheck size={12} /> Protected
                            </span>
                          ) : (
                            <button
                              onClick={() => openProtectModal(ep)}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--sev-low)', background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)', cursor: 'pointer' }}
                            >
                              <Shield size={12} /> Protect
                            </button>
                          )}
                          {isBlocked(ep) ? (
                            <button
                              onClick={() => handleUnblock(ep)}
                              disabled={blockingKey === `${ep.method} ${ep.uri}`}
                              title="Click to remove this block"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--danger-color)', background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', cursor: 'pointer' }}
                            >
                              <ShieldOff size={12} /> Blocked
                            </button>
                          ) : (
                            <button
                              onClick={() => handleBlock(ep)}
                              disabled={blockingKey === `${ep.method} ${ep.uri}`}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 600, color: 'var(--danger-color)', background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', cursor: 'pointer' }}
                            >
                              <AlertTriangle size={12} /> Block
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="10" style={{ padding: '32px 8px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                    {emptyStateMessage}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </div>

      {/* OpenAPI Spec Upload + Drift Detection */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileUp size={18} color="var(--sev-low)" />
              <span>OpenAPI / Swagger Drift Detection</span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px', marginBottom: 0, maxWidth: '640px', lineHeight: 1.5 }}>
              Upload your API's OpenAPI or Swagger spec (JSON or YAML) to compare it against real observed
              traffic — endpoints hit in production but never documented (shadow endpoints), and documented
              endpoints nobody's actually seen hit. Compares paths and methods only, not schemas or auth.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexShrink: 0 }}>
            {apiSpec && (
              <Button variant="secondary" size="sm" icon={Trash2} onClick={handleDeleteSpec}>
                Remove Spec
              </Button>
            )}
            <input
              ref={specFileInputRef}
              type="file"
              accept=".json,.yaml,.yml"
              onChange={handleSpecFileSelected}
              style={{ display: 'none' }}
            />
            <button
              onClick={() => specFileInputRef.current?.click()}
              disabled={uploadingSpec}
              className="modal-btn primary"
              style={{ margin: 0, display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <FileUp size={14} /> {uploadingSpec ? 'Uploading...' : apiSpec ? 'Replace Spec' : 'Upload Spec'}
            </button>
          </div>
        </div>

        {apiSpec && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '20px', padding: '12px 16px', backgroundColor: 'var(--surface-subtle)', borderRadius: '8px', fontSize: '12px' }}>
            <div><span style={{ color: 'var(--text-secondary)' }}>File: </span><span style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'monospace' }}>{apiSpec.filename}</span></div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Version: </span><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{apiSpec.version}</span></div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Documented operations: </span><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{apiSpec.endpoint_count}</span></div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Uploaded by: </span><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{apiSpec.uploaded_by}</span></div>
          </div>
        )}

        {!apiSpec ? (
          <div style={{ padding: '32px 8px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>
            No spec uploaded yet — upload one to see shadow-endpoint and undocumented-endpoint drift.
          </div>
        ) : (
          <>
            <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px', width: 'fit-content' }}>
              <button
                className={`tab-btn ${driftTab === 'shadow' ? 'active' : ''}`}
                onClick={() => setDriftTab('shadow')}
                style={{
                  border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '13px', cursor: 'pointer',
                  backgroundColor: driftTab === 'shadow' ? 'var(--sev-low-border)' : 'transparent',
                  color: driftTab === 'shadow' ? 'var(--sev-low)' : 'var(--text-secondary)',
                  fontWeight: driftTab === 'shadow' ? 600 : 500,
                }}
              >
                Shadow Endpoints (undocumented){drift?.shadow_endpoints?.length > 0 ? ` (${drift.shadow_endpoints.length})` : ''}
              </button>
              <button
                className={`tab-btn ${driftTab === 'undocumented' ? 'active' : ''}`}
                onClick={() => setDriftTab('undocumented')}
                title="Documented in the spec, never observed in traffic"
                style={{
                  border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '13px', cursor: 'pointer',
                  backgroundColor: driftTab === 'undocumented' ? 'var(--sev-low-border)' : 'transparent',
                  color: driftTab === 'undocumented' ? 'var(--sev-low)' : 'var(--text-secondary)',
                  fontWeight: driftTab === 'undocumented' ? 600 : 500,
                }}
              >
                Never Observed (spec-only){drift?.undocumented_spec_endpoints?.length > 0 ? ` (${drift.undocumented_spec_endpoints.length})` : ''}
              </button>
            </div>

            {driftTab === 'shadow' ? (
              drift?.shadow_endpoints?.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {drift.shadow_endpoints.map((ep, idx) => (
                    <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px' }}>
                      <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                        <AlertTriangle size={14} color="var(--sev-medium)" />
                        <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                        <span style={{ color: 'var(--text-primary)', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                      </div>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Hits: <strong style={{ color: 'var(--text-primary)' }}>{ep.hit_count}</strong></span>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '24px 8px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>
                  No shadow endpoints — every observed endpoint matches something in the spec.
                </div>
              )
            ) : (
              drift?.undocumented_spec_endpoints?.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {drift.undocumented_spec_endpoints.map((ep, idx) => (
                    <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '10px 14px', backgroundColor: 'var(--surface-subtle)', borderRadius: '6px' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: 'var(--text-primary)', fontSize: '13px', fontFamily: 'monospace' }}>{ep.path_template}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '24px 8px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>
                  Every documented endpoint has been observed in real traffic.
                </div>
              )
            )}
          </>
        )}
      </div>

      <Toast toast={toast} />

      {protectTarget && createPortal(
        <div
          style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'var(--overlay-bg)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}
          onClick={closeProtectModal}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: 'rgba(20, 20, 20, 0.97)', border: '1px solid var(--border-strong)', borderRadius: '16px', padding: '28px', width: '100%', maxWidth: '480px', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)' }}>Protect Endpoint</h3>
                <div style={{ marginTop: '4px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                  {protectTarget.method} {protectTarget.uri}
                </div>
              </div>
              <Button variant="ghost" size="md" icon={X} onClick={closeProtectModal} aria-label="Close" />
            </div>

            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: 0, marginBottom: '18px', lineHeight: 1.5 }}>
              This creates a rate-limit rule using the same engine as DDoS &amp; Bot Shield's Advanced
              Rate Limiting Rules — it'll also show up (and stay editable) there.
            </p>

            {headroomForLatency(protectTarget.avg_response_time_ms) < 3 && (
              <p style={{ fontSize: '12px', color: 'var(--warning-color, #d97706)', marginTop: '-10px', marginBottom: '18px', lineHeight: 1.5 }}>
                This endpoint averages {protectTarget.avg_response_time_ms}ms — the suggested limit
                below uses a tighter headroom than usual, since a slower endpoint can be overwhelmed
                by fewer concurrent requests.
              </p>
            )}

            <form onSubmit={handleCreateRule} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label htmlFor="rl-rule-name" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Rule Name</label>
                <input
                  id="rl-rule-name"
                  type="text"
                  className="search-input"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label htmlFor="rl-rule-pattern" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Match Pattern (Request URI)</label>
                <input
                  id="rl-rule-pattern"
                  type="text"
                  className="search-input"
                  style={{ fontFamily: 'monospace' }}
                  value={rulePattern}
                  onChange={(e) => setRulePattern(e.target.value)}
                />
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Case-insensitive regex against the request URI. Anchored (^...$) to match only this
                  exact path — remove the anchors to also cover similar paths (e.g. dynamic IDs).
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label htmlFor="rl-rate-limit" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Rate Limit</label>
                    <span style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 600 }}>{ruleRps} req/s</span>
                  </div>
                  <input
                    id="rl-rate-limit"
                    type="range" min="1" max="500"
                    value={ruleRps} onChange={(e) => setRuleRps(parseInt(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent-color)' }}
                  />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label htmlFor="rl-burst-tolerance" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Burst Tolerance</label>
                    <span style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 600 }}>{ruleBurst} reqs</span>
                  </div>
                  <input
                    id="rl-burst-tolerance"
                    type="range" min="1" max="1000"
                    value={ruleBurst} onChange={(e) => setRuleBurst(parseInt(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent-color)' }}
                  />
                </div>
              </div>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '-8px' }}>
                Suggested from this endpoint's own observed traffic (3x its typical rate) — adjust if needed.
              </span>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '4px' }}>
                <Button type="button" variant="secondary" onClick={closeProtectModal}>
                  Cancel
                </Button>
                <button type="submit" disabled={savingRule} className="modal-btn primary" style={{ margin: 0 }}>
                  {savingRule ? 'Applying to NGINX...' : 'Create and Apply Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}
    </motion.div>
  );
}

