import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Activity, Database, Server } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { getDdosBotSettings, saveDdosBotSettings, getDdosAnalytics } from '../services/api';
import { useToast } from '../hooks/useToast';
import Toast from './Toast';

export default function DdosBotMitigation() {
  const [rateLimitRps, setRateLimitRps] = useState(50);
  const [burstTolerance, setBurstTolerance] = useState(100);
  const [trustedIps, setTrustedIps] = useState("");
  const [botMitigationAction, setBotMitigationAction] = useState("Silent Drop");

  // Advanced Rate Limiting State
  const [advancedRules, setAdvancedRules] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleType, setNewRuleType] = useState("URI");
  const [newRuleValue, setNewRuleValue] = useState("");
  const [newRuleRps, setNewRuleRps] = useState(10);
  const [newRuleBurst, setNewRuleBurst] = useState(20);

  const [loadingAction, setLoadingAction] = useState(false);
  const { toast, showToast } = useToast();

  const [analytics, setAnalytics] = useState({
    timeline: [],
    top_ips: [],
    total_blocks: 0,
    total_unique_ips: 0
  });

  const fetchSettings = async () => {
    try {
      const ddos = await getDdosBotSettings();
      if (ddos) {
        if (ddos.rate_limit_rps !== undefined) setRateLimitRps(ddos.rate_limit_rps);
        if (ddos.burst_tolerance !== undefined) setBurstTolerance(ddos.burst_tolerance);
        if (ddos.trusted_ips !== undefined) setTrustedIps(ddos.trusted_ips.join(', '));
        if (ddos.bot_mitigation_action) setBotMitigationAction(ddos.bot_mitigation_action);
        if (ddos.advanced_rules !== undefined) setAdvancedRules(ddos.advanced_rules);
      }
    } catch (err) {
      console.error("Failed to load DDoS settings", err);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const data = await getDdosAnalytics();
      if (data) setAnalytics(data);
    } catch (err) {
      console.error("Failed to fetch DDoS analytics", err);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchSettings();
      fetchAnalytics();
    }, 0);
    const interval = setInterval(fetchAnalytics, 3000);
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, []);

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const ips = trustedIps.split(',').map(ip => ip.trim()).filter(ip => ip);
      await saveDdosBotSettings({
        rate_limit_rps: rateLimitRps,
        burst_tolerance: burstTolerance,
        trusted_ips: ips,
        bot_mitigation_action: botMitigationAction,
        advanced_rules: advancedRules
      });
      showToast("Anti-DDoS & Bot Mitigation settings updated successfully.");
    } catch (err) {
      showToast("Failed to update Anti-DDoS settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const saveWithRules = async (updatedRules) => {
    setLoadingAction(true);
    try {
      const ips = trustedIps.split(',').map(ip => ip.trim()).filter(ip => ip);
      await saveDdosBotSettings({
        rate_limit_rps: rateLimitRps,
        burst_tolerance: burstTolerance,
        trusted_ips: ips,
        bot_mitigation_action: botMitigationAction,
        advanced_rules: updatedRules
      });
      setAdvancedRules(updatedRules);
      showToast("Advanced rate limiting rules updated and applied to NGINX.");
    } catch (err) {
      showToast("Failed to apply advanced rules: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleAddRule = (e) => {
    e.preventDefault();
    if (!newRuleName.trim() || !newRuleValue.trim()) {
      showToast("Rule name and match pattern are required.", "error");
      return;
    }
    const newRule = {
      // FIX 12: Prevent ID collision with random suffix on fast-add
      id: "rule_" + Date.now() + "_" + Math.random().toString(36).substr(2, 5),
      name: newRuleName.trim(),
      parameter_type: newRuleType,
      parameter_value: newRuleValue.trim(),
      rate_limit_rps: newRuleRps,
      burst_tolerance: newRuleBurst,
      enabled: true
    };
    const updated = [...advancedRules, newRule];
    saveWithRules(updated);
    setNewRuleName("");
    setNewRuleValue("");
    setNewRuleRps(10);
    setNewRuleBurst(20);
    setShowAddForm(false);
  };

  const handleToggleRule = (ruleId) => {
    const updated = advancedRules.map(r =>
      r.id === ruleId ? { ...r, enabled: !r.enabled } : r
    );
    saveWithRules(updated);
  };

  const handleDeleteRule = (ruleId) => {
    const updated = advancedRules.filter(r => r.id !== ruleId);
    saveWithRules(updated);
  };

  return (
    <motion.div
      className="dashboard-grid animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Toast Alert overlay */}
      <Toast toast={toast} />

      {/* Settings Form */}
      <div className="glass-panel" style={{ gridColumn: 'span 4', padding: '24px' }}>
        <div style={{ fontSize: '15px', fontWeight: 600, color: '#f4f4f5', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <AlertTriangle size={16} color="#ef4444" />
          <span>Mitigation Configuration</span>
        </div>
        <form onSubmit={handleSaveSettings} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label style={{ fontSize: '13px', color: '#e4e4e7', fontWeight: 500 }}>L7 Rate Limit (RPS)</label>
              <span style={{ fontSize: '12px', color: '#f4f4f5', fontWeight: 600 }}>{rateLimitRps} req/s</span>
            </div>
            <div style={{ fontSize: '11px', color: '#a1a1aa', marginBottom: '8px' }}>
              Maximum requests per second allowed per client IP before dropping.
            </div>
            <input
              type="range" min="10" max="500"
              value={rateLimitRps} onChange={(e) => setRateLimitRps(parseInt(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-color)' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label style={{ fontSize: '13px', color: '#e4e4e7', fontWeight: 500 }}>Burst Tolerance</label>
              <span style={{ fontSize: '12px', color: '#f4f4f5', fontWeight: 600 }}>{burstTolerance} requests</span>
            </div>
            <div style={{ fontSize: '11px', color: '#a1a1aa', marginBottom: '8px' }}>
              Number of excessive requests allowed in a burst before rate limit applies.
            </div>
            <input
              type="range" min="10" max="1000"
              value={burstTolerance} onChange={(e) => setBurstTolerance(parseInt(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-color)' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '13px', color: '#e4e4e7', fontWeight: 500 }}>Trusted IP Allowlist</label>
            <div style={{ fontSize: '11px', color: '#a1a1aa', marginBottom: '4px' }}>
              Comma-separated IPs or subnets that bypass all WAF rules (e.g., 10.0.0.1, 192.168.1.0/24).
            </div>
            <textarea
              className="search-input"
              style={{ width: '100%', height: '60px', resize: 'vertical', fontSize: '12px', fontFamily: 'monospace' }}
              placeholder="Enter trusted IPs..."
              value={trustedIps}
              onChange={(e) => setTrustedIps(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '13px', color: '#e4e4e7', fontWeight: 500 }}>Mitigation Action</label>
            <div style={{ fontSize: '11px', color: '#a1a1aa', marginBottom: '4px' }}>
              Action to take when suspicious automation is detected.
            </div>
            <select
              className="search-input"
              style={{ width: '100%', fontSize: '12px' }}
              value={botMitigationAction}
              onChange={(e) => setBotMitigationAction(e.target.value)}
            >
              <option value="Silent Drop">Silent Drop (Connection Reset / 444)</option>
              <option value="Block">Standard Block (429 Too Many Requests)</option>
              {/* FIX 7: CAPTCHA is not integrated — disable to avoid misleading operators */}
              <option value="CAPTCHA Challenge" disabled>
                CAPTCHA Challenge (Coming Soon — requires provider integration)
              </option>
            </select>
          </div>

          <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ marginTop: '4px', alignSelf: 'flex-start' }}>
            {loadingAction ? 'Applying to NGINX...' : 'Enforce Policy'}
          </button>
        </form>
      </div>

      {/* Right side analytics */}
      <div style={{ gridColumn: 'span 8', display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* Metric Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          <div className="metric-card glass-panel" style={{ gridColumn: 'span 1' }}>
            <div className="metric-header">
              <span>Total Blocked (DDoS)</span>
              <div className="metric-icon-wrapper red"><AlertTriangle size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: '#ef4444' }}>{analytics.total_blocks.toLocaleString()}</div>
            <div className="metric-trend trend-up">
              <div className="pulse-dot" style={{ marginRight: '6px' }}></div>
              <span>Live enforcement active</span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 1' }}>
            <div className="metric-header">
              <span>Unique Blocked IPs</span>
              <div className="metric-icon-wrapper orange"><Server size={18} /></div>
            </div>
            {/* FIX 11: Show true total from backend, not top_ips.length (capped at 10) */}
            <div className="metric-value" style={{ color: '#fb923c' }}>{analytics.total_unique_ips.toLocaleString()}</div>
            <div className="metric-trend trend-down">
              <span>Distinct offenders tracked</span>
            </div>
          </div>
        </div>

        {/* Traffic Graph */}
        <div className="chart-card glass-panel" style={{ flex: 1, minHeight: '300px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              <Activity size={18} color="#3b82f6" />
              Traffic Graph (Blocked Requests)
            </div>
            <div className="pulse-container">
              <div className="pulse-dot"></div>
              <span>Live Sync</span>
            </div>
          </div>
          <div className="chart-container" style={{ minHeight: '250px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analytics.timeline}>
                <defs>
                  <linearGradient id="colorDdos" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={50} />
                <YAxis stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} />
                <RechartsTooltip
                  contentStyle={{ backgroundColor: 'rgba(15, 16, 22, 0.95)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Area type="monotone" dataKey="blocked" name="Dropped Connections" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorDdos)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Advanced Rate Limiting Rules Card */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <div style={{ fontSize: '15px', fontWeight: 600, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={18} color="#3b82f6" />
            <span>Advanced Rate Limiting Rules</span>
          </div>
          <button
            type="button"
            onClick={() => setShowAddForm(!showAddForm)}
            className="modal-btn primary"
            style={{ margin: 0 }}
          >
            {showAddForm ? 'Cancel' : '+ Add Advanced Rule'}
          </button>
        </div>

        {showAddForm && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: '8px',
              padding: '20px',
              marginBottom: '24px'
            }}
          >
            <form onSubmit={handleAddRule} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Rule Name</label>
                  <input
                    type="text"
                    className="search-input"
                    value={newRuleName}
                    onChange={(e) => setNewRuleName(e.target.value)}
                    placeholder="e.g., Login Page Rate Limit"
                  />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Match Parameter Type</label>
                  <select
                    className="search-input"
                    value={newRuleType}
                    onChange={(e) => setNewRuleType(e.target.value)}
                  >
                    <option value="URI">Request URI</option>
                    <option value="Method">HTTP Method</option>
                    <option value="Header">Custom Header (Header-Name: Pattern)</option>
                    <option value="Session">Session Cookie (Cookie-Name)</option>
                    <option value="Referrer">Referrer</option>
                    <option value="Content-Type">Content-Type</option>
                    <option value="IP">Client IP / Subnet</option>
                    <option value="Country">Country (2-Letter ISO Code)</option>
                    <option value="ISP/ASN">ISP / Autonomous System (Name or ASN ID)</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Match Pattern / Value</label>
                <input
                  type="text"
                  className="search-input"
                  value={newRuleValue}
                  onChange={(e) => setNewRuleValue(e.target.value)}
                  placeholder={
                    newRuleType === 'URI' ? 'e.g., ^/api/login' :
                      newRuleType === 'Method' ? 'e.g., POST' :
                        newRuleType === 'Header' ? 'e.g., X-API-Key (limits per key) OR X-API-Key: ^temp-.*' :
                          newRuleType === 'Session' ? 'e.g., session (limits per session cookie value)' :
                            newRuleType === 'Referrer' ? 'e.g., google.com' :
                              newRuleType === 'Content-Type' ? 'e.g., application/json' :
                                newRuleType === 'Country' ? 'e.g., CN or RU (requires Country DB)' :
                                  newRuleType === 'ISP/ASN' ? 'e.g., Google or 15169 (requires ASN DB)' :
                                    'e.g., 192.168.1.100'
                  }
                />
                <span style={{ fontSize: '11px', color: '#71717a' }}>Matches use case-insensitive regex pattern mapping. Leave Header/Session value pattern empty to rate limit by unique value.</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Rate Limit (RPS)</label>
                    <span style={{ fontSize: '12px', color: '#fff', fontWeight: 600 }}>{newRuleRps} req/s</span>
                  </div>
                  <input
                    type="range" min="1" max="200"
                    value={newRuleRps} onChange={(e) => setNewRuleRps(parseInt(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent-color)' }}
                  />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Burst Tolerance</label>
                    <span style={{ fontSize: '12px', color: '#fff', fontWeight: 600 }}>{newRuleBurst} requests</span>
                  </div>
                  <input
                    type="range" min="1" max="500"
                    value={newRuleBurst} onChange={(e) => setNewRuleBurst(parseInt(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent-color)' }}
                  />
                </div>
              </div>

              <button
                type="submit"
                className="modal-btn primary"
                style={{ alignSelf: 'flex-start', margin: 0 }}
              >
                Create and Apply Rule
              </button>
            </form>
          </motion.div>
        )}

        <div className="logs-table-wrapper">
          <table className="logs-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>Active</th>
                <th>Rule Name</th>
                <th>Parameter</th>
                <th>Match Pattern</th>
                <th style={{ textAlign: 'right' }}>RPS Limit</th>
                <th style={{ textAlign: 'right' }}>Burst Limit</th>
                <th style={{ textAlign: 'center', width: '100px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {advancedRules.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '30px', color: '#a1a1aa' }}>
                    No advanced rate limiting rules configured.
                  </td>
                </tr>
              ) : (
                advancedRules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <div
                        className={`toggle-switch ${rule.enabled ? 'active' : ''}`}
                        onClick={() => handleToggleRule(rule.id)}
                        style={{ transform: 'scale(0.85)', margin: 0 }}
                      >
                        <div className="toggle-knob"></div>
                      </div>
                    </td>
                    <td style={{ fontWeight: 500, color: '#f4f4f5' }}>{rule.name}</td>
                    <td style={{ color: '#3b82f6', fontWeight: 600 }}>{rule.parameter_type}</td>
                    <td style={{ fontFamily: 'monospace', color: '#a1a1aa', fontSize: '12px' }}>{rule.parameter_value}</td>
                    <td style={{ textAlign: 'right', fontWeight: 500, color: '#10b981' }}>{rule.rate_limit_rps} req/s</td>
                    <td style={{ textAlign: 'right', fontWeight: 500, color: '#fb923c' }}>{rule.burst_tolerance} reqs</td>
                    <td style={{ textAlign: 'center' }}>
                      <button
                        type="button"
                        onClick={() => handleDeleteRule(rule.id)}
                        className="action-btn-inspect"
                        style={{
                          background: 'rgba(239, 68, 68, 0.1)',
                          color: '#ef4444',
                          borderColor: 'rgba(239, 68, 68, 0.2)',
                          padding: '4px 10px',
                          fontSize: '11px',
                          margin: 0
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom: Top IPs */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 12' }}>
        <div className="card-title">
          <Database size={18} color="#f97316" />
          Top Offending IPs (Rate Limit Hits)
        </div>
        <div className="logs-table-wrapper" style={{ marginTop: '16px' }}>
          <table className="logs-table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Source IP Address</th>
                <th style={{ textAlign: 'right' }}>Total Blocked Requests</th>
              </tr>
            </thead>
            <tbody>
              {analytics.top_ips.length === 0 ? (
                <tr>
                  <td colSpan="3" style={{ textAlign: 'center', padding: '30px', color: '#a1a1aa' }}>
                    No IPs currently rate-limited.
                  </td>
                </tr>
              ) : (
                analytics.top_ips.map((ipObj, index) => (
                  <tr key={ipObj.ip}>
                    <td style={{ color: '#a1a1aa' }}>#{index + 1}</td>
                    <td style={{ fontFamily: 'monospace', color: '#3b82f6', fontWeight: 500 }}>{ipObj.ip}</td>
                    <td style={{ textAlign: 'right', fontWeight: 600, color: '#ef4444' }}>{ipObj.count.toLocaleString()}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );
}
