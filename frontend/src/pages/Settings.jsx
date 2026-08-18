import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Brain, CheckSquare, Database, FileCode, Lock, RotateCw, Server, Settings as SettingsIcon, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import {
  getGeneralSettings, saveGeneralSettings, getLogSettings, saveLogSettings,
  getWafSettings, saveWafSettings,
  changeAdminPassword, restartWafEngine, reloadNginxProxy, purgeStatsCache, syncSignatures,
  getHardeningSettings, saveHardeningSettings, getAntiDefacementSettings, saveAntiDefacementSettings,
  getPositiveSecurity, savePositiveSecurity,
  getCustomResponse, saveCustomResponse, getAutoLearning, saveAutoLearning,
  getAutoLearningSuggestions, runAutoLearningNow, approveAutoLearningSuggestion, rejectAutoLearningSuggestion,
} from '../services/api';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import Button from '../components/Button';

export default function Settings({ onLogout }) {
  // General Settings
  const [refreshInterval, setRefreshInterval] = useState('5s');
  const [logsPerPage, setLogsPerPage] = useState('15');
  const [liveUpdates, setLiveUpdates] = useState(true);

  // WAF Settings
  const [secRuleEngine, setSecRuleEngine] = useState('On');
  const [detectionMode, setDetectionMode] = useState('Blocking');
  const [paranoiaLevel, setParanoiaLevel] = useState(1);

  // Log Settings
  const [auditEnabled, setAuditEnabled] = useState(true);
  const [logFormat, setLogFormat] = useState('JSON');
  const [concurrentLogging, setConcurrentLogging] = useState(true);
  const [retention, setRetention] = useState('30 Days');

  // Security Settings
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [sessionTimeout, setSessionTimeout] = useState('1h');



  // Hardening & Cloaking Settings
  const [hstsEnabled, setHstsEnabled] = useState(true);
  const [hstsMaxAge, setHstsMaxAge] = useState(31536000);
  const [serverCloaking, setServerCloaking] = useState(true);
  const [ipBlacklist, setIpBlacklist] = useState("");
  const [ipWhitelist, setIpWhitelist] = useState("");

  // Anti-Defacement Settings
  const [defacementEnabled, setDefacementEnabled] = useState(true);
  const [defacementFiles, setDefacementFiles] = useState("");
  const [checkInterval, setCheckInterval] = useState(5);

  // Positive Security Settings — applies only to protected apps' own
  // traffic (never the WAF GUI's own dashboard API, see backend/app/
  // services/nginx_manager.py for how that's scoped).
  const [posSecEnabled, setPosSecEnabled] = useState(false);
  const [posSecMethods, setPosSecMethods] = useState("");
  const [posSecContentTypes, setPosSecContentTypes] = useState("");
  const [posSecExtensions, setPosSecExtensions] = useState("");

  // Custom Response (WAF block page) Settings
  const [customResponseHtml, setCustomResponseHtml] = useState("");

  // Auto-Learning Settings — feeds observed "normal" traffic back into
  // baseline tuning so it converges on real usage instead of a guessed default.
  const [autoLearningEnabled, setAutoLearningEnabled] = useState(false);
  const [autoLearningPeriod, setAutoLearningPeriod] = useState('7 Days');
  const [autoLearningThreshold, setAutoLearningThreshold] = useState(90);
  // Pending exclusion suggestions Auto-Learning has computed from Resolved
  // false positives — never auto-applied, an admin must Approve/Reject each.
  const [autoLearningSuggestions, setAutoLearningSuggestions] = useState([]);
  const [suggestionsLoading, setSuggestionsLoading] = useState(false);
  const [runningNow, setRunningNow] = useState(false);
  const [suggestionActionId, setSuggestionActionId] = useState(null);

  // Notifications & State Controls
  const { toast, showToast } = useToast();
  const confirm = useConfirm();
  const [dangerModal, setDangerModal] = useState(null);
  useEscapeToClose(() => setDangerModal(null), !!dangerModal);
  const [loadingAction, setLoadingAction] = useState(false);
  const [activeSettingTab, setActiveSettingTab] = useState('general');
  // Previously a failed initial load only did console.error, leaving every
  // tab showing hardcoded defaults with zero visible signal that they don't
  // reflect real WAF config — an admin could edit and save right over real
  // settings without ever knowing the load failed.
  const [settingsLoadError, setSettingsLoadError] = useState('');

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setSettingsLoadError('');
    try {
        const [gen, logs, waf, hardening, defacement, positiveSecurity, customResponse, autoLearning] = await Promise.all([
          getGeneralSettings(),
          getLogSettings(),
          getWafSettings(),
          getHardeningSettings(),
          getAntiDefacementSettings(),
          getPositiveSecurity(),
          getCustomResponse(),
          getAutoLearning(),
        ]);

        if (gen) {
          if (gen.refreshInterval) setRefreshInterval(gen.refreshInterval);
          if (gen.logsPerPage) setLogsPerPage(gen.logsPerPage);
          if (gen.liveUpdates !== undefined) setLiveUpdates(gen.liveUpdates);
        }
        if (logs) {
          if (logs.auditEnabled !== undefined) setAuditEnabled(logs.auditEnabled);
          if (logs.logFormat) setLogFormat(logs.logFormat);
          if (logs.concurrentLogging !== undefined) setConcurrentLogging(logs.concurrentLogging);
          if (logs.retention) setRetention(logs.retention);
        }
        if (waf) {
          if (waf.secRuleEngine) setSecRuleEngine(waf.secRuleEngine);
          if (waf.detectionMode) setDetectionMode(waf.detectionMode);
          if (waf.paranoiaLevel !== undefined) setParanoiaLevel(waf.paranoiaLevel);
        }

        if (hardening) {
          if (hardening.hsts_enabled !== undefined) setHstsEnabled(hardening.hsts_enabled);
          if (hardening.hsts_max_age !== undefined) setHstsMaxAge(hardening.hsts_max_age);
          if (hardening.server_cloaking !== undefined) setServerCloaking(hardening.server_cloaking);
          if (hardening.ip_blacklist !== undefined) setIpBlacklist(hardening.ip_blacklist.join(', '));
          if (hardening.ip_whitelist !== undefined) setIpWhitelist(hardening.ip_whitelist.join(', '));
        }
        if (defacement) {
          if (defacement.enabled !== undefined) setDefacementEnabled(defacement.enabled);
          if (defacement.monitored_files !== undefined) setDefacementFiles(defacement.monitored_files.join(', '));
          if (defacement.check_interval_seconds !== undefined) setCheckInterval(defacement.check_interval_seconds);
        }
        if (positiveSecurity) {
          if (positiveSecurity.enabled !== undefined) setPosSecEnabled(positiveSecurity.enabled);
          if (positiveSecurity.allowed_methods !== undefined) setPosSecMethods(positiveSecurity.allowed_methods.join(', '));
          if (positiveSecurity.allowed_content_types !== undefined) setPosSecContentTypes(positiveSecurity.allowed_content_types.join(', '));
          if (positiveSecurity.restricted_extensions !== undefined) setPosSecExtensions(positiveSecurity.restricted_extensions.join(', '));
        }
        if (customResponse) {
          if (customResponse.html_content !== undefined) setCustomResponseHtml(customResponse.html_content);
        }
        if (autoLearning) {
          if (autoLearning.enabled !== undefined) setAutoLearningEnabled(autoLearning.enabled);
          if (autoLearning.learning_period) setAutoLearningPeriod(autoLearning.learning_period);
          if (autoLearning.confidence_threshold !== undefined) setAutoLearningThreshold(autoLearning.confidence_threshold);
        }
    } catch (err) {
      console.error("Failed to load WAF settings from API", err);
      setSettingsLoadError(err.message || 'Could not reach the backend API.');
    }
  };

  const handleSaveGeneral = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      await saveGeneralSettings({
        refreshInterval,
        logsPerPage,
        liveUpdates
      });
      showToast("General preferences saved successfully.");
    } catch (err) {
      showToast(err.message || "Failed to save general settings.", "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveWAF = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      await saveWafSettings({
        secRuleEngine,
        detectionMode,
        paranoiaLevel
      });
      showToast("WAF core policies updated successfully.");
    } catch (err) {
      showToast(err.message || "Failed to save WAF settings.", "error");
    } finally {
      setLoadingAction(false);
    }
  };



  const handleSaveHardening = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const blacklist = ipBlacklist.split(',').map(ip => ip.trim()).filter(ip => ip);
      const whitelist = ipWhitelist.split(',').map(ip => ip.trim()).filter(ip => ip);
      await saveHardeningSettings({
        hsts_enabled: hstsEnabled,
        hsts_max_age: parseInt(hstsMaxAge) || 31536000,
        server_cloaking: serverCloaking,
        ip_blacklist: blacklist,
        ip_whitelist: whitelist
      });
      showToast("Hardening & Server Cloaking policies updated and applied to NGINX.");
    } catch (err) {
      showToast("Failed to update hardening settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveDefacement = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const files = defacementFiles.split(',').map(f => f.trim()).filter(f => f);
      await saveAntiDefacementSettings({
        enabled: defacementEnabled,
        monitored_files: files,
        check_interval_seconds: parseInt(checkInterval) || 5
      });
      showToast("Web Anti-Defacement policies updated successfully.");
    } catch (err) {
      showToast("Failed to update Anti-Defacement settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSavePositiveSecurity = async (e) => {
    e.preventDefault();
    if (posSecEnabled && !(await confirm({
      title: 'Enable Positive Security',
      message:
        "Enabling Positive Security will start denying any request to a protected app that doesn't match " +
        "the allowed methods / content-types below, or that hits a restricted file extension. This applies " +
        "immediately to ALL protected apps. Continue?",
      confirmLabel: 'Enable',
      danger: true,
    }))) {
      return;
    }
    setLoadingAction(true);
    try {
      const methods = posSecMethods.split(',').map(m => m.trim()).filter(m => m);
      const contentTypes = posSecContentTypes.split(',').map(c => c.trim()).filter(c => c);
      const extensions = posSecExtensions.split(',').map(x => x.trim()).filter(x => x);
      await savePositiveSecurity({
        enabled: posSecEnabled,
        allowed_methods: methods,
        allowed_content_types: contentTypes,
        restricted_extensions: extensions,
      });
      showToast(
        posSecEnabled
          ? "Positive Security policy updated and applied to protected apps."
          : "Positive Security disabled."
      );
    } catch (err) {
      showToast("Failed to update Positive Security settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveCustomResponse = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      await saveCustomResponse({ html_content: customResponseHtml });
      showToast("Custom block page saved and will be served on the next blocked request.");
    } catch (err) {
      showToast("Failed to save custom response page: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveAutoLearning = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      await saveAutoLearning({
        enabled: autoLearningEnabled,
        learning_period: autoLearningPeriod,
        confidence_threshold: parseInt(autoLearningThreshold) || 90,
      });
      showToast(
        autoLearningEnabled
          ? "Auto-Learning enabled — baseline tuning will use the configured window."
          : "Auto-Learning disabled."
      );
    } catch (err) {
      showToast("Failed to update Auto-Learning settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const fetchAutoLearningSuggestions = async () => {
    setSuggestionsLoading(true);
    try {
      const rows = await getAutoLearningSuggestions('Pending');
      setAutoLearningSuggestions(rows);
    } catch (err) {
      showToast("Failed to load Auto-Learning suggestions: " + (err.message || "Unknown error"), "error");
    } finally {
      setSuggestionsLoading(false);
    }
  };

  useEffect(() => {
    if (activeSettingTab === 'auto-learning') {
      const timer = setTimeout(() => fetchAutoLearningSuggestions(), 0);
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingTab]);

  const handleRunAutoLearningNow = async () => {
    setRunningNow(true);
    try {
      const result = await runAutoLearningNow();
      showToast(
        `Scan complete: ${result.scanned_false_positives ?? 0} resolved false positives reviewed, ` +
        `${result.suggestions_stored ?? 0} suggestion(s) added or updated.`
      );
      await fetchAutoLearningSuggestions();
    } catch (err) {
      showToast("Failed to run Auto-Learning scan: " + (err.message || "Unknown error"), "error");
    } finally {
      setRunningNow(false);
    }
  };

  const handleApproveSuggestion = async (suggestion) => {
    if (!(await confirm({
      title: 'Approve Auto-Learning suggestion',
      message: `This creates a real WAF exclusion for Rule ${suggestion.rule_id} ` +
        `(${suggestion.exclusion_type}${suggestion.uri ? `, URI: ${suggestion.uri}` : ''}` +
        `${suggestion.parameter_name ? `, Parameter: ${suggestion.parameter_name}` : ''}) ` +
        `and reloads NGINX immediately. Continue?`,
      confirmLabel: 'Approve & Apply',
    }))) return;
    setSuggestionActionId(suggestion.id);
    try {
      await approveAutoLearningSuggestion(suggestion.id);
      showToast("Suggestion approved — exclusion created and applied.");
      setAutoLearningSuggestions(prev => prev.filter(s => s.id !== suggestion.id));
    } catch (err) {
      showToast("Failed to approve suggestion: " + (err.message || "Unknown error"), "error");
    } finally {
      setSuggestionActionId(null);
    }
  };

  const handleRejectSuggestion = async (suggestion) => {
    setSuggestionActionId(suggestion.id);
    try {
      await rejectAutoLearningSuggestion(suggestion.id);
      showToast("Suggestion rejected.");
      setAutoLearningSuggestions(prev => prev.filter(s => s.id !== suggestion.id));
    } catch (err) {
      showToast("Failed to reject suggestion: " + (err.message || "Unknown error"), "error");
    } finally {
      setSuggestionActionId(null);
    }
  };

  const handleSaveLogs = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      await saveLogSettings({
        auditEnabled,
        logFormat,
        concurrentLogging,
        retention
      });
      showToast("Log ingestion configurations successfully updated.");
    } catch (err) {
      showToast(err.message || "Failed to update log settings.", "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    if (!newPassword || newPassword !== confirmPassword) {
      showToast("Passwords do not match or are blank.", "error");
      return;
    }
    setLoadingAction(true);
    try {
      const res = await changeAdminPassword(currentPassword, newPassword);
      showToast(res.message || "Administrator password updated successfully!");
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      showToast(err.message || "Failed to change admin password.", "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const confirmDangerAction = async () => {
    const action = dangerModal;
    setDangerModal(null);
    setLoadingAction(true);
    try {
      if (action === 'restart') {
        const res = await restartWafEngine();
        showToast(res.message || "WAF CyberSentinel Engine container restarted successfully.");
      } else if (action === 'nginx') {
        const res = await reloadNginxProxy();
        showToast(res.message || "NGINX service reloaded gracefully.");
      } else if (action === 'cache') {
        const res = await purgeStatsCache();
        showToast(res.message || "Dashboard analytics cache purged and rebuilt.");
      } else if (action === 'sync') {
        const res = await syncSignatures();
        showToast(res.message || "ModSecurity reloaded with the current on-disk rule set.");
      }
    } catch (err) {
      showToast(err.message || "Administrative action failed.", "error");
    } finally {
      setLoadingAction(false);
    }
  };

  return (
    <motion.div
      className="settings-container animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Toast Alert overlay */}
      <Toast toast={toast} />

      {/* Danger Modal confirmation prompt */}
      <AnimatePresence>
        {dangerModal && (
          <div className="modal-overlay" style={{ zIndex: 1100 }}>
            <motion.div
              className="modal-content pulse-warning"
              style={{ maxWidth: '480px', border: '1px solid var(--danger-border)' }}
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
            >
              <div className="modal-header" style={{ background: 'var(--danger-bg)', borderBottom: '1px solid var(--danger-border)' }}>
                <div className="modal-title" style={{ color: 'var(--danger-color)' }}>
                  <AlertTriangle size={20} color="var(--danger-color)" />
                  <span>Administrative Action Confirmation</span>
                </div>
                <button className="modal-close-btn" onClick={() => setDangerModal(null)} aria-label="Close">
                  <X size={18} />
                </button>
              </div>

              <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                  {dangerModal === 'restart' && "Are you sure you want to restart the CyberSentinel WAF protection engine? This will momentarily disrupt active connection guards."}
                  {dangerModal === 'nginx' && "Are you sure you want to gracefully reload NGINX configurations? This will apply all pending rule changes."}
                  {dangerModal === 'cache' && "Are you sure you want to clear the dashboard local metrics cache? The dashboard data will reload from raw logs."}
                  {dangerModal === 'sync' && "Are you sure you want to download and synchronize the latest OWASP Core Rule Set signatures? This will update your protection definitions."}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                  <button
                    onClick={() => setDangerModal(null)}
                    className="action-btn-inspect"
                    style={{ background: 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--border-strong)' }}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmDangerAction}
                    className="action-btn-inspect"
                    style={{ background: 'var(--danger-color)', color: '#fff', borderColor: 'transparent', padding: '6px 16px' }}
                  >
                    Confirm Action
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <div className="settings-layout" style={{ display: 'flex', gap: '32px', alignItems: 'flex-start' }}>

        {/* Sidebar Navigation */}
        <div className="settings-sidebar">
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: '10px', paddingLeft: '16px' }}>Configuration</div>

          <button onClick={() => setActiveSettingTab('general')} className={`settings-tab-btn ${activeSettingTab === 'general' ? 'active' : ''}`}>
            <SettingsIcon size={20} /> General Setup
          </button>
          <button onClick={() => setActiveSettingTab('waf')} className={`settings-tab-btn ${activeSettingTab === 'waf' ? 'active' : ''}`}>
            <ShieldCheck size={20} /> WAF Engine Policies
          </button>
          <button onClick={() => setActiveSettingTab('logs')} className={`settings-tab-btn ${activeSettingTab === 'logs' ? 'active' : ''}`}>
            <Database size={20} /> Log Pipeline
          </button>
          <button onClick={() => setActiveSettingTab('hardening')} className={`settings-tab-btn ${activeSettingTab === 'hardening' ? 'active' : ''}`}>
            <Server size={20} /> Server Hardening
          </button>
          <button onClick={() => setActiveSettingTab('positive-security')} className={`settings-tab-btn ${activeSettingTab === 'positive-security' ? 'active' : ''}`}>
            <CheckSquare size={20} /> Positive Security
          </button>
          <button onClick={() => setActiveSettingTab('defacement')} className={`settings-tab-btn ${activeSettingTab === 'defacement' ? 'active' : ''}`}>
            <ShieldAlert size={20} /> Anti-Defacement
          </button>
          <button onClick={() => setActiveSettingTab('custom-response')} className={`settings-tab-btn ${activeSettingTab === 'custom-response' ? 'active' : ''}`}>
            <FileCode size={20} /> Custom Response
          </button>
          <button onClick={() => setActiveSettingTab('auto-learning')} className={`settings-tab-btn ${activeSettingTab === 'auto-learning' ? 'active' : ''}`}>
            <Brain size={20} /> Auto-Learning
          </button>
          <button onClick={() => setActiveSettingTab('security')} className={`settings-tab-btn ${activeSettingTab === 'security' ? 'active' : ''}`}>
            <Lock size={20} /> Security & Danger Zone
          </button>
        </div>

        {/* Main Content Area */}
        <div className="settings-content-area">
          {settingsLoadError && (
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px',
              padding: '12px 16px', marginBottom: '16px', borderRadius: '8px',
              background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', color: 'var(--danger-color)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px' }}>
                <AlertTriangle size={18} />
                <span>Couldn't load current settings from the backend ({settingsLoadError}). The fields below may not reflect the live configuration — saving now could overwrite real settings with these defaults.</span>
              </div>
              <button
                type="button"
                onClick={fetchSettings}
                className="action-btn-inspect"
                style={{ display: 'flex', alignItems: 'center', gap: '6px', flex: 'none', background: 'var(--danger-border)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '6px 12px' }}
              >
                <RotateCw size={14} /> Retry
              </button>
            </div>
          )}
          <AnimatePresence mode="wait">

            {activeSettingTab === 'general' && (
              <motion.div key="general" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <SettingsIcon size={20} color="var(--sev-low)" />
                  General Settings
                </div>
                <div className="settings-section-subtitle">Configure dashboard behavior and real-time updates.</div>

                <form onSubmit={handleSaveGeneral} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Dashboard Refresh Interval</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={refreshInterval} onChange={(e) => setRefreshInterval(e.target.value)}>
                      <option value="3s">3 Seconds (Sync Active)</option>
                      <option value="5s">5 Seconds (Recommended)</option>
                      <option value="10s">10 Seconds</option>
                      <option value="30s">30 Seconds</option>
                      <option value="off">Disabled / Manual</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Live Logs Per Page</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={logsPerPage} onChange={(e) => setLogsPerPage(e.target.value)}>
                      <option value="10">10 entries</option>
                      <option value="15">15 entries</option>
                      <option value="25">25 entries</option>
                      <option value="50">50 entries</option>
                      <option value="100">100 entries</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Live Inbound Stream</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Stream logs dynamically from the backend</span>
                    </div>
                    <div className={`toggle-switch ${liveUpdates ? 'active' : ''}`} onClick={() => setLiveUpdates(!liveUpdates)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>
                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Save General Preferences
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'waf' && (
              <motion.div key="waf" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <ShieldCheck size={20} color="var(--sev-low)" />
                  WAF Engine Policies
                </div>
                <div className="settings-section-subtitle">Manage CyberSentinel Engine ruleset behaviors and blocking modes.</div>

                <form onSubmit={handleSaveWAF} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>SecRuleEngine Posture</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={secRuleEngine} onChange={(e) => setSecRuleEngine(e.target.value)}>
                      <option value="On">On (Active Blocking Guard)</option>
                      <option value="DetectionOnly">DetectionOnly (Simulate Attacks)</option>
                      <option value="Off">Off (Bypass WAF Shields - Critical Risk)</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Response Filtering Mode</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={detectionMode} onChange={(e) => setDetectionMode(e.target.value)}>
                      <option value="Blocking">Strict Block & Drop (403 Forbidden)</option>
                      <option value="Detection">Log Analysis Only (Bypass drops)</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Global Paranoia Setting</span>
                      <strong style={{ color: 'var(--sev-low)', fontSize: '14px' }}>PL{paranoiaLevel}</strong>
                    </label>
                    <input
                      type="range"
                      min="1"
                      max="4"
                      value={paranoiaLevel}
                      onChange={(e) => setParanoiaLevel(parseInt(e.target.value))}
                      style={{ width: '100%', height: '8px', background: 'var(--border-color)', borderRadius: '4px', outline: 'none', appearance: 'none', accentColor: 'var(--sev-low)', marginTop: '8px' }}
                    />
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
                      <span>PL1: Standard</span>
                      <span>PL2</span>
                      <span>PL3</span>
                      <span>PL4: Paranoid</span>
                    </div>
                  </div>
                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      {loadingAction ? 'Updating Ruleset...' : 'Update WAF Policies'}
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'logs' && (
              <motion.div key="logs" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <Database size={20} color="var(--sev-low)" />
                  Log Pipeline Configuration
                </div>
                <div className="settings-section-subtitle">Configure SecAuditEngine and log retention policies.</div>

                <form onSubmit={handleSaveLogs} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>SecAuditEngine Logging</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Record details of flagged transactions</span>
                    </div>
                    <div className={`toggle-switch ${auditEnabled ? 'active' : ''}`} onClick={() => setAuditEnabled(!auditEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Audit Log Structure Formats</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={logFormat} onChange={(e) => setLogFormat(e.target.value)}>
                      <option value="JSON">Structured JSON (RFC 8259 Standard)</option>
                      <option value="Native">CyberSentinel Engine Native Audit Structure</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Concurrent Multi-Threading</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Non-blocking log processing pipeline</span>
                    </div>
                    <div className={`toggle-switch ${concurrentLogging ? 'active' : ''}`} onClick={() => setConcurrentLogging(!concurrentLogging)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Log Retention Period</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={retention} onChange={(e) => setRetention(e.target.value)}>
                      <option value="7 Days">7 Days</option>
                      <option value="30 Days">30 Days</option>
                      <option value="90 Days">90 Days</option>
                      <option value="1 Year">1 Year</option>
                      <option value="Forever">Infinite / Log Rotation Disabled</option>
                    </select>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Update Logging Configuration
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'hardening' && (
              <motion.div key="hardening" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <Server size={20} color="var(--sev-low)" />
                  Infrastructure Hardening
                </div>
                <div className="settings-section-subtitle">Manage HSTS, server cloaking, and IP restrictions.</div>

                <form onSubmit={handleSaveHardening} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Strict HTTPS (HSTS)</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Enforce Strict-Transport-Security header</span>
                    </div>
                    <div className={`toggle-switch ${hstsEnabled ? 'active' : ''}`} onClick={() => setHstsEnabled(!hstsEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <AnimatePresence>
                    {hstsEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', paddingBottom: '10px' }}>
                          <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>HSTS Max Age (Seconds)</label>
                          <input
                            type="number"
                            className="settings-input"
                            style={{ width: '100%', fontSize: '14px' }}
                            value={hstsMaxAge}
                            onChange={(e) => setHstsMaxAge(e.target.value)}
                            placeholder="31536000"
                          />
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Server Cloaking</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Scrub NGINX tokens & Express header disclosures</span>
                    </div>
                    <div className={`toggle-switch ${serverCloaking ? 'active' : ''}`} onClick={() => setServerCloaking(!serverCloaking)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Global IP Blacklist (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '80px', resize: 'vertical' }}
                      value={ipBlacklist}
                      onChange={(e) => setIpBlacklist(e.target.value)}
                      placeholder="192.168.1.100, 10.0.0.50"
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Global IP Whitelist (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '80px', resize: 'vertical' }}
                      value={ipWhitelist}
                      onChange={(e) => setIpWhitelist(e.target.value)}
                      placeholder="192.168.1.10, 127.0.0.1"
                    />
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Apply Infrastructure Changes
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'positive-security' && (
              <motion.div key="positive-security" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <CheckSquare size={20} color="var(--sev-low)" />
                  Positive Security
                </div>
                <div className="settings-section-subtitle">
                  Allowlist HTTP methods, Content-Types, and deny requests for restricted file extensions.
                </div>

                <div style={{
                  display: 'flex', gap: '10px', background: 'var(--sev-low-bg)',
                  border: '1px solid var(--sev-low-border)', borderRadius: '10px',
                  padding: '14px 16px', marginBottom: '20px', maxWidth: '600px',
                }}>
                  <AlertTriangle size={16} color="var(--sev-low)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    This policy applies only to traffic for your <strong style={{ color: 'var(--text-primary)' }}>protected apps</strong> —
                    it never affects this dashboard's own API. Disabled by default: turning it on with an
                    incomplete allowlist can immediately block legitimate traffic to every protected app, so
                    review the lists below carefully before enabling.
                  </span>
                </div>

                <form onSubmit={handleSavePositiveSecurity} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Positive Security</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — no rules are active until enabled</span>
                    </div>
                    <div className={`toggle-switch ${posSecEnabled ? 'active' : ''}`} onClick={() => setPosSecEnabled(!posSecEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Allowed HTTP Methods (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '60px', resize: 'vertical' }}
                      value={posSecMethods}
                      onChange={(e) => setPosSecMethods(e.target.value)}
                      placeholder="GET, POST, HEAD"
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Requests using any other method get a 405. Leave empty to skip this check entirely.
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Allowed Content-Types (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '60px', resize: 'vertical' }}
                      value={posSecContentTypes}
                      onChange={(e) => setPosSecContentTypes(e.target.value)}
                      placeholder="application/json, application/x-www-form-urlencoded, multipart/form-data"
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Only checked on POST/PUT/PATCH requests. Requests with any other Content-Type get a 415.
                      Leave empty to skip this check entirely.
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Restricted File Extensions (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '60px', resize: 'vertical' }}
                      value={posSecExtensions}
                      onChange={(e) => setPosSecExtensions(e.target.value)}
                      placeholder=".bak, .config, .env, .log, .sql, .ini"
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Any request whose path ends in one of these gets a 403 (case-insensitive). Leave empty
                      to skip this check entirely.
                    </span>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      {loadingAction ? 'Applying to NGINX...' : 'Apply Positive Security Policy'}
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'defacement' && (
              <motion.div key="defacement" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <ShieldAlert size={20} color="var(--danger-color)" />
                  Anti-Defacement Protection
                </div>
                <div className="settings-section-subtitle">Real-time integrity monitoring for critical assets.</div>

                <form onSubmit={handleSaveDefacement} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Real-time Integrity Monitor</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Revert unauthorized content modifications instantly</span>
                    </div>
                    <div className={`toggle-switch ${defacementEnabled ? 'active' : ''}`} onClick={() => setDefacementEnabled(!defacementEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Audit Scan Interval (Seconds)</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={checkInterval} onChange={(e) => setCheckInterval(parseInt(e.target.value))}>
                      <option value="2">2 Seconds (High sensitivity)</option>
                      <option value="5">5 Seconds (Recommended)</option>
                      <option value="10">10 Seconds</option>
                      <option value="30">30 Seconds</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Monitored Asset Filepaths (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '100px', resize: 'vertical' }}
                      value={defacementFiles}
                      onChange={(e) => setDefacementFiles(e.target.value)}
                      placeholder="/var/www/html/index.html"
                      required
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      System background service prefetches and locks these files.
                    </span>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px', background: 'var(--danger-color)' }}>
                      {loadingAction ? 'Applying...' : 'Apply Defacement Protection'}
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'custom-response' && (
              <motion.div key="custom-response" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <FileCode size={20} color="var(--sev-low)" />
                  Custom Response Page
                </div>
                <div className="settings-section-subtitle">
                  The HTML page shown to a visitor when the WAF blocks their request. Use{' '}
                  <code style={{ fontSize: '12px', background: 'var(--surface-subtle)', padding: '1px 5px', borderRadius: '4px' }}>{'{{transaction_id}}'}</code>{' '}
                  anywhere in the page to include the block's transaction ID, useful for support requests.
                </div>

                <form onSubmit={handleSaveCustomResponse} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '700px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Block Page HTML</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '260px', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '12.5px' }}
                      value={customResponseHtml}
                      onChange={(e) => setCustomResponseHtml(e.target.value)}
                      placeholder="<!DOCTYPE html>..."
                      spellCheck={false}
                      required
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Full HTML document served with every WAF block response (HTTP 403).
                    </span>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      {loadingAction ? 'Saving...' : 'Save Custom Response Page'}
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'auto-learning' && (
              <motion.div key="auto-learning" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <Brain size={20} color="var(--ml-color)" />
                  Auto-Learning
                </div>
                <div className="settings-section-subtitle">
                  Observes traffic over a rolling window to tune detection baselines toward your application's
                  real usage, reducing false positives without loosening genuine protections.
                </div>

                <form onSubmit={handleSaveAutoLearning} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Auto-Learning</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — baselines only update when enabled</span>
                    </div>
                    <div className={`toggle-switch ${autoLearningEnabled ? 'active' : ''}`} onClick={() => setAutoLearningEnabled(!autoLearningEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Learning Period</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={autoLearningPeriod} onChange={(e) => setAutoLearningPeriod(e.target.value)}>
                      <option value="3 Days">3 Days</option>
                      <option value="7 Days">7 Days (Recommended)</option>
                      <option value="14 Days">14 Days</option>
                      <option value="30 Days">30 Days</option>
                    </select>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      How far back observed traffic is considered when tuning baselines.
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Confidence Threshold ({autoLearningThreshold}%)</label>
                    <input
                      type="range"
                      min="50"
                      max="99"
                      value={autoLearningThreshold}
                      onChange={(e) => setAutoLearningThreshold(parseInt(e.target.value))}
                      style={{ width: '100%' }}
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Only traffic patterns observed with at least this confidence are folded into the baseline.
                    </span>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      {loadingAction ? 'Saving...' : 'Save Auto-Learning Settings'}
                    </button>
                  </div>
                </form>

                <div style={{ marginTop: '32px', paddingTop: '24px', borderTop: '1px solid var(--surface-hover)', maxWidth: '700px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>Pending Suggestions</div>
                    <Button
                      variant="secondary" size="sm" icon={RotateCw}
                      loading={runningNow}
                      onClick={handleRunAutoLearningNow}
                    >
                      Run Now
                    </Button>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' }}>
                    Patterns learned from Resolved false positives that meet the confidence threshold above.
                    Nothing here is applied to the WAF until you Approve it.
                  </div>

                  {suggestionsLoading ? (
                    <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>Loading suggestions...</div>
                  ) : autoLearningSuggestions.length === 0 ? (
                    <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--surface-subtle)', borderRadius: '8px' }}>
                      No pending suggestions right now.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {autoLearningSuggestions.map((s) => (
                        <div key={s.id} style={{ background: 'var(--surface-subtle)', border: '1px solid var(--surface-hover)', borderRadius: '10px', padding: '14px 16px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 }}>
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                                <span style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 700, color: 'var(--sev-high)' }}>Rule #{s.rule_id}</span>
                                <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'var(--sev-low-bg)', color: 'var(--sev-low)', textTransform: 'uppercase' }}>
                                  {s.exclusion_type}
                                </span>
                                <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'rgba(16,185,129,0.1)', color: 'var(--success-color)' }}>
                                  {s.confidence_score}% confidence
                                </span>
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                                  {s.occurrence_count} occurrence{s.occurrence_count === 1 ? '' : 's'}
                                </span>
                              </div>
                              {(s.uri || s.parameter_name) && (
                                <div style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)' }}>
                                  {s.uri && `URI: ${s.uri}`}{s.uri && s.parameter_name && '  '}{s.parameter_name && `Param: ${s.parameter_name}`}
                                </div>
                              )}
                              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{s.reasoning}</div>
                            </div>
                            <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                              <Button
                                variant="danger" size="sm"
                                loading={suggestionActionId === s.id}
                                onClick={() => handleRejectSuggestion(s)}
                              >
                                Reject
                              </Button>
                              <Button
                                variant="primary" size="sm"
                                loading={suggestionActionId === s.id}
                                onClick={() => handleApproveSuggestion(s)}
                              >
                                Approve
                              </Button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {activeSettingTab === 'security' && (
              <motion.div key="security" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <Lock size={20} color="var(--sev-low)" />
                  Admin Security & Danger Zone
                </div>
                <div className="settings-section-subtitle">Manage portal access credentials and system overrides.</div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '40px', maxWidth: '600px' }}>

                  {/* Password Form */}
                  <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>Portal Authentication</div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Current Admin Password</label>
                      <input type="password" placeholder="••••••••" className="settings-input" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>New Security Password</label>
                      <input type="password" placeholder="••••••••" className="settings-input" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Confirm New Password</label>
                      <input type="password" placeholder="••••••••" className="settings-input" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Portal Session Timeout</label>
                      <select className="filter-select" style={{ width: '100%', padding: '12px' }} value={sessionTimeout} onChange={(e) => setSessionTimeout(e.target.value)}>
                        <option value="15m">15 Minutes</option>
                        <option value="30m">30 Minutes</option>
                        <option value="1h">1 Hour (Standard)</option>
                        <option value="4h">4 Hours</option>
                        <option value="12h">12 Hours</option>
                        <option value="never">No Automatic Timeout</option>
                      </select>
                    </div>
                    <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                      <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px' }}>
                        Update Credentials
                      </button>
                      <button type="button" onClick={onLogout} className="action-btn-inspect" style={{ background: 'var(--danger-bg)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '12px 24px', fontSize: '13px' }}>
                        Terminate Session
                      </button>
                    </div>
                  </form>

                  {/* Danger Zone */}
                  <div style={{ background: 'linear-gradient(135deg, var(--danger-bg) 0%, rgba(0, 0, 0, 0) 100%)', border: '1px solid var(--danger-border)', borderRadius: '16px', padding: '24px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--danger-color)', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <AlertTriangle size={18} color="var(--danger-color)" />
                      System Overrides
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'var(--danger-bg)', borderRadius: '10px', border: '1px solid var(--danger-bg)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger-color)' }}>Restart CyberSentinel Engine WAF Engine</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Force service instance container reload</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('restart')} className="action-btn-inspect" style={{ background: 'var(--danger-border)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '8px 16px' }}>
                          Restart Engine
                        </button>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'var(--danger-bg)', borderRadius: '10px', border: '1px solid var(--danger-bg)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger-color)' }}>Reload System NGINX Proxy</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Rebuild active NGINX process configurations</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('nginx')} className="action-btn-inspect" style={{ background: 'var(--danger-border)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '8px 16px' }}>
                          Reload NGINX
                        </button>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'var(--danger-bg)', borderRadius: '10px', border: '1px solid var(--danger-bg)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger-color)' }}>Purge Local UI Cache</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Invalidate local storage metrics data cache</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('cache')} className="action-btn-inspect" style={{ background: 'var(--danger-border)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '8px 16px' }}>
                          Purge Cache
                        </button>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'var(--danger-bg)', borderRadius: '10px', border: '1px solid var(--danger-bg)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--danger-color)' }}>Reload Signatures (OWASP CRS)</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Reload ModSecurity with the CRS rules currently on disk (does not fetch new signatures)</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('sync')} className="action-btn-inspect" style={{ background: 'var(--danger-border)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '8px 16px' }}>
                          Sync Signatures
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}

// Map between URL paths and tab IDs
// Protection Section Component - Sub-tabbed: Virtual Hosts | DDoS & Bot Shield
