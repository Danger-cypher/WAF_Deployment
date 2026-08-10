import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Database, Lock, Server, Settings as SettingsIcon, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import {
  getGeneralSettings, saveGeneralSettings, getLogSettings, saveLogSettings,
  getWafSettings, saveWafSettings,
  changeAdminPassword, restartWafEngine, reloadNginxProxy, purgeStatsCache, syncSignatures,
  getHardeningSettings, saveHardeningSettings, getAntiDefacementSettings, saveAntiDefacementSettings,
} from '../services/api';

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

  // Notifications & State Controls
  const [toast, setToast] = useState(null);
  const [dangerModal, setDangerModal] = useState(null);
  const [loadingAction, setLoadingAction] = useState(false);
  const [activeSettingTab, setActiveSettingTab] = useState('general');

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const [gen, logs, waf, hardening, defacement] = await Promise.all([
          getGeneralSettings(),
          getLogSettings(),
          getWafSettings(),
          getHardeningSettings(),
          getAntiDefacementSettings()
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
      } catch (err) {
        console.error("Failed to load WAF settings from API", err);
      }
    };
    fetchSettings();
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
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
        showToast(res.message || "OWASP CRS signatures synced successfully.");
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

      {/* Danger Modal confirmation prompt */}
      <AnimatePresence>
        {dangerModal && (
          <div className="modal-overlay" style={{ zIndex: 1100 }}>
            <motion.div
              className="modal-content pulse-warning"
              style={{ maxWidth: '480px', border: '1px solid rgba(239, 68, 68, 0.35)' }}
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
            >
              <div className="modal-header" style={{ background: 'rgba(239, 68, 68, 0.03)', borderBottom: '1px solid rgba(239,68,68,0.15)' }}>
                <div className="modal-title" style={{ color: '#fca5a5' }}>
                  <AlertTriangle size={20} color="#ef4444" />
                  <span>Administrative Action Confirmation</span>
                </div>
                <button className="modal-close-btn" onClick={() => setDangerModal(null)}>
                  <X size={18} />
                </button>
              </div>

              <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ fontSize: '13px', color: '#e4e4e7', lineHeight: '1.5' }}>
                  {dangerModal === 'restart' && "Are you sure you want to restart the CyberSentinel WAF protection engine? This will momentarily disrupt active connection guards."}
                  {dangerModal === 'nginx' && "Are you sure you want to gracefully reload NGINX configurations? This will apply all pending rule changes."}
                  {dangerModal === 'cache' && "Are you sure you want to clear the dashboard local metrics cache? The dashboard data will reload from raw logs."}
                  {dangerModal === 'sync' && "Are you sure you want to download and synchronize the latest OWASP Core Rule Set signatures? This will update your protection definitions."}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                  <button
                    onClick={() => setDangerModal(null)}
                    className="action-btn-inspect"
                    style={{ background: 'transparent', color: '#a1a1aa', borderColor: 'rgba(255,255,255,0.1)' }}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmDangerAction}
                    className="action-btn-inspect"
                    style={{ background: '#ef4444', color: '#fff', borderColor: 'transparent', padding: '6px 16px' }}
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
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#71717a', textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: '10px', paddingLeft: '16px' }}>Configuration</div>

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
          <button onClick={() => setActiveSettingTab('defacement')} className={`settings-tab-btn ${activeSettingTab === 'defacement' ? 'active' : ''}`}>
            <ShieldAlert size={20} /> Anti-Defacement
          </button>
          <button onClick={() => setActiveSettingTab('security')} className={`settings-tab-btn ${activeSettingTab === 'security' ? 'active' : ''}`}>
            <Lock size={20} /> Security & Danger Zone
          </button>
        </div>

        {/* Main Content Area */}
        <div className="settings-content-area">
          <AnimatePresence mode="wait">

            {activeSettingTab === 'general' && (
              <motion.div key="general" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <SettingsIcon size={20} color="#3b82f6" />
                  General Settings
                </div>
                <div className="settings-section-subtitle">Configure dashboard behavior and real-time updates.</div>

                <form onSubmit={handleSaveGeneral} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Dashboard Refresh Interval</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={refreshInterval} onChange={(e) => setRefreshInterval(e.target.value)}>
                      <option value="3s">3 Seconds (Sync Active)</option>
                      <option value="5s">5 Seconds (Recommended)</option>
                      <option value="10s">10 Seconds</option>
                      <option value="30s">30 Seconds</option>
                      <option value="off">Disabled / Manual</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Live Logs Per Page</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={logsPerPage} onChange={(e) => setLogsPerPage(e.target.value)}>
                      <option value="10">10 entries</option>
                      <option value="15">15 entries</option>
                      <option value="25">25 entries</option>
                      <option value="50">50 entries</option>
                      <option value="100">100 entries</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: '#e4e4e7' }}>Live Inbound Stream</span>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Stream logs dynamically from the backend</span>
                    </div>
                    <div className={`toggle-switch ${liveUpdates ? 'active' : ''}`} onClick={() => setLiveUpdates(!liveUpdates)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>
                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
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
                  <ShieldCheck size={20} color="#3b82f6" />
                  WAF Engine Policies
                </div>
                <div className="settings-section-subtitle">Manage CyberSentinel Engine ruleset behaviors and blocking modes.</div>

                <form onSubmit={handleSaveWAF} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>SecRuleEngine Posture</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={secRuleEngine} onChange={(e) => setSecRuleEngine(e.target.value)}>
                      <option value="On">On (Active Blocking Guard)</option>
                      <option value="DetectionOnly">DetectionOnly (Simulate Attacks)</option>
                      <option value="Off">Off (Bypass WAF Shields - Critical Risk)</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Response Filtering Mode</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={detectionMode} onChange={(e) => setDetectionMode(e.target.value)}>
                      <option value="Blocking">Strict Block & Drop (403 Forbidden)</option>
                      <option value="Detection">Log Analysis Only (Bypass drops)</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Global Paranoia Setting</span>
                      <strong style={{ color: '#3b82f6', fontSize: '14px' }}>PL{paranoiaLevel}</strong>
                    </label>
                    <input
                      type="range"
                      min="1"
                      max="4"
                      value={paranoiaLevel}
                      onChange={(e) => setParanoiaLevel(parseInt(e.target.value))}
                      style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', outline: 'none', appearance: 'none', accentColor: '#3b82f6', marginTop: '8px' }}
                    />
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#71717a', marginTop: '6px' }}>
                      <span>PL1: Standard</span>
                      <span>PL2</span>
                      <span>PL3</span>
                      <span>PL4: Paranoid</span>
                    </div>
                  </div>
                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
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
                  <Database size={20} color="#3b82f6" />
                  Log Pipeline Configuration
                </div>
                <div className="settings-section-subtitle">Configure SecAuditEngine and log retention policies.</div>

                <form onSubmit={handleSaveLogs} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: '#e4e4e7' }}>SecAuditEngine Logging</span>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Record details of flagged transactions</span>
                    </div>
                    <div className={`toggle-switch ${auditEnabled ? 'active' : ''}`} onClick={() => setAuditEnabled(!auditEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Audit Log Structure Formats</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={logFormat} onChange={(e) => setLogFormat(e.target.value)}>
                      <option value="JSON">Structured JSON (RFC 8259 Standard)</option>
                      <option value="Native">CyberSentinel Engine Native Audit Structure</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: '#e4e4e7' }}>Concurrent Multi-Threading</span>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Non-blocking log processing pipeline</span>
                    </div>
                    <div className={`toggle-switch ${concurrentLogging ? 'active' : ''}`} onClick={() => setConcurrentLogging(!concurrentLogging)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Log Retention Period</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={retention} onChange={(e) => setRetention(e.target.value)}>
                      <option value="7 Days">7 Days</option>
                      <option value="30 Days">30 Days</option>
                      <option value="90 Days">90 Days</option>
                      <option value="1 Year">1 Year</option>
                      <option value="Forever">Infinite / Log Rotation Disabled</option>
                    </select>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
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
                  <Server size={20} color="#3b82f6" />
                  Infrastructure Hardening
                </div>
                <div className="settings-section-subtitle">Manage HSTS, server cloaking, and IP restrictions.</div>

                <form onSubmit={handleSaveHardening} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: '#e4e4e7' }}>Strict HTTPS (HSTS)</span>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Enforce Strict-Transport-Security header</span>
                    </div>
                    <div className={`toggle-switch ${hstsEnabled ? 'active' : ''}`} onClick={() => setHstsEnabled(!hstsEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <AnimatePresence>
                    {hstsEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', paddingBottom: '10px' }}>
                          <label style={{ fontSize: '13px', color: '#a1a1aa' }}>HSTS Max Age (Seconds)</label>
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

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: '#e4e4e7' }}>Server Cloaking</span>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Scrub NGINX tokens & Express header disclosures</span>
                    </div>
                    <div className={`toggle-switch ${serverCloaking ? 'active' : ''}`} onClick={() => setServerCloaking(!serverCloaking)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Global IP Blacklist (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '80px', resize: 'vertical' }}
                      value={ipBlacklist}
                      onChange={(e) => setIpBlacklist(e.target.value)}
                      placeholder="192.168.1.100, 10.0.0.50"
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Global IP Whitelist (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '80px', resize: 'vertical' }}
                      value={ipWhitelist}
                      onChange={(e) => setIpWhitelist(e.target.value)}
                      placeholder="192.168.1.10, 127.0.0.1"
                    />
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Apply Infrastructure Changes
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'defacement' && (
              <motion.div key="defacement" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <ShieldAlert size={20} color="#ef4444" />
                  Anti-Defacement Protection
                </div>
                <div className="settings-section-subtitle">Real-time integrity monitoring for critical assets.</div>

                <form onSubmit={handleSaveDefacement} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: '#e4e4e7' }}>Real-time Integrity Monitor</span>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Revert unauthorized content modifications instantly</span>
                    </div>
                    <div className={`toggle-switch ${defacementEnabled ? 'active' : ''}`} onClick={() => setDefacementEnabled(!defacementEnabled)}>
                      <div className="toggle-knob"></div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Audit Scan Interval (Seconds)</label>
                    <select className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={checkInterval} onChange={(e) => setCheckInterval(parseInt(e.target.value))}>
                      <option value="2">2 Seconds (High sensitivity)</option>
                      <option value="5">5 Seconds (Recommended)</option>
                      <option value="10">10 Seconds</option>
                      <option value="30">30 Seconds</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Monitored Asset Filepaths (Comma separated)</label>
                    <textarea
                      className="settings-input"
                      style={{ width: '100%', minHeight: '100px', resize: 'vertical' }}
                      value={defacementFiles}
                      onChange={(e) => setDefacementFiles(e.target.value)}
                      placeholder="/var/www/html/index.html"
                      required
                    />
                    <span style={{ fontSize: '11px', color: '#71717a', marginTop: '4px' }}>
                      System background service prefetches and locks these files.
                    </span>
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px', background: 'var(--danger-color)' }}>
                      {loadingAction ? 'Applying...' : 'Apply Defacement Protection'}
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            {activeSettingTab === 'security' && (
              <motion.div key="security" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <Lock size={20} color="#3b82f6" />
                  Admin Security & Danger Zone
                </div>
                <div className="settings-section-subtitle">Manage portal access credentials and system overrides.</div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '40px', maxWidth: '600px' }}>

                  {/* Password Form */}
                  <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 600, color: '#f4f4f5', marginBottom: '8px' }}>Portal Authentication</div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Current Admin Password</label>
                      <input type="password" placeholder="••••••••" className="settings-input" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: '#a1a1aa' }}>New Security Password</label>
                      <input type="password" placeholder="••••••••" className="settings-input" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Confirm New Password</label>
                      <input type="password" placeholder="••••••••" className="settings-input" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                      <label style={{ fontSize: '13px', color: '#a1a1aa' }}>Portal Session Timeout</label>
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
                      <button type="button" onClick={onLogout} className="action-btn-inspect" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.2)', padding: '12px 24px', fontSize: '13px' }}>
                        Terminate Session
                      </button>
                    </div>
                  </form>

                  {/* Danger Zone */}
                  <div style={{ background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.05) 0%, rgba(0, 0, 0, 0) 100%)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '16px', padding: '24px' }}>
                    <div style={{ fontSize: '15px', fontWeight: 600, color: '#fca5a5', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <AlertTriangle size={18} color="#ef4444" />
                      System Overrides
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'rgba(239,68,68,0.04)', borderRadius: '10px', border: '1px solid rgba(239,68,68,0.1)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: '#fca5a5' }}>Restart CyberSentinel Engine WAF Engine</span>
                          <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Force service instance container reload</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('restart')} className="action-btn-inspect" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', borderColor: 'rgba(239,68,68,0.3)', padding: '8px 16px' }}>
                          Restart Engine
                        </button>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'rgba(239,68,68,0.04)', borderRadius: '10px', border: '1px solid rgba(239,68,68,0.1)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: '#fca5a5' }}>Reload System NGINX Proxy</span>
                          <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Rebuild active NGINX process configurations</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('nginx')} className="action-btn-inspect" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', borderColor: 'rgba(239,68,68,0.3)', padding: '8px 16px' }}>
                          Reload NGINX
                        </button>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'rgba(239,68,68,0.04)', borderRadius: '10px', border: '1px solid rgba(239,68,68,0.1)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: '#fca5a5' }}>Purge Local UI Cache</span>
                          <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Invalidate local storage metrics data cache</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('cache')} className="action-btn-inspect" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', borderColor: 'rgba(239,68,68,0.3)', padding: '8px 16px' }}>
                          Purge Cache
                        </button>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: 'rgba(239,68,68,0.04)', borderRadius: '10px', border: '1px solid rgba(239,68,68,0.1)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 600, color: '#fca5a5' }}>Sync Signatures (OWASP CRS)</span>
                          <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Download and synchronize latest CRS rules</span>
                        </div>
                        <button type="button" onClick={() => setDangerModal('sync')} className="action-btn-inspect" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', borderColor: 'rgba(239,68,68,0.3)', padding: '8px 16px' }}>
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
