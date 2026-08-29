import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Archive, Brain, CheckSquare, Database, Download, FileCode, History, Lock, RotateCcw, RotateCw, Search, Server, Settings as SettingsIcon, ShieldAlert, ShieldCheck, Trash2, X } from 'lucide-react';
import {
  getGeneralSettings, saveGeneralSettings, getLogSettings, saveLogSettings,
  getWafSettings, saveWafSettings,
  changeAdminPassword, restartWafEngine, reloadNginxProxy, purgeStatsCache, syncSignatures,
  getHardeningSettings, saveHardeningSettings, getGeoBlockSettings, saveGeoBlockSettings,
  getThreatIntelSettings, saveThreatIntelSettings, syncThreatIntelNow,
  getAutoReputationSettings, saveAutoReputationSettings, syncAutoReputationNow,
  getAutoBlockedIps, releaseAutoBlockedIp,
  getAdminLoginAllowlistSettings, saveAdminLoginAllowlistSettings,
  getMalwareScanningSettings, saveMalwareScanningSettings, checkMalwareScanningNow,
  getApiKeys, createApiKey, revokeApiKey,
  getAntiDefacementSettings, saveAntiDefacementSettings,
  getPositiveSecurity, savePositiveSecurity,
  getCustomResponse, saveCustomResponse, getAutoLearning, saveAutoLearning,
  getAutoLearningSuggestions, runAutoLearningNow, approveAutoLearningSuggestion, rejectAutoLearningSuggestion,
  getAuditLog,
  getBackups, createBackup, restoreBackup, deleteBackup, downloadBackup,
} from '../services/api';
import { useToast } from '../hooks/useToast';
import SettingsAccordionCard from '../components/SettingsAccordionCard';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import Button from '../components/Button';
import { formatLocalTime } from '../utils/helpers';

// One entry per independently-saved form on this page — every tab can hold
// several (Hardening alone has six accordion sections, each its own form).
// Backs the unsaved-changes bar: which form got dirty, and which tab to jump
// to for it.
const SETTINGS_SECTIONS = {
  general: { label: 'General', tab: 'general' },
  waf: { label: 'WAF Engine', tab: 'waf' },
  logs: { label: 'Log Ingestion', tab: 'logs' },
  hardening: { label: 'Infrastructure Hardening', tab: 'hardening' },
  geoblock: { label: 'Geo-Block', tab: 'hardening' },
  threatintel: { label: 'External Threat-Intel Feed', tab: 'hardening' },
  autorep: { label: 'Self-Learned IP Reputation', tab: 'hardening' },
  adminallowlist: { label: 'Admin-Login IP Allowlist', tab: 'hardening' },
  malwarescan: { label: 'Malware Scanning', tab: 'hardening' },
  possec: { label: 'Positive Security', tab: 'positive-security' },
  defacement: { label: 'Anti-Defacement', tab: 'defacement' },
  customresponse: { label: 'Custom Response Page', tab: 'custom-response' },
  autolearning: { label: 'Auto-Learning', tab: 'auto-learning' },
};

// The 11 sidebar leaf labels (distinct from SETTINGS_SECTIONS above, which
// is per-form for dirty-tracking — Hardening's 6 accordion forms all live
// under one sidebar entry). Backs the sidebar search box's "no matches"
// empty state.
const ALL_SETTINGS_LABELS = [
  'General Setup', 'WAF Engine Policies', 'Log Pipeline', 'Server Hardening',
  'Positive Security', 'Anti-Defacement', 'Auto-Learning', 'Custom Response',
  'Security & Danger Zone', 'Activity Log', 'Backups',
];

export default function Settings({ onLogout, initialSettingsTab, onConsumeInitialSettingsTab }) {
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

  // Geo-Block Settings — country allow/deny list, enforced in ml_check.lua
  // via $geoip2_data_country_code (requires GeoIP2 to be enabled to have
  // any effect; degrades to a no-op otherwise).
  const [geoBlockEnabled, setGeoBlockEnabled] = useState(false);
  const [geoBlockMode, setGeoBlockMode] = useState('deny');
  const [geoBlockCountries, setGeoBlockCountries] = useState("");

  // External Threat-Intel Feed (Spamhaus DROP/EDROP) — populates a
  // separate Redis key ml_check.lua also checks, never clobbers the
  // manually-managed IP blacklist above.
  const [threatIntelEnabled, setThreatIntelEnabled] = useState(false);
  const [threatIntelIntervalHours, setThreatIntelIntervalHours] = useState(24);
  const [threatIntelStatus, setThreatIntelStatus] = useState(null);
  const [threatIntelSyncing, setThreatIntelSyncing] = useState(false);

  // Self-Learned IP Reputation (P1-7) — auto-blocks repeat WAF-block
  // offenders from this deployment's own traffic. Separate Redis key
  // namespace from both the manual blacklist and the threat-intel feed
  // above; individual per-IP TTL'd entries, not a CIDR set.
  const [autoRepEnabled, setAutoRepEnabled] = useState(false);
  const [autoRepThreshold, setAutoRepThreshold] = useState(50);
  const [autoRepWindowHours, setAutoRepWindowHours] = useState(1);
  const [autoRepTtlHours, setAutoRepTtlHours] = useState(24);
  const [autoRepIntervalMinutes, setAutoRepIntervalMinutes] = useState(15);
  const [autoRepStatus, setAutoRepStatus] = useState(null);
  const [autoRepSyncing, setAutoRepSyncing] = useState(false);
  const [adminAllowlistEnabled, setAdminAllowlistEnabled] = useState(false);
  const [adminAllowlistNetworks, setAdminAllowlistNetworks] = useState("");
  const [malwareScanEnabled, setMalwareScanEnabled] = useState(false);
  const [malwareScanFailMode, setMalwareScanFailMode] = useState('open');
  const [malwareScanTimeout, setMalwareScanTimeout] = useState(5);
  const [malwareScanStatus, setMalwareScanStatus] = useState(null);
  const [malwareScanChecking, setMalwareScanChecking] = useState(false);
  const [apiKeys, setApiKeys] = useState([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyRole, setNewKeyRole] = useState('analyst');
  const [newKeyExpiresDays, setNewKeyExpiresDays] = useState('');
  const [creatingApiKey, setCreatingApiKey] = useState(false);
  const [revealedApiKey, setRevealedApiKey] = useState(null);
  const [autoBlockedIps, setAutoBlockedIps] = useState([]);
  const [autoBlockedIpsLoading, setAutoBlockedIpsLoading] = useState(false);

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
  // Seeded once from the Overview page's "what changed" strip (jumps
  // straight to Activity Log), if that's how this page was reached.
  const [activeSettingTab, setActiveSettingTab] = useState(initialSettingsTab || 'general');
  useEffect(() => {
    if (initialSettingsTab) onConsumeInitialSettingsTab?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [settingsSearch, setSettingsSearch] = useState('');
  // A group/button stays visible if no query is entered, or if ANY of the
  // labels passed in matches — used both per-button (one label) and per-
  // group-header (all of that group's labels, so the header only hides
  // once every one of its members is filtered out too).
  const matchesSettingsSearch = (...labels) => {
    const q = settingsSearch.trim().toLowerCase();
    if (!q) return true;
    return labels.some((l) => l.toLowerCase().includes(q));
  };
  const hasAnySettingsMatch = matchesSettingsSearch(...ALL_SETTINGS_LABELS);

  // Unsaved-changes tracking: each form marks its own key dirty on any field
  // change (via the form's onChange, which catches every input inside it —
  // no per-field wiring needed) and clears it once its own save succeeds.
  // Sections stay independent on purpose — there's no "save all", since each
  // form validates and applies separately.
  const [dirtySections, setDirtySections] = useState({});
  const markDirty = (key) => setDirtySections((prev) => (prev[key] ? prev : { ...prev, [key]: true }));
  const clearDirty = (key) => setDirtySections((prev) => {
    if (!prev[key]) return prev;
    const next = { ...prev };
    delete next[key];
    return next;
  });
  // Previously a failed initial load only did console.error, leaving every
  // tab showing hardcoded defaults with zero visible signal that they don't
  // reflect real WAF config — an admin could edit and save right over real
  // settings without ever knowing the load failed.
  const [settingsLoadError, setSettingsLoadError] = useState('');

  const fetchSettings = async () => {
    setSettingsLoadError('');
    try {
        const [gen, logs, waf, hardening, geoBlock, threatIntel, autoRep, adminLoginAllowlist, malwareScan, defacement, positiveSecurity, customResponse, autoLearning] = await Promise.all([
          getGeneralSettings(),
          getLogSettings(),
          getWafSettings(),
          getHardeningSettings(),
          getGeoBlockSettings(),
          getThreatIntelSettings(),
          getAutoReputationSettings(),
          getAdminLoginAllowlistSettings(),
          getMalwareScanningSettings(),
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
        if (geoBlock) {
          if (geoBlock.enabled !== undefined) setGeoBlockEnabled(geoBlock.enabled);
          if (geoBlock.mode) setGeoBlockMode(geoBlock.mode);
          if (geoBlock.countries !== undefined) setGeoBlockCountries(geoBlock.countries.join(', '));
        }
        if (threatIntel) {
          if (threatIntel.enabled !== undefined) setThreatIntelEnabled(threatIntel.enabled);
          if (threatIntel.sync_interval_hours !== undefined) setThreatIntelIntervalHours(threatIntel.sync_interval_hours);
          setThreatIntelStatus(threatIntel);
        }
        if (autoRep) {
          if (autoRep.enabled !== undefined) setAutoRepEnabled(autoRep.enabled);
          if (autoRep.block_threshold !== undefined) setAutoRepThreshold(autoRep.block_threshold);
          if (autoRep.window_hours !== undefined) setAutoRepWindowHours(autoRep.window_hours);
          if (autoRep.block_ttl_hours !== undefined) setAutoRepTtlHours(autoRep.block_ttl_hours);
          if (autoRep.sync_interval_minutes !== undefined) setAutoRepIntervalMinutes(autoRep.sync_interval_minutes);
          setAutoRepStatus(autoRep);
        }
        if (adminLoginAllowlist) {
          if (adminLoginAllowlist.enabled !== undefined) setAdminAllowlistEnabled(adminLoginAllowlist.enabled);
          if (adminLoginAllowlist.allowed_networks !== undefined) setAdminAllowlistNetworks(adminLoginAllowlist.allowed_networks.join(', '));
        }
        if (malwareScan) {
          if (malwareScan.enabled !== undefined) setMalwareScanEnabled(malwareScan.enabled);
          if (malwareScan.fail_mode) setMalwareScanFailMode(malwareScan.fail_mode);
          if (malwareScan.scan_timeout_seconds !== undefined) setMalwareScanTimeout(malwareScan.scan_timeout_seconds);
          setMalwareScanStatus(malwareScan);
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

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSaveGeneral = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      await saveGeneralSettings({
        refreshInterval,
        logsPerPage,
        liveUpdates
      });
      clearDirty('general');
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
      clearDirty('waf');
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
      clearDirty('hardening');
      showToast("Hardening & Server Cloaking policies updated and applied to NGINX.");
    } catch (err) {
      showToast("Failed to update hardening settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveGeoBlock = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const countries = geoBlockCountries.split(',').map(c => c.trim().toUpperCase()).filter(c => c);
      await saveGeoBlockSettings({
        enabled: geoBlockEnabled,
        mode: geoBlockMode,
        countries,
      });
      clearDirty('geoblock');
      showToast("Geo-Block policy updated.");
    } catch (err) {
      showToast("Failed to update geo-block settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveThreatIntel = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const saved = await saveThreatIntelSettings({
        enabled: threatIntelEnabled,
        sync_interval_hours: parseInt(threatIntelIntervalHours) || 24,
      });
      setThreatIntelStatus(saved);
      clearDirty('threatintel');
      showToast("Threat-intel feed settings updated.");
    } catch (err) {
      showToast("Failed to update threat-intel settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSyncThreatIntelNow = async () => {
    setThreatIntelSyncing(true);
    try {
      const result = await syncThreatIntelNow();
      showToast(`Threat-intel sync complete — ${result.count} CIDR ranges loaded.`);
      const refreshed = await getThreatIntelSettings();
      setThreatIntelStatus(refreshed);
    } catch (err) {
      showToast("Threat-intel sync failed: " + (err.message || "Unknown error"), "error");
    } finally {
      setThreatIntelSyncing(false);
    }
  };

  const handleFetchAutoBlockedIps = async () => {
    setAutoBlockedIpsLoading(true);
    try {
      const ips = await getAutoBlockedIps();
      setAutoBlockedIps(ips);
    } catch (err) {
      showToast("Failed to load auto-blocked IPs: " + (err.message || "Unknown error"), "error");
    } finally {
      setAutoBlockedIpsLoading(false);
    }
  };

  const handleSaveAutoReputation = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const saved = await saveAutoReputationSettings({
        enabled: autoRepEnabled,
        block_threshold: parseInt(autoRepThreshold) || 50,
        window_hours: parseInt(autoRepWindowHours) || 1,
        block_ttl_hours: parseInt(autoRepTtlHours) || 24,
        sync_interval_minutes: parseInt(autoRepIntervalMinutes) || 15,
      });
      setAutoRepStatus(saved);
      clearDirty('autorep');
      showToast("Self-learned IP reputation settings updated.");
    } catch (err) {
      showToast("Failed to update auto-reputation settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSyncAutoReputationNow = async () => {
    setAutoRepSyncing(true);
    try {
      const result = await syncAutoReputationNow();
      showToast(`Auto-reputation sync complete — ${result.count} IP(s) auto-blocked.`);
      const refreshed = await getAutoReputationSettings();
      setAutoRepStatus(refreshed);
      handleFetchAutoBlockedIps();
    } catch (err) {
      showToast("Auto-reputation sync failed: " + (err.message || "Unknown error"), "error");
    } finally {
      setAutoRepSyncing(false);
    }
  };

  const handleReleaseAutoBlockedIp = async (ip) => {
    try {
      await releaseAutoBlockedIp(ip);
      showToast(`${ip} released from auto-block.`);
      handleFetchAutoBlockedIps();
    } catch (err) {
      showToast(`Failed to release ${ip}: ` + (err.message || "Unknown error"), "error");
    }
  };

  const handleSaveAdminLoginAllowlist = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const networks = adminAllowlistNetworks.split(',').map(ip => ip.trim()).filter(ip => ip);
      const saved = await saveAdminLoginAllowlistSettings({
        enabled: adminAllowlistEnabled,
        allowed_networks: networks,
      });
      setAdminAllowlistNetworks(saved.allowed_networks.join(', '));
      clearDirty('adminallowlist');
      showToast("Admin-login IP allowlist updated.");
    } catch (err) {
      // Includes the backend's self-lockout guard message when an admin
      // tries to enable a list that excludes their own current IP.
      showToast("Failed to update admin-login allowlist: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleSaveMalwareScanning = async (e) => {
    e.preventDefault();
    setLoadingAction(true);
    try {
      const saved = await saveMalwareScanningSettings({
        enabled: malwareScanEnabled,
        fail_mode: malwareScanFailMode,
        scan_timeout_seconds: parseInt(malwareScanTimeout, 10) || 5,
      });
      setMalwareScanStatus(saved);
      clearDirty('malwarescan');
      showToast("Malware scanning settings updated.");
    } catch (err) {
      showToast("Failed to update malware scanning settings: " + (err.message || "Unknown error"), "error");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleCheckMalwareScanningNow = async () => {
    setMalwareScanChecking(true);
    try {
      const result = await checkMalwareScanningNow();
      setMalwareScanStatus(result);
      showToast(
        result.last_check_status === "ok"
          ? "ClamAV is reachable."
          : "ClamAV is unreachable — see status below."
      );
    } catch (err) {
      showToast("Failed to check ClamAV connectivity: " + (err.message || "Unknown error"), "error");
    } finally {
      setMalwareScanChecking(false);
    }
  };

  const fetchApiKeys = async () => {
    setApiKeysLoading(true);
    try {
      const keys = await getApiKeys();
      setApiKeys(keys || []);
    } catch (err) {
      showToast("Failed to load API keys: " + (err.message || "Unknown error"), "error");
    } finally {
      setApiKeysLoading(false);
    }
  };

  const handleCreateApiKey = async (e) => {
    e.preventDefault();
    setCreatingApiKey(true);
    try {
      const payload = { name: newKeyName, role: newKeyRole };
      if (newKeyExpiresDays) payload.expires_in_days = parseInt(newKeyExpiresDays);
      const created = await createApiKey(payload);
      setRevealedApiKey(created);
      setNewKeyName('');
      setNewKeyExpiresDays('');
      fetchApiKeys();
    } catch (err) {
      showToast("Failed to create API key: " + (err.message || "Unknown error"), "error");
    } finally {
      setCreatingApiKey(false);
    }
  };

  const handleRevokeApiKey = async (id) => {
    try {
      await revokeApiKey(id);
      showToast("API key revoked.");
      fetchApiKeys();
    } catch (err) {
      showToast("Failed to revoke API key: " + (err.message || "Unknown error"), "error");
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
      clearDirty('defacement');
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
      clearDirty('possec');
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
      clearDirty('customresponse');
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
      clearDirty('autolearning');
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

  // Activity Log (admin-action audit trail)
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotal, setAuditTotal] = useState(0);
  const AUDIT_PAGE_SIZE = 25;

  const fetchAuditLog = async (page = 1) => {
    setAuditLoading(true);
    try {
      const res = await getAuditLog(page, AUDIT_PAGE_SIZE);
      setAuditEntries(res.data || []);
      setAuditTotal(res.total || 0);
      setAuditPage(page);
    } catch (err) {
      showToast("Failed to load activity log: " + (err.message || "Unknown error"), "error");
    } finally {
      setAuditLoading(false);
    }
  };

  useEffect(() => {
    if (activeSettingTab === 'activity-log') {
      const timer = setTimeout(() => fetchAuditLog(1), 0);
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingTab]);

  // Backups (full-system config/DB snapshots)
  const [backups, setBackups] = useState([]);
  const [backupsLoading, setBackupsLoading] = useState(false);
  const [creatingBackup, setCreatingBackup] = useState(false);
  const [backupActionId, setBackupActionId] = useState(null); // id currently being restored/deleted

  const fetchBackups = async () => {
    setBackupsLoading(true);
    try {
      const res = await getBackups();
      setBackups(res || []);
    } catch (err) {
      showToast("Failed to load backups: " + (err.message || "Unknown error"), "error");
    } finally {
      setBackupsLoading(false);
    }
  };

  useEffect(() => {
    if (activeSettingTab === 'backups') {
      const timer = setTimeout(() => fetchBackups(), 0);
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingTab]);

  useEffect(() => {
    if (activeSettingTab === 'security') {
      const timer = setTimeout(() => fetchApiKeys(), 0);
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingTab]);

  useEffect(() => {
    if (activeSettingTab === 'hardening') {
      const timer = setTimeout(() => handleFetchAutoBlockedIps(), 0);
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingTab]);

  const handleCreateBackup = async () => {
    setCreatingBackup(true);
    try {
      await createBackup();
      showToast("Backup created.");
      await fetchBackups();
    } catch (err) {
      showToast("Backup failed: " + (err.message || "Unknown error"), "error");
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleDownloadBackup = async (backup) => {
    try {
      await downloadBackup(backup.id, backup.filename);
    } catch (err) {
      showToast("Download failed: " + (err.message || "Unknown error"), "error");
    }
  };

  const handleRestoreBackup = async (backup) => {
    if (!(await confirm({
      message: `Restore from "${backup.filename}"? This overwrites the live nginx configuration and every control-plane database with this backup's contents. A safety snapshot of the current state is taken automatically first, but this is still a major, immediate change — proceed?`,
      danger: true,
    }))) return;
    setBackupActionId(backup.id);
    try {
      const res = await restoreBackup(backup.id);
      showToast(res.message || "Restore complete.");
      await fetchBackups();
    } catch (err) {
      showToast("Restore failed: " + (err.message || "Unknown error"), "error");
    } finally {
      setBackupActionId(null);
    }
  };

  const handleDeleteBackup = async (backup) => {
    if (!(await confirm({ message: `Delete backup "${backup.filename}"? This cannot be undone.`, danger: true }))) return;
    setBackupActionId(backup.id);
    try {
      await deleteBackup(backup.id);
      showToast("Backup deleted.");
      await fetchBackups();
    } catch (err) {
      showToast("Delete failed: " + (err.message || "Unknown error"), "error");
    } finally {
      setBackupActionId(null);
    }
  };

  const formatBackupSize = (bytes) => {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes, i = 0;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return `${size.toFixed(1)} ${units[i]}`;
  };

  const TRIGGER_TYPE_LABELS = {
    manual: 'Manual',
    pre_restore_safety: 'Auto (pre-restore safety)',
  };

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
      clearDirty('logs');
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

      {/* Unsaved-changes bar — each form here saves independently (no "save
          all"), so this is awareness, not another save action: which
          section(s) have edits sitting uncommitted, and a one-click jump to
          them if the admin isn't already looking at that tab. */}
      {createPortal(
        <AnimatePresence>
          {Object.keys(dirtySections).length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 16 }}
              transition={{ duration: 0.2 }}
              style={{
                position: 'fixed', left: '50%', bottom: '24px', transform: 'translateX(-50%)',
                zIndex: 500, maxWidth: 'min(680px, calc(100vw - 48px))',
                display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap',
                padding: '10px 16px', borderRadius: '10px',
                background: 'var(--warning-bg)', border: '1px solid var(--warning-glow)',
                boxShadow: '0 10px 30px rgba(0,0,0,0.35)',
              }}
            >
              <AlertTriangle size={16} color="var(--warning-color)" style={{ flexShrink: 0 }} />
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--warning-color)', whiteSpace: 'nowrap' }}>
                Unsaved changes:
              </span>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {Object.keys(dirtySections).map((key) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setActiveSettingTab(SETTINGS_SECTIONS[key]?.tab || key)}
                    style={{
                      fontSize: '11px', fontWeight: 600, padding: '3px 10px', borderRadius: '999px',
                      background: 'var(--surface-hover)', color: 'var(--text-primary)',
                      border: '1px solid var(--warning-glow)', cursor: 'pointer', whiteSpace: 'nowrap',
                    }}
                  >
                    {SETTINGS_SECTIONS[key]?.label || key}
                  </button>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>,
        document.body
      )}

      {/* Danger Modal confirmation prompt */}
      <AnimatePresence>
        {dangerModal && (
          <div className="modal-overlay" style={{ zIndex: 1100 }}>
            <motion.div
              className="modal-content pulse-warning"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="danger-modal-title"
              style={{ maxWidth: '480px', border: '1px solid var(--danger-border)' }}
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
            >
              <div className="modal-header" style={{ background: 'var(--danger-bg)', borderBottom: '1px solid var(--danger-border)' }}>
                <div className="modal-title" id="danger-modal-title" style={{ color: 'var(--danger-color)' }}>
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

        {/* Sidebar Navigation — grouped into 4 domains instead of one flat
            list of 11. Every button below is unchanged (same onClick, same
            icon, same active-state check) — only the grouping/labels are
            new, so no tab's own behavior is touched by this. A search box
            filters this same list by label text rather than introducing a
            second way to navigate — 11 sections is approaching the point
            where scanning a static list stops being enough. */}
        <div className="settings-sidebar">
          <div style={{ position: 'relative', marginBottom: '8px' }}>
            <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              value={settingsSearch}
              onChange={(e) => setSettingsSearch(e.target.value)}
              placeholder="Search settings..."
              aria-label="Search settings"
              className="search-input"
              style={{ width: '100%', paddingLeft: '34px', margin: 0 }}
            />
          </div>

          {matchesSettingsSearch('Engine', 'General Setup', 'WAF Engine Policies', 'Log Pipeline') && (
            <div className="settings-sidebar-group-label" style={{ marginTop: 0 }}>Engine</div>
          )}
          {matchesSettingsSearch('General Setup') && (
            <button onClick={() => setActiveSettingTab('general')} className={`settings-tab-btn ${activeSettingTab === 'general' ? 'active' : ''}`}>
              <SettingsIcon size={20} /> General Setup
            </button>
          )}
          {matchesSettingsSearch('WAF Engine Policies') && (
            <button onClick={() => setActiveSettingTab('waf')} className={`settings-tab-btn ${activeSettingTab === 'waf' ? 'active' : ''}`}>
              <ShieldCheck size={20} /> WAF Engine Policies
            </button>
          )}
          {matchesSettingsSearch('Log Pipeline') && (
            <button onClick={() => setActiveSettingTab('logs')} className={`settings-tab-btn ${activeSettingTab === 'logs' ? 'active' : ''}`}>
              <Database size={20} /> Log Pipeline
            </button>
          )}

          {matchesSettingsSearch('Hardening', 'Server Hardening') && (
            <div className="settings-sidebar-group-label">Hardening</div>
          )}
          {matchesSettingsSearch('Server Hardening') && (
            <button onClick={() => setActiveSettingTab('hardening')} className={`settings-tab-btn ${activeSettingTab === 'hardening' ? 'active' : ''}`}>
              <Server size={20} /> Server Hardening
            </button>
          )}

          {matchesSettingsSearch('Detection Tuning', 'Positive Security', 'Anti-Defacement', 'Auto-Learning', 'Custom Response') && (
            <div className="settings-sidebar-group-label">Detection Tuning</div>
          )}
          {matchesSettingsSearch('Positive Security') && (
            <button onClick={() => setActiveSettingTab('positive-security')} className={`settings-tab-btn ${activeSettingTab === 'positive-security' ? 'active' : ''}`}>
              <CheckSquare size={20} /> Positive Security
            </button>
          )}
          {matchesSettingsSearch('Anti-Defacement') && (
            <button onClick={() => setActiveSettingTab('defacement')} className={`settings-tab-btn ${activeSettingTab === 'defacement' ? 'active' : ''}`}>
              <ShieldAlert size={20} /> Anti-Defacement
            </button>
          )}
          {matchesSettingsSearch('Auto-Learning') && (
            <button onClick={() => setActiveSettingTab('auto-learning')} className={`settings-tab-btn ${activeSettingTab === 'auto-learning' ? 'active' : ''}`}>
              <Brain size={20} /> Auto-Learning
            </button>
          )}
          {matchesSettingsSearch('Custom Response') && (
            <button onClick={() => setActiveSettingTab('custom-response')} className={`settings-tab-btn ${activeSettingTab === 'custom-response' ? 'active' : ''}`}>
              <FileCode size={20} /> Custom Response
            </button>
          )}

          {matchesSettingsSearch('Access & Audit', 'Security & Danger Zone', 'Activity Log', 'Backups') && (
            <div className="settings-sidebar-group-label">Access &amp; Audit</div>
          )}
          {matchesSettingsSearch('Security & Danger Zone') && (
            <button onClick={() => setActiveSettingTab('security')} className={`settings-tab-btn ${activeSettingTab === 'security' ? 'active' : ''}`}>
              <Lock size={20} /> Security & Danger Zone
            </button>
          )}
          {matchesSettingsSearch('Activity Log') && (
            <button onClick={() => setActiveSettingTab('activity-log')} className={`settings-tab-btn ${activeSettingTab === 'activity-log' ? 'active' : ''}`}>
              <History size={20} /> Activity Log
            </button>
          )}
          {matchesSettingsSearch('Backups') && (
            <button onClick={() => setActiveSettingTab('backups')} className={`settings-tab-btn ${activeSettingTab === 'backups' ? 'active' : ''}`}>
              <Archive size={20} /> Backups
            </button>
          )}

          {settingsSearch.trim() && !hasAnySettingsMatch && (
            <div style={{ padding: '16px', fontSize: '12px', color: 'var(--text-muted)', textAlign: 'center' }}>
              No settings match "{settingsSearch}".
            </div>
          )}
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

                <form onSubmit={handleSaveGeneral} onChange={() => markDirty('general')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-refresh-interval">Dashboard Refresh Interval</label>
                    <select id="settings-refresh-interval" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={refreshInterval} onChange={(e) => setRefreshInterval(e.target.value)}>
                      <option value="3s">3 Seconds (Sync Active)</option>
                      <option value="5s">5 Seconds (Recommended)</option>
                      <option value="10s">10 Seconds</option>
                      <option value="30s">30 Seconds</option>
                      <option value="off">Disabled / Manual</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-logs-per-page">Live Logs Per Page</label>
                    <select id="settings-logs-per-page" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={logsPerPage} onChange={(e) => setLogsPerPage(e.target.value)}>
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
                    <button type="button" role="switch" aria-checked={liveUpdates} aria-label="Live Inbound Stream" className={`toggle-switch ${liveUpdates ? 'active' : ''}`} onClick={() => setLiveUpdates(!liveUpdates)}>
                      <div className="toggle-knob"></div>
                    </button>
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

                <form onSubmit={handleSaveWAF} onChange={() => markDirty('waf')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-secruleengine-posture">SecRuleEngine Posture</label>
                    <select id="settings-secruleengine-posture" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={secRuleEngine} onChange={(e) => setSecRuleEngine(e.target.value)}>
                      <option value="On">On (Active Blocking Guard)</option>
                      <option value="DetectionOnly">DetectionOnly (Simulate Attacks)</option>
                      <option value="Off">Off (Bypass WAF Shields - Critical Risk)</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-response-filtering-mode">Response Filtering Mode</label>
                    <select id="settings-response-filtering-mode" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={detectionMode} onChange={(e) => setDetectionMode(e.target.value)}>
                      <option value="Blocking">Strict Block & Drop (403 Forbidden)</option>
                      <option value="Detection">Log Analysis Only (Bypass drops)</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}>
                    <label htmlFor="settings-paranoia-level" style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Global Paranoia Setting</span>
                      <strong style={{ color: 'var(--sev-low)', fontSize: '14px' }}>PL{paranoiaLevel}</strong>
                    </label>
                    <input
                      id="settings-paranoia-level"
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

                <form onSubmit={handleSaveLogs} onChange={() => markDirty('logs')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>SecAuditEngine Logging</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Record details of flagged transactions</span>
                    </div>
                    <button type="button" role="switch" aria-checked={auditEnabled} aria-label="SecAuditEngine Logging" className={`toggle-switch ${auditEnabled ? 'active' : ''}`} onClick={() => setAuditEnabled(!auditEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-audit-log-format">Audit Log Structure Formats</label>
                    <select id="settings-audit-log-format" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={logFormat} onChange={(e) => setLogFormat(e.target.value)}>
                      <option value="JSON">Structured JSON (RFC 8259 Standard)</option>
                      <option value="Native">CyberSentinel Engine Native Audit Structure</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Concurrent Multi-Threading</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Non-blocking log processing pipeline</span>
                    </div>
                    <button type="button" role="switch" aria-checked={concurrentLogging} aria-label="Concurrent Multi-Threading" className={`toggle-switch ${concurrentLogging ? 'active' : ''}`} onClick={() => setConcurrentLogging(!concurrentLogging)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-log-retention-period">Log Retention Period</label>
                    <select id="settings-log-retention-period" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={retention} onChange={(e) => setRetention(e.target.value)}>
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
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <SettingsAccordionCard icon={Server} title="Infrastructure Hardening" status={hstsEnabled ? 'HSTS On' : 'HSTS Off'} tone={hstsEnabled ? 'active' : 'inactive'}>
                <div className="settings-section-subtitle" style={{ marginTop: 0 }}>Manage HSTS, server cloaking, and IP restrictions.</div>

                <form onSubmit={handleSaveHardening} onChange={() => markDirty('hardening')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Strict HTTPS (HSTS)</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Enforce Strict-Transport-Security header</span>
                    </div>
                    <button type="button" role="switch" aria-checked={hstsEnabled} aria-label="Strict HTTPS (HSTS)" className={`toggle-switch ${hstsEnabled ? 'active' : ''}`} onClick={() => setHstsEnabled(!hstsEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <AnimatePresence>
                    {hstsEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', paddingBottom: '10px' }}>
                          <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-hsts-max-age">HSTS Max Age (Seconds)</label>
                          <input id="settings-hsts-max-age"
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
                    <button type="button" role="switch" aria-checked={serverCloaking} aria-label="Server Cloaking" className={`toggle-switch ${serverCloaking ? 'active' : ''}`} onClick={() => setServerCloaking(!serverCloaking)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-ip-blacklist">Global IP Blacklist (Comma separated)</label>
                    <textarea id="settings-ip-blacklist"
                      className="settings-input"
                      style={{ width: '100%', minHeight: '80px', resize: 'vertical' }}
                      value={ipBlacklist}
                      onChange={(e) => setIpBlacklist(e.target.value)}
                      placeholder="192.168.1.100, 10.0.0.50"
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-ip-whitelist">Global IP Whitelist (Comma separated)</label>
                    <textarea id="settings-ip-whitelist"
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
                </SettingsAccordionCard>

                <SettingsAccordionCard icon={ShieldAlert} title="Geo-Block" status={geoBlockEnabled ? 'Active' : 'Off'} tone={geoBlockEnabled ? 'active' : 'inactive'}>
                <div className="settings-section-subtitle" style={{ marginTop: 0 }}>
                  Allow or deny traffic by country. Requires GeoIP2 to be enabled (Settings loads with it
                  active in this deployment) — otherwise this has no effect.
                </div>

                <form onSubmit={handleSaveGeoBlock} onChange={() => markDirty('geoblock')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Geo-Block</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — no country restrictions until enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={geoBlockEnabled} aria-label="Enable Geo-Block" className={`toggle-switch ${geoBlockEnabled ? 'active' : ''}`} onClick={() => setGeoBlockEnabled(!geoBlockEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <AnimatePresence>
                    {geoBlockEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-geoblock-mode">Mode</label>
                          <select id="settings-geoblock-mode"
                            className="settings-input"
                            style={{ width: '100%', fontSize: '14px' }}
                            value={geoBlockMode}
                            onChange={(e) => setGeoBlockMode(e.target.value)}
                          >
                            <option value="deny">Deny listed countries (block only these)</option>
                            <option value="allow">Allow listed countries only (block everyone else)</option>
                          </select>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-geoblock-countries">Countries (ISO 3166-1 alpha-2 codes, comma separated)</label>
                          <textarea id="settings-geoblock-countries"
                            className="settings-input"
                            style={{ width: '100%', minHeight: '60px', resize: 'vertical' }}
                            value={geoBlockCountries}
                            onChange={(e) => setGeoBlockCountries(e.target.value)}
                            placeholder="RU, CN, KP"
                          />
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <div style={{ marginTop: '4px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Apply Geo-Block Changes
                    </button>
                  </div>
                </form>
                </SettingsAccordionCard>

                <SettingsAccordionCard icon={ShieldAlert} title="External Threat-Intel Feed" status={threatIntelEnabled ? 'Active' : 'Off'} tone={threatIntelEnabled ? 'active' : 'inactive'}>
                <div className="settings-section-subtitle" style={{ marginTop: 0 }}>
                  Pulls Spamhaus DROP + EDROP (free, no API key) on a schedule into a dedicated
                  blacklist Redis key — separate from the manual IP blacklist above, so a sync
                  can never overwrite your own entries. Your manual whitelist always overrides it.
                </div>

                <form onSubmit={handleSaveThreatIntel} onChange={() => markDirty('threatintel')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Scheduled Sync</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — no external feed until enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={threatIntelEnabled} aria-label="Enable Scheduled Sync" className={`toggle-switch ${threatIntelEnabled ? 'active' : ''}`} onClick={() => setThreatIntelEnabled(!threatIntelEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <AnimatePresence>
                    {threatIntelEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', paddingBottom: '10px' }}>
                          <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-threatintel-sync-interval">Sync Interval (Hours)</label>
                          <input id="settings-threatintel-sync-interval"
                            type="number"
                            min="1"
                            className="settings-input"
                            style={{ width: '100%', fontSize: '14px' }}
                            value={threatIntelIntervalHours}
                            onChange={(e) => setThreatIntelIntervalHours(e.target.value)}
                            placeholder="24"
                          />
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {threatIntelStatus && (
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span>
                        Last sync: {threatIntelStatus.last_sync_at ? formatLocalTime(threatIntelStatus.last_sync_at) : 'never'}
                        {threatIntelStatus.last_sync_status === 'success' && ` — ${threatIntelStatus.last_sync_count} CIDR ranges loaded`}
                        {threatIntelStatus.last_sync_status === 'error' && ` — failed: ${threatIntelStatus.last_sync_error || 'unknown error'}`}
                      </span>
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: '12px', marginTop: '4px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Apply Threat-Intel Changes
                    </button>
                    <button
                      type="button"
                      onClick={handleSyncThreatIntelNow}
                      disabled={threatIntelSyncing}
                      className="action-btn-inspect"
                    >
                      {threatIntelSyncing ? 'Syncing...' : 'Sync Now'}
                    </button>
                  </div>
                </form>
                </SettingsAccordionCard>

                <SettingsAccordionCard icon={ShieldAlert} title="Self-Learned IP Reputation" status={autoRepEnabled ? `${autoBlockedIps.length} IPs blocked` : 'Off'} tone={autoRepEnabled ? 'active' : 'inactive'}>
                <div className="settings-section-subtitle" style={{ marginTop: 0 }}>
                  Watches this deployment's own traffic (not a third-party feed) for IPs racking up
                  enough blocked requests to count as proven repeat offenders, and auto-blocks them —
                  a self-tuning defense that improves with your own traffic. Separate Redis key from
                  the manual blacklist and the threat-intel feed above; each auto-block self-expires
                  on its own TTL rather than growing a permanent list, and never overrides your manual
                  whitelist.
                </div>

                <form onSubmit={handleSaveAutoReputation} onChange={() => markDirty('autorep')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Auto-Block</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — nobody gets auto-blocked until enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={autoRepEnabled} aria-label="Enable Auto-Block" className={`toggle-switch ${autoRepEnabled ? 'active' : ''}`} onClick={() => setAutoRepEnabled(!autoRepEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <AnimatePresence>
                    {autoRepEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', paddingBottom: '10px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-autorep-block-threshold">Block Threshold (requests)</label>
                            <input id="settings-autorep-block-threshold"
                              type="number" min="1" className="settings-input" style={{ fontSize: '14px' }}
                              value={autoRepThreshold} onChange={(e) => setAutoRepThreshold(e.target.value)}
                            />
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-autorep-window-hours">Window (hours)</label>
                            <input id="settings-autorep-window-hours"
                              type="number" min="1" className="settings-input" style={{ fontSize: '14px' }}
                              value={autoRepWindowHours} onChange={(e) => setAutoRepWindowHours(e.target.value)}
                            />
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-autorep-block-duration">Block Duration (hours)</label>
                            <input id="settings-autorep-block-duration"
                              type="number" min="1" className="settings-input" style={{ fontSize: '14px' }}
                              value={autoRepTtlHours} onChange={(e) => setAutoRepTtlHours(e.target.value)}
                            />
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-autorep-sync-interval">Sync Interval (minutes)</label>
                            <input id="settings-autorep-sync-interval"
                              type="number" min="5" className="settings-input" style={{ fontSize: '14px' }}
                              value={autoRepIntervalMinutes} onChange={(e) => setAutoRepIntervalMinutes(e.target.value)}
                            />
                          </div>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-secondary)', paddingBottom: '10px' }}>
                          An IP with {autoRepThreshold}+ blocked requests in the last {autoRepWindowHours}h gets
                          auto-blocked for {autoRepTtlHours}h, checked every {autoRepIntervalMinutes} minutes.
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {autoRepStatus && (
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      Last sync: {autoRepStatus.last_sync_at ? formatLocalTime(autoRepStatus.last_sync_at) : 'never'}
                      {autoRepStatus.last_sync_status === 'success' && ` — ${autoRepStatus.last_sync_count} IP(s) auto-blocked`}
                      {autoRepStatus.last_sync_status === 'error' && ` — failed: ${autoRepStatus.last_sync_error || 'unknown error'}`}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: '12px', marginTop: '4px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Apply Auto-Reputation Changes
                    </button>
                    <button
                      type="button"
                      onClick={handleSyncAutoReputationNow}
                      disabled={autoRepSyncing}
                      className="action-btn-inspect"
                    >
                      {autoRepSyncing ? 'Syncing...' : 'Sync Now'}
                    </button>
                  </div>
                </form>

                <div style={{ marginTop: '20px', maxWidth: '600px' }}>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                    Currently Auto-Blocked ({autoBlockedIps.length})
                  </div>
                  {autoBlockedIpsLoading ? (
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Loading...</div>
                  ) : autoBlockedIps.length === 0 ? (
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>No IPs currently auto-blocked.</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                      {autoBlockedIps.map((entry) => (
                        <tr key={entry.ip} style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                          <td style={{ padding: '6px 0', fontFamily: 'monospace' }}>{entry.ip}</td>
                          <td style={{ padding: '6px 8px', color: 'var(--text-secondary)' }}>
                            expires in {Math.max(0, Math.round(entry.ttl_seconds / 60))}m
                          </td>
                          <td style={{ padding: '6px 0', textAlign: 'right' }}>
                            <button
                              type="button"
                              onClick={() => handleReleaseAutoBlockedIp(entry.ip)}
                              className="action-btn-inspect"
                              style={{ padding: '3px 10px', fontSize: '11px' }}
                            >
                              Release
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody></table>
                  )}
                </div>
                </SettingsAccordionCard>

                <SettingsAccordionCard icon={Lock} title="Admin-Login IP Allowlist" status={adminAllowlistEnabled ? 'Active' : 'Off'} tone={adminAllowlistEnabled ? 'active' : 'inactive'}>
                <div className="settings-section-subtitle" style={{ marginTop: 0 }}>
                  Restricts the dashboard's own login (and MFA step) to specific IPs/CIDRs — separate
                  from the Global IP Whitelist/Blacklist above, which gates all site traffic. Even a
                  stolen valid password can't reach a live session from outside this list. Applies to
                  every account (admin, analyst, and app-scoped admins) uniformly.
                </div>

                <div style={{
                  display: 'flex', gap: '10px', background: 'var(--sev-low-bg)',
                  border: '1px solid var(--sev-low-border)', borderRadius: '10px',
                  padding: '14px 16px', marginBottom: '20px', maxWidth: '600px',
                }}>
                  <AlertTriangle size={16} color="var(--sev-low)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    The server refuses to enable this if your own current IP isn't in the list below —
                    there's no other admin-facing way back in once every login is blocked. Add your
                    own IP or CIDR first.
                  </span>
                </div>

                <form onSubmit={handleSaveAdminLoginAllowlist} onChange={() => markDirty('adminallowlist')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Login Allowlist</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — login works from anywhere until enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={adminAllowlistEnabled} aria-label="Enable Login Allowlist" className={`toggle-switch ${adminAllowlistEnabled ? 'active' : ''}`} onClick={() => setAdminAllowlistEnabled(!adminAllowlistEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-admin-allowlist-networks">Allowed IPs / CIDRs (Comma separated)</label>
                    <textarea id="settings-admin-allowlist-networks"
                      className="settings-input"
                      style={{ width: '100%', minHeight: '80px', resize: 'vertical' }}
                      value={adminAllowlistNetworks}
                      onChange={(e) => setAdminAllowlistNetworks(e.target.value)}
                      placeholder="203.0.113.5, 10.0.0.0/24"
                    />
                  </div>

                  <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" disabled={loadingAction} className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      {loadingAction ? 'Applying...' : 'Apply Login Allowlist'}
                    </button>
                  </div>
                </form>
                </SettingsAccordionCard>

                <SettingsAccordionCard icon={ShieldAlert} title="Malware Scanning" status={malwareScanEnabled ? 'Active' : 'Off'} tone={malwareScanEnabled ? 'active' : 'inactive'}>
                <div className="settings-section-subtitle" style={{ marginTop: 0 }}>
                  Scans uploaded files with ClamAV before they reach a protected app's backend
                  (or the dashboard's own certificate upload). A defense-in-depth layer on top of
                  the WAF's existing rule-based protections, not a replacement for them.
                </div>

                <form onSubmit={handleSaveMalwareScanning} onChange={() => markDirty('malwarescan')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Malware Scanning</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — no uploads are scanned until enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={malwareScanEnabled} aria-label="Enable Malware Scanning" className={`toggle-switch ${malwareScanEnabled ? 'active' : ''}`} onClick={() => setMalwareScanEnabled(!malwareScanEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <AnimatePresence>
                    {malwareScanEnabled && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', paddingBottom: '10px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-malwarescan-fail-mode">If ClamAV is unreachable</label>
                            <select id="settings-malwarescan-fail-mode" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={malwareScanFailMode} onChange={(e) => setMalwareScanFailMode(e.target.value)}>
                              <option value="open">Allow uploads through unscanned (recommended)</option>
                              <option value="closed">Block all uploads until it recovers</option>
                            </select>
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-malwarescan-timeout">Scan Timeout (seconds)</label>
                            <input id="settings-malwarescan-timeout"
                              type="number" min="1" max="60" className="settings-input" style={{ fontSize: '14px' }}
                              value={malwareScanTimeout} onChange={(e) => setMalwareScanTimeout(e.target.value)}
                            />
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {malwareScanStatus && (
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      ClamAV status: {' '}
                      <strong style={{ color: malwareScanStatus.last_check_status === 'ok' ? 'var(--success-color)' : 'var(--danger-color)' }}>
                        {malwareScanStatus.last_check_status === 'ok' ? 'Reachable'
                          : malwareScanStatus.last_check_status === 'degraded' ? 'Unreachable'
                          : 'Never checked'}
                      </strong>
                      {malwareScanStatus.last_check_at && ` — last checked ${formatLocalTime(malwareScanStatus.last_check_at)}`}
                      {malwareScanStatus.last_check_error && ` (${malwareScanStatus.last_check_error})`}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: '12px', marginTop: '4px', paddingTop: '20px', borderTop: '1px solid var(--surface-hover)' }}>
                    <button type="submit" className="modal-btn primary" style={{ padding: '12px 24px', fontSize: '14px' }}>
                      Apply Malware Scanning Changes
                    </button>
                    <button
                      type="button"
                      onClick={handleCheckMalwareScanningNow}
                      disabled={malwareScanChecking}
                      className="action-btn-inspect"
                    >
                      {malwareScanChecking ? 'Checking...' : 'Check Connection Now'}
                    </button>
                  </div>
                </form>
                </SettingsAccordionCard>
                </div>
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

                <form onSubmit={handleSavePositiveSecurity} onChange={() => markDirty('possec')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Positive Security</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — no rules are active until enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={posSecEnabled} aria-label="Enable Positive Security" className={`toggle-switch ${posSecEnabled ? 'active' : ''}`} onClick={() => setPosSecEnabled(!posSecEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-possec-methods">Allowed HTTP Methods (Comma separated)</label>
                    <textarea id="settings-possec-methods"
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
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-possec-content-types">Allowed Content-Types (Comma separated)</label>
                    <textarea id="settings-possec-content-types"
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
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-possec-extensions">Restricted File Extensions (Comma separated)</label>
                    <textarea id="settings-possec-extensions"
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

                <form onSubmit={handleSaveDefacement} onChange={() => markDirty('defacement')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Real-time Integrity Monitor</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Revert unauthorized content modifications instantly</span>
                    </div>
                    <button type="button" role="switch" aria-checked={defacementEnabled} aria-label="Real-time Integrity Monitor" className={`toggle-switch ${defacementEnabled ? 'active' : ''}`} onClick={() => setDefacementEnabled(!defacementEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-defacement-check-interval">Audit Scan Interval (Seconds)</label>
                    <select id="settings-defacement-check-interval" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={checkInterval} onChange={(e) => setCheckInterval(parseInt(e.target.value))}>
                      <option value="2">2 Seconds (High sensitivity)</option>
                      <option value="5">5 Seconds (Recommended)</option>
                      <option value="10">10 Seconds</option>
                      <option value="30">30 Seconds</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-defacement-files">Monitored Asset Filepaths (Comma separated)</label>
                    <textarea id="settings-defacement-files"
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

                <form onSubmit={handleSaveCustomResponse} onChange={() => markDirty('customresponse')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '700px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-custom-response-html">Block Page HTML</label>
                    <textarea id="settings-custom-response-html"
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

                <form onSubmit={handleSaveAutoLearning} onChange={() => markDirty('autolearning')} style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '600px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '12px', border: '1px solid var(--surface-hover)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>Enable Auto-Learning</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Off by default — baselines only update when enabled</span>
                    </div>
                    <button type="button" role="switch" aria-checked={autoLearningEnabled} aria-label="Enable Auto-Learning" className={`toggle-switch ${autoLearningEnabled ? 'active' : ''}`} onClick={() => setAutoLearningEnabled(!autoLearningEnabled)}>
                      <div className="toggle-knob"></div>
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-autolearning-period">Learning Period</label>
                    <select id="settings-autolearning-period" className="filter-select" style={{ width: '100%', padding: '12px', fontSize: '14px' }} value={autoLearningPeriod} onChange={(e) => setAutoLearningPeriod(e.target.value)}>
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
                    <label htmlFor="settings-confidence-threshold" style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Confidence Threshold ({autoLearningThreshold}%)</label>
                    <input
                      id="settings-confidence-threshold"
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
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-current-admin-password">Current Admin Password</label>
                      <input id="settings-current-admin-password" type="password" placeholder="••••••••" className="settings-input" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-new-security-password">New Security Password</label>
                      <input id="settings-new-security-password" type="password" placeholder="••••••••" className="settings-input" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-confirm-new-password">Confirm New Password</label>
                      <input id="settings-confirm-new-password" type="password" placeholder="••••••••" className="settings-input" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                      <label style={{ fontSize: '13px', color: 'var(--text-secondary)' }} htmlFor="settings-session-timeout">Portal Session Timeout</label>
                      <select id="settings-session-timeout" className="filter-select" style={{ width: '100%', padding: '12px' }} value={sessionTimeout} onChange={(e) => setSessionTimeout(e.target.value)}>
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

                  {/* API Keys */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>API Keys</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        Machine credentials for scripts, CI/CD, or external tools to call this API without an
                        interactive login. Each key carries the same admin/analyst role permissions as a
                        dashboard account, independent of any user's password or session.
                      </div>
                    </div>

                    {revealedApiKey && (
                      <div style={{ background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                          Key "{revealedApiKey.name}" created — copy it now, it will not be shown again.
                        </div>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <code style={{ flex: 1, fontSize: '12px', background: 'var(--surface-subtle)', padding: '8px 10px', borderRadius: '6px', wordBreak: 'break-all' }}>
                            {revealedApiKey.api_key}
                          </code>
                          <button
                            type="button"
                            className="action-btn-inspect"
                            style={{ padding: '6px 12px', fontSize: '12px', flexShrink: 0 }}
                            onClick={() => {
                              navigator.clipboard.writeText(revealedApiKey.api_key);
                              showToast("Copied to clipboard.");
                            }}
                          >
                            Copy
                          </button>
                        </div>
                        <button
                          type="button"
                          onClick={() => setRevealedApiKey(null)}
                          className="action-btn-inspect"
                          style={{ alignSelf: 'flex-start', padding: '4px 10px', fontSize: '11px' }}
                        >
                          Dismiss
                        </button>
                      </div>
                    )}

                    <form onSubmit={handleCreateApiKey} style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: '2 1 160px' }}>
                        <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }} htmlFor="settings-new-api-key-name">Key Name</label>
                        <input id="settings-new-api-key-name"
                          type="text" className="settings-input" value={newKeyName}
                          onChange={(e) => setNewKeyName(e.target.value)}
                          placeholder="CI/CD pipeline" required
                        />
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: '1 1 140px' }}>
                        <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }} htmlFor="settings-new-api-key-role">Role</label>
                        <select id="settings-new-api-key-role" className="filter-select" style={{ padding: '10px' }} value={newKeyRole} onChange={(e) => setNewKeyRole(e.target.value)}>
                          <option value="analyst">Analyst (read-only)</option>
                          <option value="admin">Admin (full access)</option>
                        </select>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: '1 1 110px' }}>
                        <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }} htmlFor="settings-new-api-key-expires">Expires (days)</label>
                        <input id="settings-new-api-key-expires"
                          type="number" min="1" className="settings-input" value={newKeyExpiresDays}
                          onChange={(e) => setNewKeyExpiresDays(e.target.value)}
                          placeholder="Never"
                        />
                      </div>
                      <button type="submit" disabled={creatingApiKey} className="modal-btn primary" style={{ padding: '10px 18px', fontSize: '13px' }}>
                        {creatingApiKey ? 'Creating...' : 'Create Key'}
                      </button>
                    </form>

                    {apiKeysLoading ? (
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Loading...</div>
                    ) : apiKeys.length === 0 ? (
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>No API keys created yet.</div>
                    ) : (
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                        {apiKeys.map((k) => (
                          <tr key={k.id} style={{ borderBottom: '1px solid var(--surface-subtle)', opacity: k.enabled ? 1 : 0.5 }}>
                            <td style={{ padding: '8px 0' }}>
                              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{k.name}</div>
                              <div style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{k.key_prefix}…</div>
                            </td>
                            <td style={{ padding: '8px', color: 'var(--text-secondary)' }}>{k.role}</td>
                            <td style={{ padding: '8px', color: 'var(--text-secondary)' }}>
                              {!k.enabled ? 'revoked' : k.expires_at ? `expires ${formatLocalTime(k.expires_at)}` : 'never expires'}
                            </td>
                            <td style={{ padding: '8px', color: 'var(--text-secondary)' }}>
                              {k.last_used_at ? `used ${formatLocalTime(k.last_used_at)}` : 'never used'}
                            </td>
                            <td style={{ padding: '8px 0', textAlign: 'right' }}>
                              {k.enabled && (
                                <button
                                  type="button"
                                  onClick={() => handleRevokeApiKey(k.id)}
                                  className="action-btn-inspect"
                                  style={{ padding: '3px 10px', fontSize: '11px', color: 'var(--danger-color)' }}
                                >
                                  Revoke
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody></table>
                    )}
                  </div>

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

            {activeSettingTab === 'activity-log' && (
              <motion.div key="activity-log" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <History size={20} color="var(--accent-color)" />
                  Activity Log
                </div>
                <div className="settings-section-subtitle">Who changed what WAF configuration, and when — settings, protected apps, users, false positives, and rules.</div>

                {auditLoading ? (
                  <div style={{ padding: '24px', color: 'var(--text-secondary)' }}>Loading...</div>
                ) : auditEntries.length === 0 ? (
                  <div style={{ padding: '24px', color: 'var(--text-secondary)' }}>No activity recorded yet.</div>
                ) : (
                  <>
                    <div style={{ overflowX: 'auto' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Entity</th>
                            <th>Action</th>
                            <th>Details</th>
                            <th>IP</th>
                          </tr>
                        </thead>
                        <tbody>
                          {auditEntries.map((entry) => (
                            <tr key={entry.id}>
                              <td>{formatLocalTime(entry.timestamp)}</td>
                              <td>{entry.username}</td>
                              <td>{entry.entity_type} #{entry.entity_id}</td>
                              <td>{entry.action}</td>
                              <td style={{ maxWidth: '360px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.details}>{entry.details}</td>
                              <td>{entry.ip_address || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                        Page {auditPage} of {Math.max(1, Math.ceil(auditTotal / AUDIT_PAGE_SIZE))} — {auditTotal} total
                      </span>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button type="button" className="action-btn-inspect" disabled={auditPage <= 1} onClick={() => fetchAuditLog(auditPage - 1)}>Previous</button>
                        <button type="button" className="action-btn-inspect" disabled={auditPage * AUDIT_PAGE_SIZE >= auditTotal} onClick={() => fetchAuditLog(auditPage + 1)}>Next</button>
                      </div>
                    </div>
                  </>
                )}
              </motion.div>
            )}

            {activeSettingTab === 'backups' && (
              <motion.div key="backups" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.2 }}>
                <div className="settings-section-title">
                  <Archive size={20} color="var(--accent-color)" />
                  Backups
                </div>
                <div className="settings-section-subtitle">
                  Full-system snapshots — nginx configuration and every control-plane database.
                  Restoring always takes a fresh safety snapshot first, and a restored nginx
                  configuration is validated before it can go live (rolled back automatically if
                  it fails). Not included: <code>.env</code> and other host-level secrets — safeguard
                  those separately.
                </div>

                <Button variant="primary" size="md" icon={Archive} onClick={handleCreateBackup} disabled={creatingBackup} style={{ marginBottom: '16px' }}>
                  {creatingBackup ? 'Creating…' : 'Create Backup Now'}
                </Button>

                {backupsLoading ? (
                  <div style={{ padding: '24px', color: 'var(--text-secondary)' }}>Loading...</div>
                ) : backups.length === 0 ? (
                  <div style={{ padding: '24px', color: 'var(--text-secondary)' }}>No backups yet.</div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Created</th>
                          <th>Size</th>
                          <th>Triggered By</th>
                          <th>Type</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {backups.map((backup) => (
                          <tr key={backup.id}>
                            <td>{formatLocalTime(backup.created_at)}</td>
                            <td>{formatBackupSize(backup.size_bytes)}</td>
                            <td>{backup.triggered_by}</td>
                            <td>{TRIGGER_TYPE_LABELS[backup.trigger_type] || backup.trigger_type}</td>
                            <td>
                              <div style={{ display: 'flex', gap: '8px' }}>
                                <button type="button" className="action-btn-inspect" title="Download" onClick={() => handleDownloadBackup(backup)}>
                                  <Download size={14} />
                                </button>
                                <button
                                  type="button" className="action-btn-inspect" title="Restore"
                                  disabled={backupActionId === backup.id}
                                  onClick={() => handleRestoreBackup(backup)}
                                >
                                  <RotateCcw size={14} />
                                </button>
                                <button
                                  type="button" className="action-btn-inspect" title="Delete"
                                  disabled={backupActionId === backup.id}
                                  onClick={() => handleDeleteBackup(backup)}
                                >
                                  <Trash2 size={14} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
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
