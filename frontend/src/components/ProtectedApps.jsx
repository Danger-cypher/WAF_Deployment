import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Plus, Trash2, Edit2, Server, Globe, Power, Shield, Activity, ArrowRight, Lock, ChevronDown, ChevronUp, Zap, Network, Key, CheckCircle2, X, FileJson } from 'lucide-react';
import { getProtectedApps, deleteProtectedApp, toggleProtectedApp, getDdosBotSettings, saveDdosBotSettings, getAppSchema, saveAppSchema } from '../services/api';
import { useToast } from '../hooks/useToast';
import Toast from './Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import Button from './Button';

// Deterministic rule id per app — re-saving/editing an app's login
// protection updates the SAME advanced_rule instead of creating a
// duplicate, and lets the "already protected" badge look it up directly
// without guessing at the configured path.
const loginRuleId = (appId) => `login_protect_app_${appId}`;

const PREREQUISITES = [
  {
    icon: Zap,
    color: 'var(--warning-color)',
    bg: 'rgba(245, 158, 11, 0.1)',
    border: 'rgba(245, 158, 11, 0.2)',
    step: '01',
    title: 'Application Must Be Running',
    desc: 'Your backend application must already be online and accessible from this server. The WAF acts as a reverse proxy — it forwards traffic to your app. If your app is offline, users will receive a 502 Gateway Error.',
    tip: 'Test with: curl http://<your-backend-host>:<port>',
  },
  {
    icon: Network,
    color: 'var(--cyan-color)',
    bg: 'rgba(0, 212, 255, 0.1)',
    border: 'rgba(0, 212, 255, 0.2)',
    step: '02',
    title: 'Know Your Backend Host & Port',
    desc: 'You need the internal IP address (e.g. 192.168.1.50) or Docker container hostname (e.g. my-app) of your backend, plus the port it listens on (e.g. 8080, 3000, 5000).',
    tip: 'Example: Host = 192.168.1.50, Port = 8080',
  },
  {
    icon: Globe,
    color: 'var(--ml-color)',
    bg: 'var(--ml-bg)',
    border: 'var(--ml-bg)',
    step: '03',
    title: 'Point Your DNS to This WAF Server',
    desc: 'In your domain registrar (e.g. GoDaddy, Cloudflare DNS, Route53), create an A Record pointing your domain to this WAF server\'s public IP address — NOT directly to your backend. This forces all traffic through the WAF.',
    tip: `WAF Server IP: ${window.location.hostname}`,
  },
  {
    icon: Lock,
    color: 'var(--success-color)',
    bg: 'var(--success-bg)',
    border: 'var(--success-glow)',
    step: '04',
    title: 'Decide on SSL/TLS',
    desc: 'Choose how HTTPS will be handled. Use "Self-Signed" for internal/test environments, or upload your own certificate for production. The WAF terminates SSL at its edge and proxies plain HTTP to your backend internally.',
    tip: 'Recommended: Use your own cert for public-facing apps',
  },
  {
    icon: Key,
    color: 'var(--danger-color)',
    bg: 'var(--danger-bg)',
    border: 'var(--danger-border)',
    step: '05',
    title: 'Unique Domain Per Application',
    desc: 'Each application you register must use a unique domain name. The WAF uses the domain (Host header) to route traffic to the correct backend. Two apps cannot share the same domain.',
    tip: 'e.g. app1.example.com → Backend A, app2.example.com → Backend B',
  },
];

function PrerequisitesPanel() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div style={{
      background: 'rgba(0, 212, 255, 0.03)',
      borderRadius: '14px',
      border: '1px solid rgba(0, 212, 255, 0.15)',
      marginBottom: '24px',
      overflow: 'hidden',
    }}>
      {/* Header — always visible */}
      <button
        onClick={() => setIsOpen(v => !v)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 24px',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--text-primary)',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '34px', height: '34px', borderRadius: '8px',
            background: 'rgba(0, 212, 255, 0.12)', border: '1px solid rgba(0, 212, 255, 0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <CheckCircle2 size={18} style={{ color: 'var(--cyan-color)' }} />
          </div>
          <div style={{ textAlign: 'left' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Before You Start — Prerequisites Checklist
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              5 things to prepare before configuring WAF protection for any application
            </div>
          </div>
        </div>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          color: 'rgba(0, 212, 255, 0.8)', fontSize: '13px', fontWeight: 500, flexShrink: 0,
        }}>
          {isOpen ? 'Hide' : 'Show Guide'}
          {isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </button>

      {/* Collapsible body */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            key="prereq-body"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{
              padding: '0 24px 24px',
              borderTop: '1px solid rgba(0, 212, 255, 0.1)',
            }}>
              <p style={{ margin: '16px 0 20px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                Complete this checklist before clicking <strong style={{ color: 'var(--text-primary)' }}>Add Application</strong>. 
                The WAF will handle everything automatically once these requirements are in place.
              </p>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
                gap: '14px',
              }}>
                {PREREQUISITES.map((item) => {
                  const Icon = item.icon;
                  return (
                    <div
                      key={item.step}
                      style={{
                        background: item.bg,
                        border: `1px solid ${item.border}`,
                        borderRadius: '12px',
                        padding: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px',
                        transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 8px 24px ${item.border}`; }}
                      onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
                    >
                      {/* Step header */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{
                          width: '36px', height: '36px', borderRadius: '9px',
                          background: 'var(--inset-bg)', border: `1px solid ${item.border}`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          <Icon size={18} style={{ color: item.color }} />
                        </div>
                        <div>
                          <div style={{ fontSize: '10px', fontWeight: 700, color: item.color, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                            Step {item.step}
                          </div>
                          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
                            {item.title}
                          </div>
                        </div>
                      </div>

                      {/* Description */}
                      <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                        {item.desc}
                      </p>

                      {/* Tip pill */}
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: '6px',
                        background: 'var(--inset-bg)', borderRadius: '6px', padding: '7px 10px',
                        fontSize: '12px', color: item.color, fontFamily: 'monospace',
                        borderLeft: `3px solid ${item.color}`,
                      }}>
                        <Zap size={11} style={{ color: item.color, flexShrink: 0 }} />
                        {item.tip}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Flow summary */}
              <div style={{
                marginTop: '20px', padding: '14px 18px',
                background: 'var(--inset-bg)', borderRadius: '10px',
                border: '1px solid var(--border-color)',
                display: 'flex', alignItems: 'center', gap: '8px',
                fontSize: '13px', color: 'var(--text-secondary)', flexWrap: 'wrap',
              }}>
                <Shield size={14} style={{ color: 'var(--cyan-color)', flexShrink: 0 }} />
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Traffic Flow:</span>
                {['Internet', 'WAF (Port 80/443)', 'CyberSentinel Engine + ML Check', 'Your Backend App'].map((step, i, arr) => (
                  <span key={step} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: i === 0 ? 'var(--text-secondary)' : i === arr.length - 1 ? 'var(--success-color)' : 'var(--cyan-color)', fontWeight: i === arr.length - 1 ? 600 : 400 }}>{step}</span>
                    {i < arr.length - 1 && <ArrowRight size={12} style={{ color: 'var(--text-muted)' }} />}
                  </span>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}



export default function ProtectedApps({ onOpenWizard }) {
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [togglingId, setTogglingId] = useState(null);
  const { toast, showToast } = useToast();
  const confirm = useConfirm();

  // Login/brute-force protection — reuses the DDoS & Bot Shield advanced
  // rate-limiting engine (same backend, same nginx_manager.py apply path)
  // via a new "Host+URI" rule type scoped to $host$request_uri instead of
  // $request_uri alone, so identical login paths on different apps don't
  // share one rate-limit bucket.
  const [ddosSettings, setDdosSettings] = useState(null);
  const [loginProtectTarget, setLoginProtectTarget] = useState(null);
  useEscapeToClose(() => setLoginProtectTarget(null), !!loginProtectTarget);
  const [loginPath, setLoginPath] = useState('/login');
  const [loginAttemptsPerMin, setLoginAttemptsPerMin] = useState(5);
  const [loginBurst, setLoginBurst] = useState(3);
  const [savingLoginRule, setSavingLoginRule] = useState(false);

  // Positive-security API schema — declared known-good endpoints per app,
  // enforced (or just logged) in ml_check.lua's schema_validate module.
  // Raw-JSON editing for the endpoint list is a deliberately minimal v1 UI
  // (routes/apps.py's PUT /apps/{id}/schema does the real validation).
  const [apiSchemaTarget, setApiSchemaTarget] = useState(null);
  useEscapeToClose(() => setApiSchemaTarget(null), !!apiSchemaTarget);
  const [apiSchemaMode, setApiSchemaMode] = useState('log');
  const [apiSchemaEndpointsText, setApiSchemaEndpointsText] = useState('[]');
  const [apiSchemaJsonError, setApiSchemaJsonError] = useState('');
  const [savingApiSchema, setSavingApiSchema] = useState(false);
  const [loadingApiSchema, setLoadingApiSchema] = useState(false);

  const fetchApps = async () => {
    setLoading(true);
    try {
      const [data, ddos] = await Promise.all([getProtectedApps(), getDdosBotSettings()]);
      setApps(data || []);
      setDdosSettings(ddos || null);
    } catch (err) {
      console.error("Failed to load protected apps", err);
      showToast("Failed to fetch applications list.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const getLoginRule = (app) =>
    (ddosSettings?.advanced_rules || []).find((r) => r.id === loginRuleId(app.id));

  const openLoginProtectModal = (app) => {
    const existing = getLoginRule(app);
    setLoginProtectTarget(app);
    if (existing) {
      const [, ...pathParts] = existing.parameter_value.split('/');
      setLoginPath('/' + pathParts.join('/'));
      setLoginAttemptsPerMin(existing.rate_limit_rps);
      setLoginBurst(existing.burst_tolerance);
    } else {
      setLoginPath('/login');
      setLoginAttemptsPerMin(5);
      setLoginBurst(3);
    }
  };

  const closeLoginProtectModal = () => setLoginProtectTarget(null);

  const handleSaveLoginProtection = async (e) => {
    e.preventDefault();
    const app = loginProtectTarget;
    const path = loginPath.trim();
    if (!path.startsWith('/')) {
      showToast("Login path must start with '/'.", "error");
      return;
    }
    setSavingLoginRule(true);
    try {
      const current = await getDdosBotSettings();
      const existingRules = current.advanced_rules || [];
      const ruleId = loginRuleId(app.id);
      const newRule = {
        id: ruleId,
        name: `Login Protection — ${app.name}`,
        parameter_type: 'Host+URI',
        parameter_value: `${app.domain}${path}`,
        rate_limit_rps: loginAttemptsPerMin,
        rate_limit_unit: 'r/m',
        burst_tolerance: loginBurst,
        enabled: true,
      };
      const updated = {
        ...current,
        advanced_rules: [...existingRules.filter((r) => r.id !== ruleId), newRule],
      };
      await saveDdosBotSettings(updated);
      setDdosSettings(updated);
      showToast(`Login protection applied for ${app.name}.`);
      closeLoginProtectModal();
    } catch (err) {
      showToast("Failed to apply login protection: " + (err.message || "Unknown error"), "error");
    } finally {
      setSavingLoginRule(false);
    }
  };

  const handleRemoveLoginProtection = async (app) => {
    if (!(await confirm({
      title: 'Remove login protection',
      message: `Remove the login/brute-force rate limit for ${app.name}?`,
      confirmLabel: 'Remove',
      danger: true,
    }))) {
      return;
    }
    setSavingLoginRule(true);
    try {
      const current = await getDdosBotSettings();
      const ruleId = loginRuleId(app.id);
      const updated = {
        ...current,
        advanced_rules: (current.advanced_rules || []).filter((r) => r.id !== ruleId),
      };
      await saveDdosBotSettings(updated);
      setDdosSettings(updated);
      showToast(`Login protection removed for ${app.name}.`);
      closeLoginProtectModal();
    } catch (err) {
      showToast("Failed to remove login protection: " + (err.message || "Unknown error"), "error");
    } finally {
      setSavingLoginRule(false);
    }
  };

  const openApiSchemaModal = async (app) => {
    setApiSchemaTarget(app);
    setApiSchemaJsonError('');
    setLoadingApiSchema(true);
    try {
      const current = await getAppSchema(app.id);
      setApiSchemaMode(current?.mode || 'log');
      setApiSchemaEndpointsText(JSON.stringify(current?.endpoints || [], null, 2));
    } catch (err) {
      showToast("Failed to load API schema: " + (err.message || "Unknown error"), "error");
      setApiSchemaMode('log');
      setApiSchemaEndpointsText('[]');
    } finally {
      setLoadingApiSchema(false);
    }
  };

  const closeApiSchemaModal = () => setApiSchemaTarget(null);

  const handleSaveApiSchema = async (e) => {
    e.preventDefault();
    let endpoints;
    try {
      endpoints = JSON.parse(apiSchemaEndpointsText);
      if (!Array.isArray(endpoints)) throw new Error('Endpoints must be a JSON array.');
    } catch (err) {
      setApiSchemaJsonError(err.message || 'Invalid JSON.');
      return;
    }
    setApiSchemaJsonError('');
    setSavingApiSchema(true);
    try {
      await saveAppSchema(apiSchemaTarget.id, { mode: apiSchemaMode, endpoints });
      showToast(`API schema saved for ${apiSchemaTarget.name}.`);
      closeApiSchemaModal();
    } catch (err) {
      showToast("Failed to save API schema: " + (err.message || "Unknown error"), "error");
    } finally {
      setSavingApiSchema(false);
    }
  };

  const handleDeleteApp = async (appId) => {
    if (!(await confirm({
      title: 'Remove protected application',
      message: 'Are you sure you want to remove this protected application? Nginx configuration will be updated and reloaded.',
      confirmLabel: 'Remove',
      danger: true,
    }))) {
      return;
    }
    setActionLoading(true);
    try {
      await deleteProtectedApp(appId);
      showToast("Application deleted successfully.");
      fetchApps();
    } catch (err) {
      showToast("Error deleting application: " + (err.message || "Failed"), "error");
    } finally {
      setActionLoading(false);
    }
  };

  const handleToggleActive = async (app) => {
    setTogglingId(app.id);
    setActionLoading(true);
    try {
      await toggleProtectedApp(app.id);
      showToast(`Application successfully ${app.is_active ? 'disabled' : 'enabled'}.`);
      fetchApps();
    } catch (err) {
      showToast("Error toggling application status: " + (err.message || "Failed"), "error");
    } finally {
      setActionLoading(false);
      setTogglingId(null);
    }
  };

  return (
    <div className="protected-apps-tab" style={{ padding: '24px' }}>
      <div className="dashboard-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h2 style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: 0, fontSize: '24px', fontWeight: 700 }}>
          <Server size={24} style={{ color: 'var(--accent-color)' }} />
          <span>Protected Applications</span>
        </h2>
        <button
          onClick={() => onOpenWizard()}
          disabled={actionLoading}
          style={{
            padding: '10px 20px',
            background: 'var(--accent-color)',
            border: 'none',
            borderRadius: '8px',
            color: '#000',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: '0 4px 14px rgba(0, 212, 255, 0.3)',
            transition: 'all 0.2s ease',
          }}
        >
          <Plus size={18} />
          Add Application
        </button>
      </div>

      {/* Prerequisites Panel */}
      <PrerequisitesPanel />

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-secondary)' }}>
          <Activity className="animate-spin" size={32} style={{ margin: '0 auto 16px', color: 'var(--accent-color)' }} />
          <span>Fetching configuration status...</span>
        </div>
      ) : apps.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: '80px 40px',
          background: 'var(--inset-bg)',
          borderRadius: '16px',
          border: '1px dashed var(--border-strong)'
        }}>
          <Server size={48} style={{ color: 'var(--border-strong)', marginBottom: '16px' }} />
          <h3 style={{ margin: '0 0 8px', fontSize: '18px', color: 'var(--text-primary)' }}>No Applications Configured</h3>
          <p style={{ margin: '0 0 24px', color: 'var(--text-secondary)', fontSize: '14px' }}>Get started by adding your first protected service.</p>
          <button
            onClick={() => onOpenWizard()}
            style={{
              padding: '10px 20px',
              background: 'rgba(0, 212, 255, 0.15)',
              border: '1px solid var(--accent-color)',
              borderRadius: '8px',
              color: 'var(--accent-color)',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Create New Virtual Host
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '20px' }}>
          {apps.map((app) => (
            <motion.div
              key={app.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              style={{
                background: app.is_active ? 'var(--inset-bg)' : 'var(--surface-subtle)',
                border: app.is_active ? '1px solid var(--surface-strong)' : '1px solid var(--surface-subtle)',
                borderRadius: '12px',
                padding: '20px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'all 0.3s ease',
                position: 'relative'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: app.is_active ? '#fff' : 'var(--text-secondary)' }}>
                    {app.name}
                  </h3>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    background: app.is_active ? 'rgba(0, 212, 255, 0.1)' : 'var(--surface-hover)',
                    color: app.is_active ? 'var(--accent-color)' : 'var(--text-secondary)',
                    border: app.is_active ? '1px solid rgba(0, 212, 255, 0.2)' : '1px solid var(--surface-hover)'
                  }}>
                    {app.is_active ? 'Active' : 'Disabled'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Globe size={14} style={{ color: 'var(--text-muted)' }} />
                    <span style={{ color: 'var(--text-secondary)' }}>Domain:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: app.is_active ? 'var(--accent-color)' : 'var(--text-secondary)' }}>
                      {app.domain}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Server size={14} style={{ color: 'var(--text-muted)' }} />
                    <span style={{ color: 'var(--text-secondary)' }}>Upstream:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: app.is_active ? '#fff' : 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      {app.protocol}://{app.upstream_host}:{app.upstream_port}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={14} style={{ color: 'var(--text-muted)' }} />
                    <span style={{ color: 'var(--text-secondary)' }}>Rate Limit:</span>
                    <span style={{ color: app.is_active ? '#fff' : 'var(--text-secondary)' }}>
                      {app.rate_limit_rps} RPS (Burst: {app.burst_tolerance})
                    </span>
                  </div>
                </div>
              </div>

              <div style={{
                display: 'flex',
                gap: '10px',
                borderTop: '1px solid var(--surface-hover)',
                paddingTop: '16px',
                justifyContent: 'flex-end'
              }}>
                <button
                  onClick={() => handleToggleActive(app)}
                  disabled={actionLoading}
                  title={app.is_active ? "Disable Application" : "Enable Application"}
                  style={{
                    padding: '8px',
                    borderRadius: '6px',
                    border: '1px solid var(--surface-hover)',
                    background: app.is_active ? 'rgba(255, 59, 92, 0.1)' : 'rgba(0, 212, 255, 0.1)',
                    color: app.is_active ? 'var(--danger-color)' : 'var(--accent-color)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '32px',
                    height: '32px'
                  }}
                >
                  {togglingId === app.id ? (
                    <Activity size={14} className="animate-spin" style={{ color: 'var(--accent-color)' }} />
                  ) : (
                    <Power size={14} />
                  )}
                </button>
                <button
                  onClick={() => openLoginProtectModal(app)}
                  disabled={actionLoading || app.domain === '_'}
                  title={app.domain === '_' ? "Login protection needs a specific domain — not available for the wildcard/catch-all app." : undefined}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: getLoginRule(app) ? '1px solid var(--success-glow)' : '1px solid var(--surface-hover)',
                    background: getLoginRule(app) ? 'var(--success-bg)' : 'var(--surface-subtle)',
                    color: getLoginRule(app) ? 'var(--success-color)' : 'var(--text-primary)',
                    cursor: app.domain === '_' ? 'not-allowed' : 'pointer',
                    opacity: app.domain === '_' ? 0.5 : 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px'
                  }}
                >
                  <Key size={12} />
                  {getLoginRule(app) ? 'Login Protected' : 'Protect Login'}
                </button>
                <button
                  onClick={() => openApiSchemaModal(app)}
                  disabled={actionLoading}
                  title="Positive-security: declare known-good endpoints for this app"
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--surface-hover)',
                    background: 'var(--surface-subtle)',
                    color: 'var(--text-primary)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px'
                  }}
                >
                  <FileJson size={12} />
                  API Schema
                </button>
                <button
                  onClick={() => onOpenWizard(app)}
                  disabled={actionLoading}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--surface-hover)',
                    background: 'var(--surface-subtle)',
                    color: 'var(--text-primary)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px'
                  }}
                >
                  <Edit2 size={12} />
                  Edit
                </button>
                <button
                  onClick={() => handleDeleteApp(app.id)}
                  disabled={actionLoading}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,59,92,0.15)',
                    background: 'rgba(255,59,92,0.05)',
                    color: 'var(--danger-color)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px'
                  }}
                >
                  <Trash2 size={12} />
                  Delete
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Floating success/error Toast notification */}
      <Toast toast={toast} />

      {loginProtectTarget && createPortal(
        <div
          style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'var(--overlay-bg)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}
          onClick={closeLoginProtectModal}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: 'rgba(20, 20, 20, 0.97)', border: '1px solid var(--border-strong)', borderRadius: '16px', padding: '28px', width: '100%', maxWidth: '480px', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)' }}>Login / Brute-Force Protection</h3>
                <div style={{ marginTop: '4px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                  {loginProtectTarget.domain}
                </div>
              </div>
              <Button variant="ghost" size="md" icon={X} onClick={closeLoginProtectModal} aria-label="Close" />
            </div>

            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: 0, marginBottom: '18px', lineHeight: 1.5 }}>
              Rate-limits this one path, on this one app's domain only, per client IP —
              uses the same engine as DDoS &amp; Bot Shield's Advanced Rate Limiting Rules
              (visible there as "{loginProtectTarget.name ? `Login Protection — ${loginProtectTarget.name}` : ''}"),
              scoped so an identical path on a different protected app is never affected.
            </p>

            <form onSubmit={handleSaveLoginProtection} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label htmlFor="pa-login-path" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Login Path</label>
                <input
                  id="pa-login-path"
                  type="text"
                  className="search-input"
                  style={{ fontFamily: 'monospace' }}
                  value={loginPath}
                  onChange={(e) => setLoginPath(e.target.value)}
                  placeholder="/login"
                />
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  The exact path your app's login form posts to (e.g. /login, /wp-login.php, /admin/login).
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label htmlFor="pa-login-attempts" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Max Attempts</label>
                    <span style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 600 }}>{loginAttemptsPerMin} / min</span>
                  </div>
                  <input
                    id="pa-login-attempts"
                    type="range" min="1" max="60"
                    value={loginAttemptsPerMin} onChange={(e) => setLoginAttemptsPerMin(parseInt(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent-color)' }}
                  />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label htmlFor="pa-login-burst" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Burst Tolerance</label>
                    <span style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 600 }}>{loginBurst} reqs</span>
                  </div>
                  <input
                    id="pa-login-burst"
                    type="range" min="0" max="20"
                    value={loginBurst} onChange={(e) => setLoginBurst(parseInt(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent-color)' }}
                  />
                </div>
              </div>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '-8px' }}>
                Default (5/min) allows a real user a few mistyped-password retries while stopping
                automated guessing — tighten for higher-value accounts.
              </span>

              <div style={{ display: 'flex', gap: '12px', justifyContent: getLoginRule(loginProtectTarget) ? 'space-between' : 'flex-end', marginTop: '4px' }}>
                {getLoginRule(loginProtectTarget) && (
                  <button
                    type="button"
                    onClick={() => handleRemoveLoginProtection(loginProtectTarget)}
                    disabled={savingLoginRule}
                    className="action-btn-inspect"
                    style={{ background: 'var(--danger-bg)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)' }}
                  >
                    Remove Protection
                  </button>
                )}
                <div style={{ display: 'flex', gap: '12px' }}>
                  <Button type="button" variant="secondary" onClick={closeLoginProtectModal}>
                    Cancel
                  </Button>
                  <button type="submit" disabled={savingLoginRule} className="modal-btn primary" style={{ margin: 0 }}>
                    {savingLoginRule ? 'Applying to NGINX...' : 'Apply Protection'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {apiSchemaTarget && createPortal(
        <div
          style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'var(--overlay-bg)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}
          onClick={closeApiSchemaModal}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: 'rgba(20, 20, 20, 0.97)', border: '1px solid var(--border-strong)', borderRadius: '16px', padding: '28px', width: '100%', maxWidth: '560px', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)' }}>API Schema (Positive Security)</h3>
                <div style={{ marginTop: '4px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                  {apiSchemaTarget.domain}
                </div>
              </div>
              <Button variant="ghost" size="md" icon={X} onClick={closeApiSchemaModal} aria-label="Close" />
            </div>

            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: 0, marginBottom: '18px', lineHeight: 1.5 }}>
              Declares known-good endpoints for this app — only requests matching a listed
              method + path are checked; everything else passes through untouched. JSON body
              requests to a listed endpoint are rejected if a required field is missing, or
              (when <code>allowed_fields</code> is set) if an unexpected field is present.
              Optionally, <code>field_types</code> constrains a field beyond presence — type
              (<code>string</code> / <code>number</code> / <code>boolean</code> / <code>enum</code>),
              plus <code>max_length</code> and/or a regex <code>pattern</code> for strings, or an{' '}
              <code>enum</code> list of allowed values.
              "Log" records violations without blocking; "Enforce" rejects them with a 400.
            </p>

            {loadingApiSchema ? (
              <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>Loading...</div>
            ) : (
              <form onSubmit={handleSaveApiSchema} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label htmlFor="pa-api-schema-mode" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Mode</label>
                  <select
                    id="pa-api-schema-mode"
                    className="settings-input"
                    style={{ width: '100%', fontSize: '14px' }}
                    value={apiSchemaMode}
                    onChange={(e) => setApiSchemaMode(e.target.value)}
                  >
                    <option value="log">Log only (record violations, never block)</option>
                    <option value="enforce">Enforce (reject violations with 400)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label htmlFor="pa-api-schema-endpoints" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Endpoints (JSON array)</label>
                  <textarea
                    id="pa-api-schema-endpoints"
                    className="settings-input"
                    style={{ width: '100%', minHeight: '180px', resize: 'vertical', fontFamily: 'monospace', fontSize: '12px' }}
                    value={apiSchemaEndpointsText}
                    onChange={(e) => setApiSchemaEndpointsText(e.target.value)}
                    placeholder={'[\n  {\n    "method": "POST",\n    "path": "/api/users",\n    "required_fields": ["name", "email"],\n    "allowed_fields": ["name", "email", "role"],\n    "field_types": {\n      "email": {"type": "string", "max_length": 254, "pattern": "^[^@]+@[^@]+$"},\n      "role": {"type": "enum", "enum": ["admin", "member"]}\n    }\n  }\n]'}
                  />
                  {apiSchemaJsonError && (
                    <span style={{ fontSize: '11px', color: 'var(--danger-color)' }}>{apiSchemaJsonError}</span>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '4px' }}>
                  <Button type="button" variant="secondary" onClick={closeApiSchemaModal}>
                    Cancel
                  </Button>
                  <button type="submit" disabled={savingApiSchema} className="modal-btn primary" style={{ margin: 0 }}>
                    {savingApiSchema ? 'Saving...' : 'Save Schema'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}
