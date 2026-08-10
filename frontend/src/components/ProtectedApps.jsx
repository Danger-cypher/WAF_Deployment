import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Plus, Trash2, Edit2, Server, Globe, Power, Check, X, Shield, Activity, ArrowRight, Lock, ChevronDown, ChevronUp, Zap, Network, Key, CheckCircle2 } from 'lucide-react';
import { getProtectedApps, createProtectedApp, updateProtectedApp, deleteProtectedApp, toggleProtectedApp } from '../services/api';

const PREREQUISITES = [
  {
    icon: Zap,
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.1)',
    border: 'rgba(245, 158, 11, 0.2)',
    step: '01',
    title: 'Application Must Be Running',
    desc: 'Your backend application must already be online and accessible from this server. The WAF acts as a reverse proxy — it forwards traffic to your app. If your app is offline, users will receive a 502 Gateway Error.',
    tip: 'Test with: curl http://<your-backend-host>:<port>',
  },
  {
    icon: Network,
    color: '#00d4ff',
    bg: 'rgba(0, 212, 255, 0.1)',
    border: 'rgba(0, 212, 255, 0.2)',
    step: '02',
    title: 'Know Your Backend Host & Port',
    desc: 'You need the internal IP address (e.g. 192.168.1.50) or Docker container hostname (e.g. my-app) of your backend, plus the port it listens on (e.g. 8080, 3000, 5000).',
    tip: 'Example: Host = 192.168.1.50, Port = 8080',
  },
  {
    icon: Globe,
    color: '#a78bfa',
    bg: 'rgba(167, 139, 250, 0.1)',
    border: 'rgba(167, 139, 250, 0.2)',
    step: '03',
    title: 'Point Your DNS to This WAF Server',
    desc: 'In your domain registrar (e.g. GoDaddy, Cloudflare DNS, Route53), create an A Record pointing your domain to this WAF server\'s public IP address — NOT directly to your backend. This forces all traffic through the WAF.',
    tip: `WAF Server IP: ${window.location.hostname}`,
  },
  {
    icon: Lock,
    color: '#34d399',
    bg: 'rgba(52, 211, 153, 0.1)',
    border: 'rgba(52, 211, 153, 0.2)',
    step: '04',
    title: 'Decide on SSL/TLS',
    desc: 'Choose how HTTPS will be handled. Use "Self-Signed" for internal/test environments, or upload your own certificate for production. The WAF terminates SSL at its edge and proxies plain HTTP to your backend internally.',
    tip: 'Recommended: Use your own cert for public-facing apps',
  },
  {
    icon: Key,
    color: '#f87171',
    bg: 'rgba(248, 113, 113, 0.1)',
    border: 'rgba(248, 113, 113, 0.2)',
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
          color: '#fff',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '34px', height: '34px', borderRadius: '8px',
            background: 'rgba(0, 212, 255, 0.12)', border: '1px solid rgba(0, 212, 255, 0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>
            <CheckCircle2 size={18} style={{ color: '#00d4ff' }} />
          </div>
          <div style={{ textAlign: 'left' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>
              Before You Start — Prerequisites Checklist
            </div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginTop: '2px' }}>
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
              <p style={{ margin: '16px 0 20px', fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
                Complete this checklist before clicking <strong style={{ color: '#fff' }}>Add Application</strong>. 
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
                          background: 'rgba(0,0,0,0.2)', border: `1px solid ${item.border}`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          <Icon size={18} style={{ color: item.color }} />
                        </div>
                        <div>
                          <div style={{ fontSize: '10px', fontWeight: 700, color: item.color, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                            Step {item.step}
                          </div>
                          <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff', lineHeight: 1.2 }}>
                            {item.title}
                          </div>
                        </div>
                      </div>

                      {/* Description */}
                      <p style={{ margin: 0, fontSize: '13px', color: 'rgba(255,255,255,0.65)', lineHeight: 1.6 }}>
                        {item.desc}
                      </p>

                      {/* Tip pill */}
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: '6px',
                        background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '7px 10px',
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
                background: 'rgba(0,0,0,0.2)', borderRadius: '10px',
                border: '1px solid rgba(255,255,255,0.06)',
                display: 'flex', alignItems: 'center', gap: '8px',
                fontSize: '13px', color: 'rgba(255,255,255,0.6)', flexWrap: 'wrap',
              }}>
                <Shield size={14} style={{ color: '#00d4ff', flexShrink: 0 }} />
                <span style={{ fontWeight: 600, color: '#fff' }}>Traffic Flow:</span>
                {['Internet', 'WAF (Port 80/443)', 'CyberSentinel Engine + ML Check', 'Your Backend App'].map((step, i, arr) => (
                  <span key={step} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: i === 0 ? 'rgba(255,255,255,0.6)' : i === arr.length - 1 ? '#34d399' : '#00d4ff', fontWeight: i === arr.length - 1 ? 600 : 400 }}>{step}</span>
                    {i < arr.length - 1 && <ArrowRight size={12} style={{ color: 'rgba(255,255,255,0.3)' }} />}
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
  const [toast, setToast] = useState(null);

  // Form modals state
  const [showModal, setShowModal] = useState(false);
  const [modalMode, setModalMode] = useState("create"); // "create" or "edit"
  const [selectedApp, setSelectedApp] = useState(null);

  // Form fields
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [upstreamHost, setUpstreamHost] = useState("");
  const [upstreamPort, setUpstreamPort] = useState(80);
  const [protocol, setProtocol] = useState("http");
  const [isActive, setIsActive] = useState(1);
  const [rateLimitRps, setRateLimitRps] = useState(50);
  const [burstTolerance, setBurstTolerance] = useState(100);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const fetchApps = async () => {
    setLoading(true);
    try {
      const data = await getProtectedApps();
      setApps(data || []);
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

  const handleOpenCreateModal = () => {
    setModalMode("create");
    setSelectedApp(null);
    setName("");
    setDomain("");
    setUpstreamHost("");
    setUpstreamPort(80);
    setProtocol("http");
    setIsActive(1);
    setRateLimitRps(50);
    setBurstTolerance(100);
    setShowModal(true);
  };

  const handleOpenEditModal = (app) => {
    setModalMode("edit");
    setSelectedApp(app);
    setName(app.name);
    setDomain(app.domain);
    setUpstreamHost(app.upstream_host);
    setUpstreamPort(app.upstream_port);
    setProtocol(app.protocol);
    setIsActive(app.is_active);
    setRateLimitRps(app.rate_limit_rps || 50);
    setBurstTolerance(app.burst_tolerance || 100);
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name || !domain || !upstreamHost || !upstreamPort) {
      showToast("All fields are required.", "error");
      return;
    }

    setActionLoading(true);
    const appData = {
      name: name.trim(),
      domain: domain.trim().toLowerCase(),
      upstream_host: upstreamHost.trim(),
      upstream_port: parseInt(upstreamPort),
      protocol: protocol.toLowerCase(),
      is_active: parseInt(isActive),
      rate_limit_rps: parseInt(rateLimitRps),
      burst_tolerance: parseInt(burstTolerance)
    };

    try {
      if (modalMode === "create") {
        await createProtectedApp(appData);
        showToast("Protected application added successfully!");
      } else {
        await updateProtectedApp(selectedApp.id, appData);
        showToast("Protected application updated successfully!");
      }
      setShowModal(false);
      fetchApps();
    } catch (err) {
      showToast("Error saving application: " + (err.message || "Configuration invalid"), "error");
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteApp = async (appId) => {
    if (!window.confirm("Are you sure you want to remove this protected application? Nginx configuration will be updated and reloaded.")) {
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
          onClick={() => onOpenWizard ? onOpenWizard() : handleOpenCreateModal()}
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
        <div style={{ textAlign: 'center', padding: '60px', color: 'rgba(255,255,255,0.5)' }}>
          <Activity className="animate-spin" size={32} style={{ margin: '0 auto 16px', color: 'var(--accent-color)' }} />
          <span>Fetching configuration status...</span>
        </div>
      ) : apps.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: '80px 40px',
          background: 'rgba(0,0,0,0.15)',
          borderRadius: '16px',
          border: '1px dashed rgba(255,255,255,0.1)'
        }}>
          <Server size={48} style={{ color: 'rgba(255,255,255,0.2)', marginBottom: '16px' }} />
          <h3 style={{ margin: '0 0 8px', fontSize: '18px', color: '#fff' }}>No Applications Configured</h3>
          <p style={{ margin: '0 0 24px', color: 'rgba(255,255,255,0.5)', fontSize: '14px' }}>Get started by adding your first protected service.</p>
          <button
            onClick={() => onOpenWizard ? onOpenWizard() : handleOpenCreateModal()}
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
                background: app.is_active ? 'rgba(0,0,0,0.2)' : 'rgba(255,255,255,0.01)',
                border: app.is_active ? '1px solid rgba(255,255,255,0.08)' : '1px solid rgba(255,255,255,0.03)',
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
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: app.is_active ? '#fff' : 'rgba(255,255,255,0.4)' }}>
                    {app.name}
                  </h3>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    background: app.is_active ? 'rgba(0, 212, 255, 0.1)' : 'rgba(255,255,255,0.05)',
                    color: app.is_active ? 'var(--accent-color)' : 'rgba(255,255,255,0.4)',
                    border: app.is_active ? '1px solid rgba(0, 212, 255, 0.2)' : '1px solid rgba(255,255,255,0.05)'
                  }}>
                    {app.is_active ? 'Active' : 'Disabled'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Globe size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />
                    <span style={{ color: 'rgba(255,255,255,0.6)' }}>Domain:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: app.is_active ? 'var(--accent-color)' : 'rgba(255,255,255,0.4)' }}>
                      {app.domain}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Server size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />
                    <span style={{ color: 'rgba(255,255,255,0.6)' }}>Upstream:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: app.is_active ? '#fff' : 'rgba(255,255,255,0.4)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      {app.protocol}://{app.upstream_host}:{app.upstream_port}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />
                    <span style={{ color: 'rgba(255,255,255,0.6)' }}>Rate Limit:</span>
                    <span style={{ color: app.is_active ? '#fff' : 'rgba(255,255,255,0.4)' }}>
                      {app.rate_limit_rps} RPS (Burst: {app.burst_tolerance})
                    </span>
                  </div>
                </div>
              </div>

              <div style={{
                display: 'flex',
                gap: '10px',
                borderTop: '1px solid rgba(255,255,255,0.05)',
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
                    border: '1px solid rgba(255,255,255,0.05)',
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
                  onClick={() => onOpenWizard ? onOpenWizard(app) : handleOpenEditModal(app)}
                  disabled={actionLoading}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,255,255,0.05)',
                    background: 'rgba(255,255,255,0.03)',
                    color: '#fff',
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

      {/* Slide-over or Modal Overlay */}
      <AnimatePresence>
        {showModal && (
          <div style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.6)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999
          }}>
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              style={{
                background: 'rgba(20, 20, 20, 0.95)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '16px',
                padding: '30px',
                width: '100%',
                maxWidth: '480px',
                boxShadow: '0 10px 30px rgba(0,0,0,0.5)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                <h3 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: '#fff' }}>
                  {modalMode === "create" ? "Add Protected Application" : "Edit Application Configuration"}
                </h3>
                <button
                  onClick={() => setShowModal(false)}
                  style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.5)', cursor: 'pointer' }}
                >
                  <X size={20} />
                </button>
              </div>

              <form onSubmit={handleSubmit}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                      Application Name
                    </label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Production API Portal"
                      required
                      style={{
                        width: '100%',
                        padding: '10px 14px',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                        color: '#fff',
                        fontSize: '14px'
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                      Domain Name (server_name)
                    </label>
                    <input
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="e.g. api.company.com or '_'"
                      required
                      style={{
                        width: '100%',
                        padding: '10px 14px',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                        color: '#fff',
                        fontSize: '14px',
                        fontFamily: 'var(--font-mono)'
                      }}
                    />
                    <small style={{ color: 'rgba(255,255,255,0.4)', fontSize: '11px', marginTop: '4px', display: 'block' }}>
                      Use <strong>_</strong> as domain to serve as the default server matching any hostname.
                    </small>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                        Protocol
                      </label>
                      <select
                        value={protocol}
                        onChange={(e) => setProtocol(e.target.value)}
                        style={{
                          width: '100%',
                          padding: '10px 14px',
                          background: 'rgba(0,0,0,0.3)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          color: '#fff',
                          fontSize: '14px'
                        }}
                      >
                        <option value="http">http</option>
                        <option value="https">https</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                        Upstream Port
                      </label>
                      <input
                        type="number"
                        value={upstreamPort}
                        onChange={(e) => setUpstreamPort(e.target.value)}
                        placeholder="7000"
                        min="1"
                        max="65535"
                        required
                        style={{
                          width: '100%',
                          padding: '10px 14px',
                          background: 'rgba(0,0,0,0.3)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          color: '#fff',
                          fontSize: '14px'
                        }}
                      />
                    </div>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                      Upstream Host IP / Container Name
                    </label>
                    <input
                      type="text"
                      value={upstreamHost}
                      onChange={(e) => setUpstreamHost(e.target.value)}
                      placeholder="e.g. host.docker.internal or 192.168.1.50"
                      required
                      style={{
                        width: '100%',
                        padding: '10px 14px',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                        color: '#fff',
                        fontSize: '14px',
                        fontFamily: 'var(--font-mono)'
                      }}
                    />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                        Rate Limit (RPS)
                      </label>
                      <input
                        type="number"
                        value={rateLimitRps}
                        onChange={(e) => setRateLimitRps(e.target.value)}
                        placeholder="50"
                        min="1"
                        max="10000"
                        required
                        style={{
                          width: '100%',
                          padding: '10px 14px',
                          background: 'rgba(0,0,0,0.3)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          color: '#fff',
                          fontSize: '14px'
                        }}
                      />
                    </div>

                    <div>
                      <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                        Burst Tolerance
                      </label>
                      <input
                        type="number"
                        value={burstTolerance}
                        onChange={(e) => setBurstTolerance(e.target.value)}
                        placeholder="100"
                        min="1"
                        max="20000"
                        required
                        style={{
                          width: '100%',
                          padding: '10px 14px',
                          background: 'rgba(0,0,0,0.3)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          color: '#fff',
                          fontSize: '14px'
                        }}
                      />
                    </div>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '6px', textTransform: 'uppercase' }}>
                      Activation Mode
                    </label>
                    <select
                      value={isActive}
                      onChange={(e) => setIsActive(parseInt(e.target.value))}
                      style={{
                        width: '100%',
                        padding: '10px 14px',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                        color: '#fff',
                        fontSize: '14px'
                      }}
                    >
                      <option value={1}>Enabled (Active Routing)</option>
                      <option value={0}>Disabled (No routing)</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    style={{
                      padding: '10px 20px',
                      background: 'transparent',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                      color: 'rgba(255,255,255,0.7)',
                      cursor: 'pointer'
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={actionLoading}
                    style={{
                      padding: '10px 20px',
                      background: 'var(--accent-color)',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#000',
                      fontWeight: 600,
                      cursor: 'pointer',
                      boxShadow: '0 4px 14px rgba(0, 212, 255, 0.2)'
                    }}
                  >
                    {actionLoading ? "Syncing..." : modalMode === "create" ? "Add App" : "Apply Changes"}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Floating success/error Toast notification */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            style={{
              position: 'fixed',
              bottom: '24px',
              right: '24px',
              padding: '12px 24px',
              background: toast.type === 'error' ? 'rgba(255, 59, 92, 0.95)' : 'rgba(0, 212, 255, 0.95)',
              border: toast.type === 'error' ? '1px solid #ff3b5c' : '1px solid #00d4ff',
              borderRadius: '8px',
              color: toast.type === 'error' ? '#fff' : '#000',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              zIndex: 99999,
              boxShadow: '0 10px 30px rgba(0,0,0,0.3)'
            }}
          >
            {toast.type === 'error' ? <X size={16} /> : <Check size={16} />}
            <span>{toast.message}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
