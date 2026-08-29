import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Activity, Lock, Database, Code, Server, AlertTriangle, RotateCw } from 'lucide-react';
import {
  getAlertChannels, createAlertChannel, updateAlertChannel, deleteAlertChannel,
  testAlertChannel, getAlertRules, createAlertRule, updateAlertRule, deleteAlertRule, getHealth,
  getAlertChannelsHealth,
} from '../services/api';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';

export default function AlertsIntegrations({ userRole }) {
  const [loading, setLoading] = useState(true);
  const [alertDataError, setAlertDataError] = useState('');
  const { toast, showToast } = useToast();
  const confirm = useConfirm();
  const [healthData, setHealthData] = useState(null);
  // Per-channel delivery health (attempts/successes/last outcome), keyed by
  // channel name — separate from healthData above, which is the unrelated
  // system-level /health (Redis/ClickHouse/DB).
  const [channelHealth, setChannelHealth] = useState({});
  const [activeSubTab, setActiveSubTab] = useState('connectors'); // 'connectors', 'channels', 'rules'

  // Alert Config State
  const [channels, setChannels] = useState([]);
  const [rules, setRules] = useState([]);
  const [isChannelCreateOpen, setIsChannelCreateOpen] = useState(false);
  const [isRuleCreateOpen, setIsRuleCreateOpen] = useState(false);
  // null = the open form is creating a new rule; a rule id = editing that
  // existing rule (PUT /alerts/rules/{id}, wired to the UI but previously
  // only reachable directly through the API, no button anywhere used it).
  const [editingRuleId, setEditingRuleId] = useState(null);
  const [channelForm, setChannelForm] = useState({ name: '', channel_type: 'slack', config: {} });
  const [ruleForm, setRuleForm] = useState({ name: '', event_type: 'attack_detected', severity: 'high', conditions: {}, channels: [], throttle_minutes: 5 });
  // Text-input mirrors of ruleForm.conditions/channels — the raw fields are
  // JSON/array values, but the inputs below are free-text, so they need
  // their own controlled string state to display correctly when editing an
  // existing rule (the inputs were previously uncontrolled, fine for
  // create-only where they always start blank, but that silently shows a
  // blank field instead of the real value when populating from an edit).
  const [conditionsText, setConditionsText] = useState('');
  const [channelsText, setChannelsText] = useState('');

  const isFetchingHealthRef = useRef(false);

  const fetchHealth = async () => {
    if (isFetchingHealthRef.current) return;
    isFetchingHealthRef.current = true;
    try {
      const data = await getHealth();
      setHealthData(data);
    } catch (err) {
      console.error("Health check failed", err);
    } finally {
      setLoading(false);
      isFetchingHealthRef.current = false;
    }
  };

  const loadAlertData = async () => {
    try {
      const chans = await getAlertChannels();
      setChannels(chans || []);
      const rls = await getAlertRules();
      setRules(rls || []);
      setAlertDataError('');
    } catch (err) {
      // Previously silent — a failed load left channels/rules at [], which
      // renders identically to "you haven't configured any alerting yet."
      // An admin has no way to tell those two states apart without this.
      console.error("Error loading alert configurations:", err);
      setAlertDataError(err.message || 'Could not reach the backend API.');
    }

    // Best-effort — a failed health fetch shouldn't block channels/rules
    // from loading, so it's kept out of the try/catch above (channel cards
    // just render without a health badge instead).
    try {
      const health = await getAlertChannelsHealth();
      setChannelHealth(Object.fromEntries((health || []).map(h => [h.channel_name, h])));
    } catch (err) {
      console.error("Failed to load channel delivery health:", err);
    }
  };

  useEffect(() => {
    fetchHealth();
    loadAlertData();
    const interval = setInterval(fetchHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleCreateChannel = async (e) => {
    e.preventDefault();
    try {
      if (channelForm.id) {
        await updateAlertChannel(channelForm.id, channelForm);
      } else {
        await createAlertChannel(channelForm);
      }
      setIsChannelCreateOpen(false);
      setChannelForm({ name: '', channel_type: 'slack', config: {} });
      loadAlertData();
    } catch (err) {
      showToast("Failed to save channel: " + err.message, "error");
    }
  };

  const handleDeleteChannel = async (id) => {
    if (!(await confirm({
      title: 'Delete notification channel',
      message: 'Are you sure you want to delete this notification channel?',
      confirmLabel: 'Delete',
      danger: true,
    }))) return;
    try {
      await deleteAlertChannel(id);
      loadAlertData();
    } catch (err) {
      showToast("Failed to delete channel: " + err.message, "error");
    }
  };

  const handleTestChannel = async (id) => {
    try {
      const res = await testAlertChannel(id, { test_message: "Test warning alert configured successfully." });
      if (res.success) {
        showToast("Test notification dispatched successfully.");
      } else {
        showToast("Dispatch failed: " + res.message, "error");
      }
    } catch (err) {
      showToast("Error: " + err.message, "error");
    }
  };

  const resetRuleForm = () => {
    setIsRuleCreateOpen(false);
    setEditingRuleId(null);
    setRuleForm({ name: '', event_type: 'attack_detected', severity: 'high', conditions: {}, channels: [], throttle_minutes: 5 });
    setConditionsText('');
    setChannelsText('');
  };

  const handleSubmitRule = async (e) => {
    e.preventDefault();
    try {
      if (editingRuleId != null) {
        await updateAlertRule(editingRuleId, ruleForm);
        showToast("Alert rule updated.");
      } else {
        await createAlertRule(ruleForm);
      }
      resetRuleForm();
      loadAlertData();
    } catch (err) {
      showToast(`Failed to ${editingRuleId != null ? 'update' : 'create'} rule: ` + err.message, "error");
    }
  };

  const handleEditRuleClick = (rule) => {
    setEditingRuleId(rule.id);
    setRuleForm({
      name: rule.name,
      event_type: rule.event_type,
      severity: rule.severity,
      conditions: rule.conditions || {},
      channels: rule.channels || [],
      throttle_minutes: rule.throttle_minutes,
    });
    setConditionsText(rule.conditions && Object.keys(rule.conditions).length ? JSON.stringify(rule.conditions) : '');
    setChannelsText((rule.channels || []).join(', '));
    setIsRuleCreateOpen(true);
  };

  const handleDeleteRule = async (id) => {
    if (!(await confirm({
      title: 'Delete alerting rule',
      message: 'Are you sure you want to delete this alerting rule?',
      confirmLabel: 'Delete',
      danger: true,
    }))) return;
    try {
      await deleteAlertRule(id);
      loadAlertData();
    } catch (err) {
      showToast("Failed to delete rule: " + err.message, "error");
    }
  };

  const futureIntegrations = [
    { name: 'Elasticsearch Indexer', desc: 'Forward WAF audit events directly to an Elasticsearch cluster.', icon: Database },
    { name: 'Fluent Bit Log Streamer', desc: 'Stream live CyberSentinel logs via Fluent Bit daemonsets.', icon: Code },
    { name: 'Telegram Alerts', desc: 'Send real-time alerts to Telegram SOC channels via Bot API.', icon: Server }
  ];

  if (loading && !healthData) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: 'var(--text-secondary)', gap: '12px' }}>
        <Activity className="animate-spin" size={24} color="var(--accent-color)" />
        <span>Loading alerting & integrations status...</span>
      </div>
    );
  }

  return (
    <motion.div
      className="integrations-container animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
    >
      {/* Tab Selection */}
      <div style={{ display: 'flex', gap: '12px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
        <button
          className={`tab-btn ${activeSubTab === 'connectors' ? 'active' : ''}`}
          style={{ padding: '8px 16px', fontSize: '13px', borderRadius: '6px', background: activeSubTab === 'connectors' ? 'var(--sev-low-bg)' : 'transparent', border: activeSubTab === 'connectors' ? '1px solid var(--sev-low-border)' : '1px solid transparent', color: activeSubTab === 'connectors' ? 'var(--sev-low)' : 'var(--text-secondary)', cursor: 'pointer', transition: 'all 0.2s' }}
          onClick={() => setActiveSubTab('connectors')}
        >
          Connectors & Health
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'channels' ? 'active' : ''}`}
          style={{ padding: '8px 16px', fontSize: '13px', borderRadius: '6px', background: activeSubTab === 'channels' ? 'var(--sev-low-bg)' : 'transparent', border: activeSubTab === 'channels' ? '1px solid var(--sev-low-border)' : '1px solid transparent', color: activeSubTab === 'channels' ? 'var(--sev-low)' : 'var(--text-secondary)', cursor: 'pointer', transition: 'all 0.2s' }}
          onClick={() => setActiveSubTab('channels')}
        >
          Notification Channels ({channels.length})
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'rules' ? 'active' : ''}`}
          style={{ padding: '8px 16px', fontSize: '13px', borderRadius: '6px', background: activeSubTab === 'rules' ? 'var(--sev-low-bg)' : 'transparent', border: activeSubTab === 'rules' ? '1px solid var(--sev-low-border)' : '1px solid transparent', color: activeSubTab === 'rules' ? 'var(--sev-low)' : 'var(--text-secondary)', cursor: 'pointer', transition: 'all 0.2s' }}
          onClick={() => setActiveSubTab('rules')}
        >
          Evaluation Rules ({rules.length})
        </button>
      </div>

      {alertDataError && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px',
          padding: '12px 16px', borderRadius: '8px',
          background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', color: 'var(--danger-color)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px' }}>
            <AlertTriangle size={18} />
            <span>Couldn't load notification channels/rules from the backend ({alertDataError}). The counts and lists below may be incomplete, not empty.</span>
          </div>
          <button
            type="button"
            onClick={loadAlertData}
            className="action-btn-inspect"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', flex: 'none', background: 'var(--danger-border)', color: 'var(--danger-color)', borderColor: 'var(--danger-border)', padding: '6px 12px' }}
          >
            <RotateCw size={14} /> Retry
          </button>
        </div>
      )}

      {/* Connectors Tab */}
      {activeSubTab === 'connectors' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>CyberSentinel Engine</span>
                <span className="status-badge green"><span className="status-dot"></span> Active</span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: 'var(--text-primary)' }}>Engine:</strong> CyberSentinel Engine v2.0</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Type:</strong> Web Application Firewall</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Scope:</strong> Connection Filtering</div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>OWASP CRS</span>
                <span className="status-badge green"><span className="status-dot"></span> Active</span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: 'var(--text-primary)' }}>Ruleset:</strong> v4.0.0 (Core Ruleset)</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Active Rules:</strong> 250+ guards</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Paranoia Level:</strong> PL1</div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>NGINX</span>
                <span className="status-badge green"><span className="status-dot"></span> Running</span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: 'var(--text-primary)' }}>Version:</strong> nginx/1.24.0</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Engine Connector:</strong> Enabled</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Reverse Proxy:</strong> Active</div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>FastAPI Backend</span>
                <span className={`status-badge ${healthData?.status === 'ok' ? 'green' : 'red'}`}>
                  <span className="status-dot"></span> {healthData?.status === 'ok' ? 'Connected' : 'Offline'}
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: 'var(--text-primary)' }}>Port:</strong> 8000 (Uvicorn)</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Parsed Logs:</strong> {healthData?.total_parsed_files || 0} files</div>
                <div><strong style={{ color: 'var(--text-primary)' }}>Log Status:</strong> {healthData?.log_directory_exists ? 'Readable' : 'Unreachable'}</div>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            <div className="glass-panel" style={{ padding: '24px' }}>
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={16} color="var(--accent-color)" />
                <span>Internal API Gateway Probe Status</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>GET /logs</span>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Query transaction log streams</span>
                  </div>
                  <span style={{ fontSize: '11px', background: 'rgba(16,185,129,0.1)', color: 'var(--success-color)', border: '1px solid rgba(16,185,129,0.2)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>200 OK</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>GET /stats</span>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Calculates incident counters</span>
                  </div>
                  <span style={{ fontSize: '11px', background: 'rgba(16,185,129,0.1)', color: 'var(--success-color)', border: '1px solid rgba(16,185,129,0.2)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>200 OK</span>
                </div>
              </div>
            </div>
          </div>

          <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px' }}>
            <Lock size={18} color="var(--text-secondary)" />
            <span>Enterprise Connectors (Future Roadmap)</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
            {futureIntegrations.map((item, index) => {
              const Icon = item.icon;
              return (
                <div key={index} className="glass-panel" style={{ padding: '20px', display: 'flex', gap: '16px', opacity: 0.45, position: 'relative', overflow: 'hidden' }}>
                  <div style={{ background: 'var(--surface-subtle)', border: '1px solid var(--surface-hover)', padding: '10px', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', height: '42px', width: '42px', flexShrink: 0 }}>
                    <Icon size={20} color="var(--text-secondary)" />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span>{item.name}</span>
                      <span style={{ fontSize: '9px', background: 'var(--surface-hover)', border: '1px solid var(--border-strong)', color: 'var(--text-secondary)', padding: '1px 5px', borderRadius: '3px', textTransform: 'uppercase' }}>Inactive</span>
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0, lineHeight: '1.4' }}>{item.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Channels Tab */}
      {activeSubTab === 'channels' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>Configure Slack, Email and Custom Webhook integrations:</span>
            {userRole === 'admin' && (
              <button className="action-btn-inspect" style={{ padding: '8px 16px', fontSize: '13px' }} onClick={() => setIsChannelCreateOpen(true)}>
                + Add Integration Channel
              </button>
            )}
          </div>

          {isChannelCreateOpen && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border-color)', padding: '20px', borderRadius: '8px', marginBottom: '16px' }}>
              <form onSubmit={handleCreateChannel} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <h4 style={{ margin: 0, fontSize: '14px', color: 'var(--sev-low)' }}>{channelForm.id ? 'Edit Notification Integration' : 'Add New Notification Integration'}</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Connection Name</label>
                    <input className="settings-input" type="text" placeholder="e.g. SOC Team Slack" required value={channelForm.name} onChange={(e) => setChannelForm({ ...channelForm, name: e.target.value })} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Connector Type</label>
                    <select className="settings-input" style={{ width: '100%' }} value={channelForm.channel_type} onChange={(e) => {
                      const newType = e.target.value;
                      let defaultCfg;
                      if (newType === 'email') defaultCfg = { smtp_host: "smtp.office365.com", smtp_port: 587, username: "alerts@yourcompany.com", password: "YOUR_PASSWORD_HERE", from_addr: "alerts@yourcompany.com", to_addrs: ["soc@yourcompany.com"], use_tls: true, use_ssl: false };
                      else if (newType === 'slack') defaultCfg = { webhook_url: "https://hooks.slack.com/services/..." };
                      else if (newType === 'pagerduty') defaultCfg = { integration_key: "YOUR_PAGERDUTY_INTEGRATION_KEY" };
                      else if (newType === 'syslog') defaultCfg = { host: "siem.yourcompany.internal", port: 514, protocol: "udp", facility: "local0", format: "rfc5424" };
                      else defaultCfg = { url: "https://company.api/events", method: "POST", headers: {} };
                      setChannelForm({ ...channelForm, channel_type: newType, config: defaultCfg });
                    }}>
                      <option value="slack">Slack Webhook</option>
                      <option value="email">Email SMTP</option>
                      <option value="pagerduty">PagerDuty</option>
                      <option value="webhook">Generic Webhook</option>
                      <option value="syslog">Syslog (SIEM export)</option>
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Configuration Payload (JSON)</label>
                  {channelForm.channel_type === 'syslog' && (
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Gets every matching event immediately — unlike the other channel types above,
                      syslog is never throttled/deduped, since a SIEM wants everything for its own
                      correlation rather than a reduced-noise subset meant for humans.
                    </div>
                  )}
                  <textarea
                    key={channelForm.channel_type}
                    className="settings-input"
                    required
                    style={{ minHeight: '140px', fontSize: '11px', fontFamily: 'monospace' }}
                    defaultValue={Object.keys(channelForm.config).length > 0 ? JSON.stringify(channelForm.config, null, 2) : (channelForm.channel_type === 'slack' ? '{\n  "webhook_url": "https://hooks.slack.com/services/..."\n}' : channelForm.channel_type === 'email' ? '{\n  "smtp_host": "smtp.office365.com",\n  "smtp_port": 587,\n  "username": "alerts@yourcompany.com",\n  "password": "YOUR_PASSWORD_HERE",\n  "from_addr": "alerts@yourcompany.com",\n  "to_addrs": ["soc@yourcompany.com"],\n  "use_tls": true,\n  "use_ssl": false\n}' : channelForm.channel_type === 'pagerduty' ? '{\n  "integration_key": "YOUR_PAGERDUTY_INTEGRATION_KEY"\n}' : channelForm.channel_type === 'syslog' ? '{\n  "host": "siem.yourcompany.internal",\n  "port": 514,\n  "protocol": "udp",\n  "facility": "local0",\n  "format": "rfc5424"\n}' : '{\n  "url": "https://company.api/events",\n  "method": "POST",\n  "headers": {}\n}')}
                    onChange={(e) => {
                      try {
                        const cfg = JSON.parse(e.target.value);
                        setChannelForm({ ...channelForm, config: cfg });
                      } catch {
                        // ignore invalid JSON while typing
                      }
                    }}
                  ></textarea>
                </div>
                <div style={{ display: 'flex', gap: '10px', marginTop: '4px' }}>
                  <button type="submit" className="modal-btn primary" style={{ margin: 0 }}>Save Integration</button>
                  <button type="button" className="modal-btn secondary" onClick={() => { setIsChannelCreateOpen(false); setChannelForm({ name: '', channel_type: 'slack', config: {} }); }} style={{ margin: 0 }}>Cancel</button>
                </div>
              </form>
            </motion.div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '16px' }}>
            {channels.length > 0 ? (
              channels.map(chan => {
                const health = channelHealth[chan.name];
                return (
                <div key={chan.id} className="glass-panel" style={{ padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1, minWidth: 0, paddingRight: '16px' }}>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{chan.name}</span>
                      <span style={{ background: 'var(--sev-low-border)', color: 'var(--sev-low)', fontSize: '9px', textTransform: 'uppercase', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>{chan.channel_type}</span>
                      {health ? (
                        <span
                          title={health.last_success ? undefined : (health.last_error || 'Last delivery attempt failed')}
                          style={{
                            display: 'flex', alignItems: 'center', gap: '4px', fontSize: '9px', fontWeight: 700,
                            textTransform: 'uppercase', padding: '2px 6px', borderRadius: '4px',
                            background: health.last_success ? 'var(--success-bg)' : 'var(--danger-bg)',
                            color: health.last_success ? 'var(--success-color)' : 'var(--danger-color)',
                          }}
                        >
                          <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'currentColor' }} />
                          {health.last_success ? 'Healthy' : 'Degraded'} · {health.successes}/{health.attempts}
                        </span>
                      ) : (
                        <span style={{ fontSize: '9px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>No deliveries yet</span>
                      )}
                    </div>
                    <code style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'monospace', wordBreak: 'break-all' }}>{JSON.stringify(chan.config)}</code>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                    {userRole === 'admin' && (
                      <button className="action-btn-inspect" style={{ padding: '6px 12px', fontSize: '11px', margin: 0 }} onClick={() => handleTestChannel(chan.id)}>Test</button>
                    )}
                    {userRole === 'admin' && (
                      <button className="action-btn-inspect" style={{ padding: '6px 12px', fontSize: '11px', margin: 0 }} onClick={() => { setChannelForm(chan); setIsChannelCreateOpen(true); }}>
                        Edit
                      </button>
                    )}
                    {userRole === 'admin' && (
                      <button className="action-btn-inspect" style={{ padding: '6px 12px', fontSize: '11px', color: 'var(--danger-color)', border: '1px solid var(--danger-border)', background: 'var(--danger-bg)', margin: 0 }} onClick={() => handleDeleteChannel(chan.id)}>
                        Delete
                      </button>
                    )}
                  </div>
                </div>
                );
              })
            ) : (
              <div className="glass-panel" style={{ gridColumn: 'span 12', padding: '30px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No active notification integrations configured.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Rules Tab */}
      {activeSubTab === 'rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>Define warning and critical event alerting thresholds:</span>
            {userRole === 'admin' && (
              <button className="action-btn-inspect" style={{ padding: '8px 16px', fontSize: '13px' }} onClick={() => { setEditingRuleId(null); setIsRuleCreateOpen(true); }}>
                + Create Alert Rule
              </button>
            )}
          </div>

          {isRuleCreateOpen && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border-color)', padding: '20px', borderRadius: '8px', marginBottom: '16px' }}>
              <form onSubmit={handleSubmitRule} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <h4 style={{ margin: 0, fontSize: '14px', color: 'var(--sev-low)' }}>{editingRuleId != null ? 'Edit Incident Alerting Rule' : 'Create Incident Alerting Rule'}</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Rule Name</label>
                    <input className="settings-input" type="text" placeholder="e.g. Critical Threat Event" required value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Event Type</label>
                    <select className="settings-input" style={{ width: '100%' }} value={ruleForm.event_type} onChange={(e) => setRuleForm({ ...ruleForm, event_type: e.target.value })}>
                      <option value="attack_detected">Attack Detected (WAF)</option>
                      <option value="high_threat_score">High Anomaly Threat Score</option>
                      <option value="ml_anomaly">ML Engine Anomaly Event</option>
                      <option value="health_check_failed">Health Check Failed (System)</option>
                      <option value="system_error">System Error</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Severity Level</label>
                    <select className="settings-input" style={{ width: '100%' }} value={ruleForm.severity} onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value })}>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                    </select>
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Conditions JSON (Optional)</label>
                    <textarea className="settings-input" style={{ minHeight: '90px', fontSize: '11px', fontFamily: 'monospace' }} placeholder='e.g. {"threat_score_gt": 80}' value={conditionsText} onChange={(e) => {
                      setConditionsText(e.target.value);
                      try {
                        const conds = e.target.value.trim() ? JSON.parse(e.target.value) : {};
                        setRuleForm({ ...ruleForm, conditions: conds });
                      } catch {
                        // ignore invalid JSON while typing
                      }
                    }} />
                    {/* Reference for the condition keys evaluate_condition() actually
                        supports (backend/app/services/alert_manager.py) — the field
                        itself is free-text JSON with no other documentation, so this
                        is the only way to discover them short of reading source.
                        crs_score_gt deliberately isn't listed: it's fed by the
                        ModSecurity-nginx connector's CRS score, a known separate gap
                        where that value always reports 0 — listing it here would
                        point analysts at a condition that can never currently match. */}
                    <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                      <strong>Available keys:</strong>{' '}
                      <code>threat_score_gt</code> / <code>threat_score_lt</code> (number, ML combined threat score),{' '}
                      <code>rpm_gt</code> (number, requests/min from client),{' '}
                      <code>isolation_score_gt</code> (number, Isolation Forest anomaly score),{' '}
                      <code>xgb_prob_gt</code> (number, XGBoost probability),{' '}
                      <code>blocked_countries</code> / <code>allowed_countries</code> (array of ISO country codes)
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Throttle Cooldown (Minutes)</label>
                    <input className="settings-input" type="number" min="1" value={ruleForm.throttle_minutes} onChange={(e) => setRuleForm({ ...ruleForm, throttle_minutes: parseInt(e.target.value) || 5 })} />
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Routing Targets (Channel IDs, comma-separated e.g. 1, 2)</label>
                  <input className="settings-input" type="text" placeholder="Enter channel numeric IDs..." value={channelsText} onChange={(e) => {
                    setChannelsText(e.target.value);
                    const ids = e.target.value.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));
                    setRuleForm({ ...ruleForm, channels: ids });
                  }} />
                </div>
                <div style={{ display: 'flex', gap: '10px', marginTop: '4px' }}>
                  <button type="submit" className="modal-btn primary" style={{ margin: 0 }}>{editingRuleId != null ? 'Save Changes' : 'Create Rule'}</button>
                  <button type="button" className="modal-btn secondary" onClick={resetRuleForm} style={{ margin: 0 }}>Cancel</button>
                </div>
              </form>
            </motion.div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
            {rules.length > 0 ? (
              rules.map(rule => (
                <div key={rule.id} className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px', position: 'relative' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)' }}>{rule.name}</span>
                    <span style={{
                      padding: '2px 8px', borderRadius: '4px', fontSize: '9px', fontWeight: 700, textTransform: 'uppercase',
                      background: rule.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                      color: rule.severity === 'critical' ? 'var(--danger-color)' : 'var(--warning-color)',
                      border: rule.severity === 'critical' ? '1px solid rgba(255, 59, 92, 0.2)' : '1px solid rgba(255, 149, 0, 0.2)'
                    }}>{rule.severity}</span>
                  </div>
                  <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '6px', borderTop: '1px solid var(--border-color)', paddingTop: '10px', color: 'var(--text-secondary)' }}>
                    <div><strong>Event type:</strong> <span className="badge-purple" style={{ padding: '2px 6px', background: 'rgba(139, 92, 246, 0.15)', color: 'var(--ml-color)', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>{rule.event_type}</span></div>
                    <div><strong>Conditions:</strong> <code style={{ fontSize: '11px', color: 'var(--success-color)', fontFamily: 'monospace' }}>{JSON.stringify(rule.conditions)}</code></div>
                    <div><strong>Cooldown throttle:</strong> {rule.throttle_minutes} min</div>
                    <div><strong>Channels assigned:</strong> Channel IDs: {JSON.stringify(rule.channels)}</div>
                  </div>
                  {userRole === 'admin' && (
                    <div style={{ display: 'flex', gap: '8px', alignSelf: 'flex-end', marginTop: '8px' }}>
                      <button className="action-btn-inspect" style={{ padding: '4px 10px', fontSize: '11px', margin: 0 }} onClick={() => handleEditRuleClick(rule)}>
                        Edit
                      </button>
                      <button className="action-btn-inspect" style={{ padding: '4px 10px', fontSize: '11px', color: 'var(--danger-color)', border: '1px solid var(--danger-border)', background: 'var(--danger-bg)', margin: 0 }} onClick={() => handleDeleteRule(rule.id)}>
                        Delete Rule
                      </button>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="glass-panel" style={{ gridColumn: 'span 12', padding: '30px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No active alerting rules defined.
              </div>
            )}
          </div>
        </div>
      )}
      <Toast toast={toast} />
    </motion.div>
  );
}

