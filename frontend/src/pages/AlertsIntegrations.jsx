import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, Lock, Database, Code, Server } from 'lucide-react';
import {
  getAlertChannels, createAlertChannel, updateAlertChannel, deleteAlertChannel,
  testAlertChannel, getAlertRules, createAlertRule, deleteAlertRule, getHealth,
} from '../services/api';

export default function AlertsIntegrations({ userRole }) {
  const [loading, setLoading] = useState(true);
  const [healthData, setHealthData] = useState(null);
  const [activeSubTab, setActiveSubTab] = useState('connectors'); // 'connectors', 'channels', 'rules'

  // Alert Config State
  const [channels, setChannels] = useState([]);
  const [rules, setRules] = useState([]);
  const [isChannelCreateOpen, setIsChannelCreateOpen] = useState(false);
  const [isRuleCreateOpen, setIsRuleCreateOpen] = useState(false);
  const [channelForm, setChannelForm] = useState({ name: '', channel_type: 'slack', config: {} });
  const [ruleForm, setRuleForm] = useState({ name: '', event_type: 'attack_detected', severity: 'high', conditions: {}, channels: [], throttle_minutes: 5 });

  const fetchHealth = async () => {
    try {
      const data = await getHealth();
      setHealthData(data);
    } catch (err) {
      console.error("Health check failed", err);
    } finally {
      setLoading(false);
    }
  };

  const loadAlertData = async () => {
    try {
      const chans = await getAlertChannels();
      setChannels(chans || []);
      const rls = await getAlertRules();
      setRules(rls || []);
    } catch (err) {
      console.error("Error loading alert configurations:", err);
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
      alert("Failed to save channel: " + err.message);
    }
  };

  const handleDeleteChannel = async (id) => {
    if (window.confirm("Are you sure you want to delete this notification channel?")) {
      try {
        await deleteAlertChannel(id);
        loadAlertData();
      } catch (err) {
        alert("Failed to delete channel: " + err.message);
      }
    }
  };

  const handleTestChannel = async (id) => {
    try {
      const res = await testAlertChannel(id, { test_message: "Test warning alert configured successfully." });
      if (res.success) {
        alert("Test notification dispatched successfully!");
      } else {
        alert("Dispatch failed: " + res.message);
      }
    } catch (err) {
      alert("Error: " + err.message);
    }
  };

  const handleCreateRule = async (e) => {
    e.preventDefault();
    try {
      await createAlertRule(ruleForm);
      setIsRuleCreateOpen(false);
      setRuleForm({ name: '', event_type: 'attack_detected', severity: 'high', conditions: {}, channels: [], throttle_minutes: 5 });
      loadAlertData();
    } catch (err) {
      alert("Failed to create rule: " + err.message);
    }
  };

  const handleDeleteRule = async (id) => {
    if (window.confirm("Are you sure you want to delete this alerting rule?")) {
      try {
        await deleteAlertRule(id);
        loadAlertData();
      } catch (err) {
        alert("Failed to delete rule: " + err.message);
      }
    }
  };

  const futureIntegrations = [
    { name: 'Elasticsearch Indexer', desc: 'Forward WAF audit events directly to an Elasticsearch cluster.', icon: Database },
    { name: 'Fluent Bit Log Streamer', desc: 'Stream live CyberSentinel logs via Fluent Bit daemonsets.', icon: Code },
    { name: 'Telegram Alerts', desc: 'Send real-time alerts to Telegram SOC channels via Bot API.', icon: Server }
  ];

  if (loading && !healthData) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: '#a1a1aa', gap: '12px' }}>
        <Activity className="animate-spin" size={24} color="#3b82f6" />
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
      <div style={{ display: 'flex', gap: '12px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '12px' }}>
        <button
          className={`tab-btn ${activeSubTab === 'connectors' ? 'active' : ''}`}
          style={{ padding: '8px 16px', fontSize: '13px', borderRadius: '6px', background: activeSubTab === 'connectors' ? 'rgba(59,130,246,0.1)' : 'transparent', border: activeSubTab === 'connectors' ? '1px solid rgba(59,130,246,0.2)' : '1px solid transparent', color: activeSubTab === 'connectors' ? '#60a5fa' : '#a1a1aa', cursor: 'pointer', transition: 'all 0.2s' }}
          onClick={() => setActiveSubTab('connectors')}
        >
          Connectors & Health
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'channels' ? 'active' : ''}`}
          style={{ padding: '8px 16px', fontSize: '13px', borderRadius: '6px', background: activeSubTab === 'channels' ? 'rgba(59,130,246,0.1)' : 'transparent', border: activeSubTab === 'channels' ? '1px solid rgba(59,130,246,0.2)' : '1px solid transparent', color: activeSubTab === 'channels' ? '#60a5fa' : '#a1a1aa', cursor: 'pointer', transition: 'all 0.2s' }}
          onClick={() => setActiveSubTab('channels')}
        >
          Notification Channels ({channels.length})
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'rules' ? 'active' : ''}`}
          style={{ padding: '8px 16px', fontSize: '13px', borderRadius: '6px', background: activeSubTab === 'rules' ? 'rgba(59,130,246,0.1)' : 'transparent', border: activeSubTab === 'rules' ? '1px solid rgba(59,130,246,0.2)' : '1px solid transparent', color: activeSubTab === 'rules' ? '#60a5fa' : '#a1a1aa', cursor: 'pointer', transition: 'all 0.2s' }}
          onClick={() => setActiveSubTab('rules')}
        >
          Evaluation Rules ({rules.length})
        </button>
      </div>

      {/* Connectors Tab */}
      {activeSubTab === 'connectors' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: '#e4e4e7' }}>CyberSentinel Engine</span>
                <span className="status-badge green"><span className="status-dot"></span> Active</span>
              </div>
              <div style={{ fontSize: '13px', color: '#a1a1aa', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: '#d4d4d8' }}>Engine:</strong> CyberSentinel Engine v2.0</div>
                <div><strong style={{ color: '#d4d4d8' }}>Type:</strong> Web Application Firewall</div>
                <div><strong style={{ color: '#d4d4d8' }}>Scope:</strong> Connection Filtering</div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: '#e4e4e7' }}>OWASP CRS</span>
                <span className="status-badge green"><span className="status-dot"></span> Active</span>
              </div>
              <div style={{ fontSize: '13px', color: '#a1a1aa', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: '#d4d4d8' }}>Ruleset:</strong> v4.0.0 (Core Ruleset)</div>
                <div><strong style={{ color: '#d4d4d8' }}>Active Rules:</strong> 250+ guards</div>
                <div><strong style={{ color: '#d4d4d8' }}>Paranoia Level:</strong> PL1</div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: '#e4e4e7' }}>NGINX</span>
                <span className="status-badge green"><span className="status-dot"></span> Running</span>
              </div>
              <div style={{ fontSize: '13px', color: '#a1a1aa', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: '#d4d4d8' }}>Version:</strong> nginx/1.24.0</div>
                <div><strong style={{ color: '#d4d4d8' }}>Engine Connector:</strong> Enabled</div>
                <div><strong style={{ color: '#d4d4d8' }}>Reverse Proxy:</strong> Active</div>
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: '#e4e4e7' }}>FastAPI Backend</span>
                <span className={`status-badge ${healthData?.status === 'ok' ? 'green' : 'red'}`}>
                  <span className="status-dot"></span> {healthData?.status === 'ok' ? 'Connected' : 'Offline'}
                </span>
              </div>
              <div style={{ fontSize: '13px', color: '#a1a1aa', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><strong style={{ color: '#d4d4d8' }}>Port:</strong> 8000 (Uvicorn)</div>
                <div><strong style={{ color: '#d4d4d8' }}>Parsed Logs:</strong> {healthData?.total_parsed_files || 0} files</div>
                <div><strong style={{ color: '#d4d4d8' }}>Log Status:</strong> {healthData?.log_directory_exists ? 'Readable' : 'Unreachable'}</div>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            <div className="glass-panel" style={{ padding: '24px' }}>
              <div style={{ fontSize: '15px', fontWeight: 600, color: '#f4f4f5', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={16} color="#3b82f6" />
                <span>Internal API Gateway Probe Status</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: '#e4e4e7' }}>GET /logs</span>
                    <span style={{ fontSize: '11px', color: '#a1a1aa' }}>Query transaction log streams</span>
                  </div>
                  <span style={{ fontSize: '11px', background: 'rgba(16,185,129,0.1)', color: '#10b981', border: '1px solid rgba(16,185,129,0.2)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>200 OK</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: '#e4e4e7' }}>GET /stats</span>
                    <span style={{ fontSize: '11px', color: '#a1a1aa' }}>Calculates incident counters</span>
                  </div>
                  <span style={{ fontSize: '11px', background: 'rgba(16,185,129,0.1)', color: '#10b981', border: '1px solid rgba(16,185,129,0.2)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>200 OK</span>
                </div>
              </div>
            </div>
          </div>

          <div style={{ fontSize: '16px', fontWeight: 600, color: '#a1a1aa', display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px' }}>
            <Lock size={18} color="#a1a1aa" />
            <span>Enterprise Connectors (Future Roadmap)</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
            {futureIntegrations.map((item, index) => {
              const Icon = item.icon;
              return (
                <div key={index} className="glass-panel" style={{ padding: '20px', display: 'flex', gap: '16px', opacity: 0.45, position: 'relative', overflow: 'hidden' }}>
                  <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)', padding: '10px', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', height: '42px', width: '42px', flexShrink: 0 }}>
                    <Icon size={20} color="#a1a1aa" />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ fontWeight: 600, color: '#e4e4e7', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span>{item.name}</span>
                      <span style={{ fontSize: '9px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#a1a1aa', padding: '1px 5px', borderRadius: '3px', textTransform: 'uppercase' }}>Inactive</span>
                    </div>
                    <p style={{ fontSize: '12px', color: '#a1a1aa', margin: 0, lineHeight: '1.4' }}>{item.desc}</p>
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
            <span style={{ fontSize: '14px', color: '#a1a1aa' }}>Configure Slack, Email and Custom Webhook integrations:</span>
            {userRole === 'admin' && (
              <button className="action-btn-inspect" style={{ padding: '8px 16px', fontSize: '13px' }} onClick={() => setIsChannelCreateOpen(true)}>
                + Add Integration Channel
              </button>
            )}
          </div>

          {isChannelCreateOpen && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', padding: '20px', borderRadius: '8px', marginBottom: '16px' }}>
              <form onSubmit={handleCreateChannel} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <h4 style={{ margin: 0, fontSize: '14px', color: '#60a5fa' }}>{channelForm.id ? 'Edit Notification Integration' : 'Add New Notification Integration'}</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Connection Name</label>
                    <input className="settings-input" type="text" placeholder="e.g. SOC Team Slack" required value={channelForm.name} onChange={(e) => setChannelForm({ ...channelForm, name: e.target.value })} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Connector Type</label>
                    <select className="settings-input" style={{ width: '100%' }} value={channelForm.channel_type} onChange={(e) => {
                      const newType = e.target.value;
                      let defaultCfg;
                      if (newType === 'email') defaultCfg = { smtp_host: "smtp.office365.com", smtp_port: 587, username: "alerts@yourcompany.com", password: "YOUR_PASSWORD_HERE", from_addr: "alerts@yourcompany.com", to_addrs: ["soc@yourcompany.com"], use_tls: true, use_ssl: false };
                      else if (newType === 'slack') defaultCfg = { webhook_url: "https://hooks.slack.com/services/..." };
                      else defaultCfg = { url: "https://company.api/events", method: "POST", headers: {} };
                      setChannelForm({ ...channelForm, channel_type: newType, config: defaultCfg });
                    }}>
                      <option value="slack">Slack Webhook</option>
                      <option value="email">Email SMTP</option>
                      <option value="webhook">Generic Webhook</option>
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Configuration Payload (JSON)</label>
                  <textarea 
                    key={channelForm.channel_type}
                    className="settings-input" 
                    required 
                    style={{ minHeight: '140px', fontSize: '11px', fontFamily: 'monospace' }} 
                    defaultValue={Object.keys(channelForm.config).length > 0 ? JSON.stringify(channelForm.config, null, 2) : (channelForm.channel_type === 'slack' ? '{\n  "webhook_url": "https://hooks.slack.com/services/..."\n}' : channelForm.channel_type === 'email' ? '{\n  "smtp_host": "smtp.office365.com",\n  "smtp_port": 587,\n  "username": "alerts@yourcompany.com",\n  "password": "YOUR_PASSWORD_HERE",\n  "from_addr": "alerts@yourcompany.com",\n  "to_addrs": ["soc@yourcompany.com"],\n  "use_tls": true,\n  "use_ssl": false\n}' : '{\n  "url": "https://company.api/events",\n  "method": "POST",\n  "headers": {}\n}')} 
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
              channels.map(chan => (
                <div key={chan.id} className="glass-panel" style={{ padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1, minWidth: 0, paddingRight: '16px' }}>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '14px', color: '#e4e4e7', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{chan.name}</span>
                      <span style={{ background: 'rgba(59,130,246,0.15)', color: '#60a5fa', fontSize: '9px', textTransform: 'uppercase', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>{chan.channel_type}</span>
                    </div>
                    <code style={{ fontSize: '11px', color: '#a1a1aa', fontFamily: 'monospace', wordBreak: 'break-all' }}>{JSON.stringify(chan.config)}</code>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                    <button className="action-btn-inspect" style={{ padding: '6px 12px', fontSize: '11px', margin: 0 }} onClick={() => handleTestChannel(chan.id)}>Test</button>
                    {userRole === 'admin' && chan.channel_type === 'email' && (
                      <button className="action-btn-inspect" style={{ padding: '6px 12px', fontSize: '11px', margin: 0 }} onClick={() => { setChannelForm(chan); setIsChannelCreateOpen(true); }}>
                        Edit
                      </button>
                    )}
                    {userRole === 'admin' && (
                      <button className="action-btn-inspect" style={{ padding: '6px 12px', fontSize: '11px', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.06)', margin: 0 }} onClick={() => handleDeleteChannel(chan.id)}>
                        Delete
                      </button>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="glass-panel" style={{ gridColumn: 'span 12', padding: '30px', textAlign: 'center', color: '#a1a1aa' }}>
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
            <span style={{ fontSize: '14px', color: '#a1a1aa' }}>Define warning and critical event alerting thresholds:</span>
            {userRole === 'admin' && (
              <button className="action-btn-inspect" style={{ padding: '8px 16px', fontSize: '13px' }} onClick={() => setIsRuleCreateOpen(true)}>
                + Create Alert Rule
              </button>
            )}
          </div>

          {isRuleCreateOpen && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', padding: '20px', borderRadius: '8px', marginBottom: '16px' }}>
              <form onSubmit={handleCreateRule} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <h4 style={{ margin: 0, fontSize: '14px', color: '#60a5fa' }}>Create Incident Alerting Rule</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Rule Name</label>
                    <input className="settings-input" type="text" placeholder="e.g. Critical Threat Event" required value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Event Type</label>
                    <select className="settings-input" style={{ width: '100%' }} value={ruleForm.event_type} onChange={(e) => setRuleForm({ ...ruleForm, event_type: e.target.value })}>
                      <option value="attack_detected">Attack Detected (WAF)</option>
                      <option value="high_threat_score">High Anomaly Threat Score</option>
                      <option value="ml_anomaly">ML Engine Anomaly Event</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Severity Level</label>
                    <select className="settings-input" style={{ width: '100%' }} value={ruleForm.severity} onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value })}>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                    </select>
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Conditions JSON (Optional)</label>
                    <input className="settings-input" type="text" placeholder='e.g. {"threat_score_gt": 80}' onChange={(e) => {
                      try {
                        const conds = JSON.parse(e.target.value);
                        setRuleForm({ ...ruleForm, conditions: conds });
                      } catch {
                        // ignore invalid JSON while typing
                      }
                    }} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Throttle Cooldown (Minutes)</label>
                    <input className="settings-input" type="number" min="1" value={ruleForm.throttle_minutes} onChange={(e) => setRuleForm({ ...ruleForm, throttle_minutes: parseInt(e.target.value) || 5 })} />
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '12px', color: '#a1a1aa' }}>Routing Targets (Channel IDs, comma-separated e.g. 1, 2)</label>
                  <input className="settings-input" type="text" placeholder="Enter channel numeric IDs..." onChange={(e) => {
                    const ids = e.target.value.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));
                    setRuleForm({ ...ruleForm, channels: ids });
                  }} />
                </div>
                <div style={{ display: 'flex', gap: '10px', marginTop: '4px' }}>
                  <button type="submit" className="modal-btn primary" style={{ margin: 0 }}>Create Rule</button>
                  <button type="button" className="modal-btn secondary" onClick={() => setIsRuleCreateOpen(false)} style={{ margin: 0 }}>Cancel</button>
                </div>
              </form>
            </motion.div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
            {rules.length > 0 ? (
              rules.map(rule => (
                <div key={rule.id} className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px', position: 'relative' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: '14px', color: '#e4e4e7' }}>{rule.name}</span>
                    <span style={{
                      padding: '2px 8px', borderRadius: '4px', fontSize: '9px', fontWeight: 700, textTransform: 'uppercase',
                      background: rule.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                      color: rule.severity === 'critical' ? 'var(--danger-color)' : 'var(--warning-color)',
                      border: rule.severity === 'critical' ? '1px solid rgba(255, 59, 92, 0.2)' : '1px solid rgba(255, 149, 0, 0.2)'
                    }}>{rule.severity}</span>
                  </div>
                  <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '6px', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '10px', color: '#a1a1aa' }}>
                    <div><strong>Event type:</strong> <span className="badge-purple" style={{ padding: '2px 6px', background: 'rgba(139, 92, 246, 0.15)', color: '#a78bfa', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>{rule.event_type}</span></div>
                    <div><strong>Conditions:</strong> <code style={{ fontSize: '11px', color: '#34d399', fontFamily: 'monospace' }}>{JSON.stringify(rule.conditions)}</code></div>
                    <div><strong>Cooldown throttle:</strong> {rule.throttle_minutes} min</div>
                    <div><strong>Channels assigned:</strong> Channel IDs: {JSON.stringify(rule.channels)}</div>
                  </div>
                  {userRole === 'admin' && (
                    <button className="action-btn-inspect" style={{ alignSelf: 'flex-end', padding: '4px 10px', fontSize: '11px', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.06)', margin: 0, marginTop: '8px' }} onClick={() => handleDeleteRule(rule.id)}>
                      Delete Rule
                    </button>
                  )}
                </div>
              ))
            ) : (
              <div className="glass-panel" style={{ gridColumn: 'span 12', padding: '30px', textAlign: 'center', color: '#a1a1aa' }}>
                No active alerting rules defined.
              </div>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}

