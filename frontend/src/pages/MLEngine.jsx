import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle as AlertTriangleIcon, Brain, Clock, Globe, Lock,
  Server, Settings as SettingsIcon, ShieldAlert,
} from 'lucide-react';
import {
  Area, Bar, CartesianGrid, Cell, ComposedChart, Pie, PieChart, Tooltip as RechartsTooltip,
  ResponsiveContainer, XAxis, YAxis,
} from 'recharts';
import {
  getMLBackups, getMLDriftHistory, getMLFeatureImportance, getMLLogs, getMLModelInfo,
  getMLRetrainStatus, getMLStats, getMLTimeline, rollbackMLModel, triggerMLRetrain,
} from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import { HelpText } from '../components/Tooltip';
import { NoMLEventsEmptyState } from '../components/EmptyStates';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import MLLogDrawer from '../components/MLLogDrawer';

export default function MLAnalytics() {
  const [stats, setStats] = useState({
    total_evaluations: 0,
    decision_breakdown: { allow: 0, block: 0, rate_limit: 0, log: 0 },
    avg_threat_score: 0.0,
    top_anomalous_uris: [],
    top_anomalous_ips: []
  });
  const [logs, setLogs] = useState([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [page, setPage] = useState(1);
  const [size] = useState(10);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterDecision, setFilterDecision] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const { toast, showToast } = useToast();
  const confirm = useConfirm();

  // Model Management & Retraining States
  const [activeSubTab, setActiveSubTab] = useState('analytics'); // 'analytics', 'management'
  const [modelInfo, setModelInfo] = useState(null);
  const [retrainStatus, setRetrainStatus] = useState({ status: 'idle', logs: '' });
  const [backups, setBackups] = useState([]);
  const [featureImportance, setFeatureImportance] = useState([]);
  const [driftHistory, setDriftHistory] = useState([]);
  const [, setLoadingManagement] = useState(false);
  const [triggeringRetrain, setTriggeringRetrain] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);

  const fetchManagementData = async () => {
    setLoadingManagement(true);
    try {
      const info = await getMLModelInfo();
      if (info && !info.error) setModelInfo(info);

      const status = await getMLRetrainStatus();
      if (status && !status.error) setRetrainStatus(status);

      const bks = await getMLBackups();
      if (bks && !bks.error) setBackups(bks.data || []);

      const imp = await getMLFeatureImportance();
      if (imp && !imp.error) setFeatureImportance(imp.data || []);

      const drift = await getMLDriftHistory();
      if (drift && !drift.error) setDriftHistory(drift.data || []);
    } catch (err) {
      console.error("Failed to load ML management data:", err);
    } finally {
      setLoadingManagement(false);
    }
  };

  const isPollingManagementRef = useRef(false);

  useEffect(() => {
    let interval;
    if (activeSubTab === 'management') {
      fetchManagementData();
      interval = setInterval(async () => {
        // setInterval fires unconditionally regardless of whether the
        // previous poll (up to 5 sequential calls) resolved — skip an
        // overlapping cycle rather than piling requests up.
        if (isPollingManagementRef.current) return;
        isPollingManagementRef.current = true;
        try {
          const status = await getMLRetrainStatus();
          if (status && !status.error) {
            setRetrainStatus(status);
            if (status.status !== 'running') {
              const info = await getMLModelInfo();
              if (info && !info.error) setModelInfo(info);
              const bks = await getMLBackups();
              if (bks && !bks.error) setBackups(bks.data || []);
              const imp = await getMLFeatureImportance();
              if (imp && !imp.error) setFeatureImportance(imp.data || []);
              const drift = await getMLDriftHistory();
              if (drift && !drift.error) setDriftHistory(drift.data || []);
            }
          }
        } catch (err) {
          console.warn("Error polling retrain status:", err);
        } finally {
          isPollingManagementRef.current = false;
        }
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [activeSubTab]);

  const handleTriggerRetrain = async () => {
    const ok = await confirm({
      title: 'Trigger ML retraining',
      message: 'This will run collect_data and rebuild XGBoost and Isolation Forest classifiers using active traffic db records.',
      confirmLabel: 'Retrain',
    });
    if (!ok) return;
    setTriggeringRetrain(true);
    try {
      const res = await triggerMLRetrain();
      if (res.status === 'success') {
        setRetrainStatus(prev => ({ ...prev, status: 'running' }));
      } else {
        showToast("Failed to start retraining: " + res.message, "error");
      }
    } catch (err) {
      showToast("Retrain error: " + err.message, "error");
    } finally {
      setTriggeringRetrain(false);
    }
  };

  const handleRollback = async (timestamp) => {
    const ok = await confirm({
      title: 'Roll back ML models',
      message: `Are you sure you want to roll back both model weights to version backup ${timestamp}?`,
      confirmLabel: 'Roll back',
      danger: true,
    });
    if (!ok) return;
    setRollingBack(true);
    try {
      const res = await rollbackMLModel(timestamp);
      if (res.status === 'success') {
        showToast(res.message);
        const info = await getMLModelInfo();
        if (info && !info.error) setModelInfo(info);
        const bks = await getMLBackups();
        if (bks && !bks.error) setBackups(bks.data || []);
      } else {
        showToast("Rollback failed: " + res.message, "error");
      }
    } catch (err) {
      showToast("Rollback error: " + err.message, "error");
    } finally {
      setRollingBack(false);
    }
  };

  const isFetchingMLDataRef = useRef(false);

  const fetchMLData = async () => {
    if (isFetchingMLDataRef.current) return;
    isFetchingMLDataRef.current = true;
    try {
      const statsData = await getMLStats();
      if (statsData && !statsData.error) {
        setStats(statsData);
      }

      const filters = {};
      if (filterDecision) filters.decision = filterDecision;
      if (searchQuery) filters.search = searchQuery;

      const logsData = await getMLLogs(page, size, filters);
      if (logsData && !logsData.error) {
        setLogs(logsData.data || []);
        setTotalLogs(logsData.total || 0);
      }

      const timelineData = await getMLTimeline();
      if (timelineData && !timelineData.error) {
        setTimeline(timelineData.data || []);
      }
    } catch (err) {
      console.error("Error fetching ML analytics data:", err);
      showToast('Failed to load ML analytics: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setLoading(false);
      isFetchingMLDataRef.current = false;
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchMLData();
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, filterDecision, searchQuery]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchMLData();
    }, refreshInterval);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh, refreshInterval, page, filterDecision, searchQuery]);

  const decisionColors = {
    allow: 'var(--success-color)',
    log: 'var(--sev-low)',
    rate_limit: 'var(--warning-color)',
    block: 'var(--danger-color)'
  };

  const pieData = Object.entries(stats.decision_breakdown).map(([name, value]) => ({
    name: name.toUpperCase().replace('_', ' '),
    value,
    color: decisionColors[name] || 'var(--text-secondary)'
  })).filter(item => item.value > 0);

  const hasPieData = pieData.length > 0;
  const displayPieData = hasPieData ? pieData : [
    { name: 'NO DATA', value: 1, color: 'var(--text-secondary)' }
  ];

  return (
    <motion.div
      className="dashboard-grid animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <Toast toast={toast} />

      {/* Dynamic Controls Header inside the grid to span full width */}
      <div className="glass-panel" style={{ gridColumn: 'span 12', padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Brain size={24} color="var(--accent-dim)" style={{ filter: 'drop-shadow(0 0 8px rgba(99, 102, 241, 0.5))' }} />
          <div>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Status: </span>
            <strong style={{ fontSize: '13px', color: 'var(--success-color)' }}>Predictive Protection Shields Active</strong>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Auto Refresh:</span>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              style={{ cursor: 'pointer', width: '16px', height: '16px' }}
            />
          </div>

          <select
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            disabled={!autoRefresh}
            className="filter-select"
            style={{ padding: '6px 12px' }}
          >
            <option value={1000}>1s Refresh</option>
            <option value={3000}>3s Refresh</option>
            <option value={5000}>5s Refresh</option>
            <option value={10000}>10s Refresh</option>
          </select>

          <button
            className="modal-btn primary"
            onClick={fetchMLData}
            style={{ padding: '6px 14px', borderRadius: '8px' }}
          >
            <Activity size={14} /> Force Sync
          </button>
        </div>
      </div>

      {/* Sub-tab selection menu */}
      <div style={{ display: 'flex', gap: '10px', gridColumn: 'span 12', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
        <button 
          className={`subtab-btn ${activeSubTab === 'analytics' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('analytics')}
          style={{ padding: '6px 16px', fontSize: '13px', border: 'none', background: 'none', cursor: 'pointer', color: activeSubTab === 'analytics' ? 'var(--accent-color)' : 'var(--text-secondary)', borderBottom: activeSubTab === 'analytics' ? '2px solid var(--accent-color)' : 'none', fontWeight: 600 }}
        >
          Analytics Telemetry
        </button>
        <button 
          className={`subtab-btn ${activeSubTab === 'management' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('management')}
          style={{ padding: '6px 16px', fontSize: '13px', border: 'none', background: 'none', cursor: 'pointer', color: activeSubTab === 'management' ? 'var(--accent-color)' : 'var(--text-secondary)', borderBottom: activeSubTab === 'management' ? '2px solid var(--accent-color)' : 'none', fontWeight: 600 }}
        >
          Model Control & Retraining
        </button>
      </div>

      {activeSubTab === 'analytics' ? (
        <>
          {/* Metric Cards Grid */}
          <div className="metric-card glass-panel" style={{ gridColumn: 'span 3' }}>
            <div className="metric-header">
              <span>AI Evaluations</span>
              <div className="metric-icon-wrapper blue"><Brain size={18} /></div>
            </div>
            <div className="metric-value">{stats.total_evaluations.toLocaleString()}</div>
            <div className="metric-trend trend-down">
              <Clock size={12} /> <span>Real-time capture</span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 3' }}>
            <div className="metric-header">
              <span>Avg Threat Score</span>
              <div className="metric-icon-wrapper blue" style={{ color: 'var(--accent-color)', background: 'var(--accent-bg)' }}><Activity size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: 'var(--accent-color)' }}>{(stats.avg_threat_score * 100).toFixed(1)}%</div>
            <div className="metric-trend trend-down">
              <span>Overall anomaly ratio</span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 3' }}>
            <div className="metric-header">
              <span>Blocks Executed</span>
              <div className="metric-icon-wrapper red"><ShieldAlert size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: 'var(--danger-color)' }}>{stats.decision_breakdown.block.toLocaleString()}</div>
            <div className="metric-trend trend-up">
              <span>
                {stats.total_evaluations > 0
                  ? ((stats.decision_breakdown.block / stats.total_evaluations) * 100).toFixed(1)
                  : 0}% block rate
              </span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 3' }}>
            <div className="metric-header">
              <span>Rate Limited</span>
              <div className="metric-icon-wrapper orange"><Lock size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: 'var(--warning-color)' }}>{stats.decision_breakdown.rate_limit.toLocaleString()}</div>
            <div className="metric-trend trend-up">
              <span>
                {stats.total_evaluations > 0
                  ? ((stats.decision_breakdown.rate_limit / stats.total_evaluations) * 100).toFixed(1)
                  : 0}% rate limits
              </span>
            </div>
          </div>

          {/* Decision Threshold Banner */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', padding: '24px' }}>
            <div className="card-title" style={{ marginBottom: '16px' }}>
              <SettingsIcon size={18} color="var(--accent-color)" />
              Hybrid Decision Matrix Routing Thresholds
            </div>

            <div style={{ display: 'flex', width: '100%', height: '32px', borderRadius: '8px', overflow: 'hidden', background: 'var(--surface-subtle)', border: '1px solid var(--border-color)', marginBottom: '16px', fontSize: '12px', fontWeight: 600, textAlign: 'center', lineHeight: '32px' }}>
              <div style={{ width: '40%', background: 'rgba(16, 185, 129, 0.15)', borderRight: '1px solid rgba(16, 185, 129, 0.3)', color: 'var(--success-color)' }}>ALLOW (Score &lt; 40%)</div>
              <div style={{ width: '30%', background: 'rgba(99, 102, 241, 0.15)', borderRight: '1px solid rgba(99, 102, 241, 0.3)', color: 'var(--accent-color)' }}>LOG (40% - 70%)</div>
              <div style={{ width: '15%', background: 'rgba(245, 158, 11, 0.15)', borderRight: '1px solid rgba(245, 158, 11, 0.3)', color: 'var(--warning-color)' }}>LIMIT (70% - 85%)</div>
              <div style={{ width: '15%', background: 'rgba(244, 63, 94, 0.15)', color: 'var(--danger-color)' }}>BLOCK (&gt;= 85%)</div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)', fontSize: '13px', flexWrap: 'wrap', gap: '8px' }}>
              <span>ℹ️ Scores combine CRS signatures (50%), XGBoost classification (30%), Isolation Forest novelty (20%), and Redis reputation.</span>
              <span style={{ color: 'var(--accent-color)', fontWeight: 500 }}>Engine: Active (FastAPI Daemon)</span>
            </div>
          </div>

          {/* Visual Analytics Row */}
          {/* Timeline Chart */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 8' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <div className="card-title" style={{ marginBottom: 0 }}>
                <Activity size={18} color="var(--accent-color)" />
                Threat Score Timeline Trends
              </div>
              <div className="pulse-container">
                <div className="pulse-dot"></div>
                <span>Live Sync</span>
              </div>
            </div>

            <div className="chart-container" style={{ minHeight: '280px' }}>
              {timeline.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={timeline} margin={{ top: 10, right: 15, left: -15, bottom: 0 }}>
                    <defs>
                      <linearGradient id="mlThreatScoreGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--danger-color)" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="var(--danger-color)" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--surface-hover)" vertical={false} />
                    <XAxis
                      dataKey="time_bucket"
                      tickFormatter={(val) => {
                        try {
                          return val.split(' ')[1].slice(0, 5); // Display HH:MM
                        } catch {
                          return val;
                        }
                      }}
                      stroke="var(--text-secondary)"
                      fontSize={11}
                      tickLine={false}
                      axisLine={false}
                      interval="preserveStartEnd"
                      minTickGap={50}
                    />
                    {/* Left YAxis: Threat Score */}
                    <YAxis
                      yAxisId="left"
                      domain={[0, 1]}
                      tickFormatter={(val) => `${(val * 100).toFixed(0)}%`}
                      stroke="var(--text-secondary)"
                      fontSize={11}
                      tickLine={false}
                      axisLine={false}
                    />
                    {/* Right YAxis: Request Count */}
                    <YAxis
                      yAxisId="right"
                      orientation="right"
                      stroke="var(--text-secondary)"
                      fontSize={11}
                      tickLine={false}
                      axisLine={false}
                      allowDecimals={false}
                    />
                    <RechartsTooltip
                      contentStyle={{
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '12px',
                        color: 'var(--text-primary)',
                        fontFamily: 'inherit',
                        boxShadow: '0 10px 25px rgba(0,0,0,0.5)'
                      }}
                      labelFormatter={(label) => `Time: ${label}`}
                      formatter={(value, name) => [
                        name === 'avg_score' ? `${(value * 100).toFixed(1)}%` : value,
                        name === 'avg_score' ? 'Avg Threat' : 'Request Count'
                      ]}
                    />
                    {/* Request Count Bar in the background */}
                    <Bar
                      yAxisId="right"
                      dataKey="count"
                      name="Request Count"
                      fill="rgba(99, 102, 241, 0.12)"
                      stroke="rgba(99, 102, 241, 0.35)"
                      strokeWidth={1}
                      barSize={18}
                      radius={[4, 4, 0, 0]}
                    />
                    {/* Avg Threat Score Area in the foreground */}
                    <Area
                      yAxisId="left"
                      type="monotone"
                      dataKey="avg_score"
                      name="Avg Threat"
                      stroke="var(--danger-color)"
                      strokeWidth={2.5}
                      fillOpacity={1}
                      fill="url(#mlThreatScoreGrad)"
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)', fontSize: '14px' }}>
                  Waiting for ML evaluation requests to compile graph data...
                </div>
              )}
            </div>
          </div>

          {/* Mitigation Actions Pie */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 4' }}>
            <div className="card-title">
              <Brain size={18} color="var(--accent-color)" />
              Mitigation Action Shares
            </div>

            <div className="chart-container" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
              <div style={{ width: '100%', height: '160px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={displayPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={65}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {displayPieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '8px',
                        color: 'var(--text-primary)',
                        fontFamily: 'inherit'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', width: '100%', marginTop: '16px', fontSize: '12px' }}>
                {Object.entries(stats.decision_breakdown).map(([key, val]) => (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: decisionColors[key] }} />
                    <span style={{ textTransform: 'capitalize' }}>{key.replace('_', ' ')}:</span>
                    <strong style={{ color: 'var(--text-primary)', marginLeft: 'auto' }}>{val}</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Leaderboards */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6' }}>
            <div className="card-title">
              <Globe size={18} color="var(--accent-color)" />
              Highly Suspect Target Endpoints
            </div>

            <div style={{ overflow: 'hidden' }}>
              {stats.top_anomalous_uris.length > 0 ? (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                      <th style={{ padding: '8px 0', fontSize: '12px', textTransform: 'uppercase', fontWeight: 500 }}>URI Path</th>
                      <th style={{ padding: '8px 0', textAlign: 'center', fontSize: '12px', textTransform: 'uppercase', fontWeight: 500 }}>Count</th>
                      <th style={{ padding: '8px 0', textAlign: 'right', fontSize: '12px', textTransform: 'uppercase', fontWeight: 500 }}>Avg Threat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.top_anomalous_uris.map((item, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--surface-subtle)', color: 'var(--text-primary)' }}>
                        <td style={{ padding: '10px 0', fontFamily: 'monospace', color: 'var(--accent-color)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.uri}>
                          {item.uri}
                        </td>
                        <td style={{ padding: '10px 0', textAlign: 'center' }}>{item.count}</td>
                        <td style={{ padding: '10px 0', textAlign: 'right', color: item.avg_score >= 0.7 ? 'var(--danger-color)' : 'var(--warning-color)', fontWeight: 600 }}>
                          {(item.avg_score * 100).toFixed(0)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ padding: '16px 0', color: 'var(--text-secondary)', textAlign: 'center' }}>No endpoints evaluated yet.</div>
              )}
            </div>
          </div>

          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6' }}>
            <div className="card-title">
              <Server size={18} color="var(--accent-color)" />
              Top Suspect Client IPs
            </div>

            <div style={{ overflow: 'hidden' }}>
              {stats.top_anomalous_ips.length > 0 ? (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                      <th style={{ padding: '8px 0', fontSize: '12px', textTransform: 'uppercase', fontWeight: 500 }}>IP Address</th>
                      <th style={{ padding: '8px 0', textAlign: 'center', fontSize: '12px', textTransform: 'uppercase', fontWeight: 500 }}>Count</th>
                      <th style={{ padding: '8px 0', textAlign: 'right', fontSize: '12px', textTransform: 'uppercase', fontWeight: 500 }}>Avg Threat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.top_anomalous_ips.map((item, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--surface-subtle)', color: 'var(--text-primary)' }}>
                        <td style={{ padding: '10px 0', fontFamily: 'monospace', color: 'var(--accent-color)' }}>{item.ip}</td>
                        <td style={{ padding: '10px 0', textAlign: 'center' }}>{item.count}</td>
                        <td style={{ padding: '10px 0', textAlign: 'right', color: item.avg_score >= 0.7 ? 'var(--danger-color)' : 'var(--warning-color)', fontWeight: 600 }}>
                          {(item.avg_score * 100).toFixed(0)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ padding: '16px 0', color: 'var(--text-secondary)', textAlign: 'center' }}>No suspicious IPs evaluated yet.</div>
              )}
            </div>
          </div>

          {/* Live Inferences Logs */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 12' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
              <div className="card-title" style={{ marginBottom: 0 }}>
                <ShieldAlert size={18} color="var(--danger-color)" />
                Recent AI/ML Evaluation Inferences
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <input
                  type="text"
                  placeholder="Search by URI, IP, variables..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setPage(1);
                  }}
                  className="search-input"
                  style={{ width: '220px', paddingLeft: '14px' }}
                />

                <select
                  value={filterDecision}
                  onChange={(e) => {
                    setFilterDecision(e.target.value);
                    setPage(1);
                  }}
                  className="filter-select"
                >
                  <option value="">All Actions</option>
                  <option value="allow">Allow Only</option>
                  <option value="log">Log Only</option>
                  <option value="rate_limit">Rate Limit Only</option>
                  <option value="block">Block Only</option>
                </select>
              </div>
            </div>

            {/* Logs Table */}
            <div className="logs-table-wrapper">
              <table className="logs-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Client IP</th>
                    <th>Request Details</th>
                    <th style={{ textAlign: 'center' }}>XGB Prob</th>
                    <th style={{ textAlign: 'center' }}>Isolation Score</th>
                    <th style={{ textAlign: 'center' }}>Threat Score</th>
                    <th style={{ textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length > 0 ? (
                    logs.map((log) => (
                      <tr
                        key={log.id}
                        onClick={() => setSelectedLog(log)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                          {formatLocalTime(log.timestamp)}
                        </td>
                        <td style={{ fontFamily: 'monospace', fontWeight: 500 }}>{log.remote_addr}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'var(--surface-hover)', color: 'var(--text-secondary)' }}>{log.method}</span>
                            <span style={{ fontFamily: 'monospace', color: 'var(--accent-color)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.uri}>{log.uri}</span>
                          </div>
                        </td>
                        <td style={{ textAlign: 'center', color: log.xgb_prob >= 0.7 ? 'var(--danger-color)' : 'var(--text-secondary)' }}>
                          {(log.xgb_prob * 100).toFixed(1)}%
                        </td>
                        <td style={{ textAlign: 'center', color: log.iso_score <= -0.1 ? 'var(--warning-color)' : 'var(--text-secondary)' }}>
                          {log.iso_score.toFixed(3)}
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                            <div style={{ width: '48px', height: '6px', borderRadius: '3px', background: 'var(--surface-hover)', overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${log.threat_score * 100}%`, background: decisionColors[log.decision] }} />
                            </div>
                            <strong style={{ fontSize: '12px', color: decisionColors[log.decision] }}>{(log.threat_score * 100).toFixed(0)}%</strong>
                          </div>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <span style={{
                            display: 'inline-block',
                            padding: '3px 8px',
                            borderRadius: '12px',
                            fontSize: '11px',
                            fontWeight: 600,
                            textTransform: 'uppercase',
                            background: `${decisionColors[log.decision]}1A`,
                            color: decisionColors[log.decision],
                            border: `1px solid ${decisionColors[log.decision]}40`
                          }}>
                            {log.decision.replace('_', ' ')}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="7" style={{ padding: 0 }}>
                        {loading ? (
                          <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--text-secondary)' }}>
                            Syncing ML engine telemetry database...
                          </div>
                        ) : (
                          <NoMLEventsEmptyState />
                        )}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalLogs > size && (
              <div className="pagination-container">
                <span className="pagination-info">
                  Showing {((page - 1) * size) + 1} - {Math.min(page * size, totalLogs)} of {totalLogs} events
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    disabled={page === 1}
                    onClick={() => setPage(page - 1)}
                    className="pagination-btn"
                  >
                    Prev
                  </button>
                  <button
                    disabled={page * size >= totalLogs}
                    onClick={() => setPage(page + 1)}
                    className="pagination-btn"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      ) : (
        <>
          {/* Models Status Cards */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Brain size={18} color="var(--accent-color)" />
              <span>Supervised Model: XGBoost Classifier</span>
              <HelpText>
                XGBoost is a machine learning model trained on known attack patterns. It analyzes incoming requests and predicts the probability that they are malicious based on historical data. Higher accuracy means better threat detection.
              </HelpText>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Model Accuracy Gate</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--success-color)', marginTop: '4px' }}>
                    {modelInfo?.model_metadata?.xgboost?.accuracy ? `${(modelInfo.model_metadata.xgboost.accuracy * 100).toFixed(1)}%` : 'N/A'}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Training Samples</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                    {modelInfo?.model_metadata?.xgboost?.sample_count?.toLocaleString() || 'N/A'}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-secondary)' }}>Model Version:</span> <strong style={{ color: 'var(--text-primary)' }}>v{modelInfo?.model_metadata?.xgboost?.version || 'N/A'}</strong></div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-secondary)' }}>Last Trained:</span> <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{modelInfo?.model_metadata?.xgboost?.training_date ? formatLocalTime(modelInfo.model_metadata.xgboost.training_date) : 'N/A'}</strong></div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-secondary)' }}>Balanced Acc:</span> <strong style={{ color: 'var(--text-primary)' }}>{modelInfo?.model_metadata?.xgboost?.balanced_accuracy ? `${(modelInfo.model_metadata.xgboost.balanced_accuracy * 100).toFixed(1)}%` : 'N/A'}</strong></div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px', marginTop: '4px' }}>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>Notes:</span>
                  <p style={{ fontStyle: 'italic', fontSize: '11px', color: 'var(--text-primary)', margin: 0 }}>{modelInfo?.model_metadata?.xgboost?.notes || 'No description notes available.'}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Brain size={18} color="var(--ml-color)" />
              <span>Anomaly Detector: Isolation Forest</span>
              <HelpText>
                Isolation Forest detects unusual traffic patterns without needing labeled attack data. It identifies requests that deviate significantly from normal behavior, catching zero-day attacks and novel threats that rule-based systems might miss.
              </HelpText>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Type Classification</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--ml-color)', marginTop: '4px' }}>Unsupervised</div>
                </div>
                <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Training Samples</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                    {modelInfo?.model_metadata?.isolation_forest?.sample_count?.toLocaleString() || 'N/A'}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-secondary)' }}>Model Version:</span> <strong style={{ color: 'var(--text-primary)' }}>v{modelInfo?.model_metadata?.isolation_forest?.version || 'N/A'}</strong></div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-secondary)' }}>Last Trained:</span> <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{modelInfo?.model_metadata?.isolation_forest?.training_date ? formatLocalTime(modelInfo.model_metadata.isolation_forest.training_date) : 'N/A'}</strong></div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px', marginTop: '4px' }}>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>Notes:</span>
                  <p style={{ fontStyle: 'italic', fontSize: '11px', color: 'var(--text-primary)', margin: 0 }}>{modelInfo?.model_metadata?.isolation_forest?.notes || 'No description notes available.'}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Explainability Feature Importance & Rollback Row */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title">
              <Brain size={18} color="var(--accent-color)" />
              Explainability — Model Features Contribution
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '340px', overflowY: 'auto', paddingRight: '4px' }}>
              {featureImportance.length > 0 ? (
                featureImportance.map((item, idx) => (
                  <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-primary)' }}>
                      <span style={{ fontWeight: 500 }}>{item.feature}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 600 }}>{(item.importance * 100).toFixed(1)}%</span>
                    </div>
                    <div style={{ width: '100%', height: '8px', background: 'var(--surface-subtle)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{ width: `${item.importance * 100}%`, height: '100%', background: 'linear-gradient(90deg, var(--accent-dim), var(--accent-color))', borderRadius: '4px', boxShadow: '0 0 6px var(--accent-glow)' }}></div>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-secondary)' }}>No feature importance telemetry loaded.</div>
              )}
            </div>
          </div>

          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title">
              <Clock size={18} color="var(--accent-color)" />
              Historical Backups & Rollback Control
            </div>
            <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', maxHeight: '340px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>
                    <th style={{ padding: '10px' }}>Backup Date</th>
                    <th style={{ padding: '10px', textAlign: 'center' }}>XGB</th>
                    <th style={{ padding: '10px', textAlign: 'center' }}>ISO</th>
                    <th style={{ padding: '10px', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.length > 0 ? (
                    backups.map((bk, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                        <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>{bk.formatted_date}</td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '3px', background: bk.xgboost ? 'var(--success-bg)' : 'var(--danger-bg)', color: bk.xgboost ? 'var(--success-color)' : 'var(--danger-color)' }}>
                            {bk.xgboost ? 'Ready' : 'Missing'}
                          </span>
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '3px', background: bk.isolation_forest ? 'var(--success-bg)' : 'var(--danger-bg)', color: bk.isolation_forest ? 'var(--success-color)' : 'var(--danger-color)' }}>
                            {bk.isolation_forest ? 'Ready' : 'Missing'}
                          </span>
                        </td>
                        <td style={{ padding: '10px', textAlign: 'right' }}>
                          <button
                            disabled={rollingBack}
                            onClick={() => handleRollback(bk.timestamp)}
                            className="action-btn-inspect"
                            style={{ padding: '3px 8px', fontSize: '11px' }}
                          >
                            Rollback
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-secondary)' }}>No backups available.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Drift Monitoring History */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title">
              <AlertTriangleIcon size={18} color="var(--accent-color)" />
              Drift Monitoring
              <HelpText>Checks telemetry from the last 24h against drift thresholds (avg threat score, false-positive rate, anomaly rate) every few hours. A breach auto-triggers a retrain, tracked in the console below.</HelpText>
            </div>
            <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', maxHeight: '340px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>
                    <th style={{ padding: '10px' }}>Checked</th>
                    <th style={{ padding: '10px', textAlign: 'center' }}>Requests</th>
                    <th style={{ padding: '10px', textAlign: 'center' }}>Avg Score</th>
                    <th style={{ padding: '10px', textAlign: 'right' }}>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {driftHistory.length > 0 ? (
                    driftHistory.map((d) => (
                      <tr key={d.id} style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                        <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>{formatLocalTime(d.timestamp)}</td>
                        <td style={{ padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>{d.total_requests?.toLocaleString()}</td>
                        <td style={{ padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>{d.avg_threat_score?.toFixed(3)}</td>
                        <td style={{ padding: '10px', textAlign: 'right' }} title={d.reasons?.join('; ') || ''}>
                          <span style={{
                            fontSize: '10px', padding: '1px 6px', borderRadius: '3px',
                            background: d.drift_detected ? 'var(--danger-bg)' : 'var(--success-bg)',
                            color: d.drift_detected ? 'var(--danger-color)' : 'var(--success-color)'
                          }}>
                            {d.drift_detected ? 'Drift → Retrain' : 'Stable'}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-secondary)' }}>No drift checks recorded yet.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Retrainer Console Terminal */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div className="card-title" style={{ marginBottom: 0 }}>
                <Activity size={18} color="var(--accent-color)" />
                ML Retrainer Console Log
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Status:</span>
                <span style={{
                  padding: '2px 8px', borderRadius: '12px', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase',
                  background: retrainStatus.status === 'running' ? 'var(--warning-bg)' : retrainStatus.status === 'success' ? 'var(--success-bg)' : 'var(--bg-tertiary)',
                  color: retrainStatus.status === 'running' ? 'var(--warning-color)' : retrainStatus.status === 'success' ? 'var(--success-color)' : 'var(--text-secondary)',
                  border: retrainStatus.status === 'running' ? '1px solid rgba(255, 149, 0, 0.2)' : retrainStatus.status === 'success' ? '1px solid rgba(0, 255, 157, 0.2)' : '1px solid var(--border-color)'
                }}>
                  {retrainStatus.status}
                </span>
                <button
                  onClick={handleTriggerRetrain}
                  disabled={retrainStatus.status === 'running' || triggeringRetrain}
                  className="modal-btn primary"
                  style={{ padding: '6px 14px', borderRadius: '8px' }}
                >
                  {retrainStatus.status === 'running' ? (
                    <>
                      <Activity className="animate-spin" size={14} /> Training...
                    </>
                  ) : (
                    <>
                      <Brain size={14} /> Retrain ML Models
                    </>
                  )}
                </button>
              </div>
            </div>
            <pre style={{
              background: 'var(--bg-void)',
              color: 'var(--success-color)',
              border: '1px solid var(--border-color)',
              padding: '16px',
              borderRadius: '8px',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              maxHeight: '260px',
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all'
            }}>
              {retrainStatus.logs || "Console output empty. Trigger retraining to view log output."}
            </pre>
          </div>
        </>
      )}

      <MLLogDrawer
        log={selectedLog}
        onClose={() => setSelectedLog(null)}
        onLabelUpdate={(updated) => {
          setSelectedLog(updated);
          setLogs(prev => prev.map(l => (l.id === updated.id ? updated : l)));
        }}
        showToast={showToast}
      />
    </motion.div>
  );
}

