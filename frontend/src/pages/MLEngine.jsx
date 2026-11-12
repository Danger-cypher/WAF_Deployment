import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle as AlertTriangleIcon, Brain, Calendar, CheckCircle, Clock,
  Gauge, Globe, Lock, Play, RotateCcw, Save, Server, Settings as SettingsIcon,
  ShieldAlert, Sliders, Sparkles, Zap, RefreshCw, TrendingUp, CheckCircle2, AlertCircle,
} from 'lucide-react';
import {
  Area, Bar, CartesianGrid, Cell, ComposedChart, Pie, PieChart, Tooltip as RechartsTooltip,
  ResponsiveContainer, XAxis, YAxis,
} from 'recharts';
import {
  getMLBackups, getMLDriftHistory, getMLFeatureImportance, getMLLogs, getMLModelInfo,
  getMLRetrainStatus, getMLStats, getMLTimeline, getMLTuning, rollbackMLModel,
  simulateMLTuning, triggerMLRetrain, updateMLTuning, runMLDriftCheck, getMLRetrainHistory,
} from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import { HelpText } from '../components/Tooltip';
import { NoMLEventsEmptyState } from '../components/EmptyStates';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import MLLogDrawer from '../components/MLLogDrawer';
import { ChartTooltip } from '../components/ui';

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
  const [activeSubTab, setActiveSubTab] = useState('analytics'); // 'analytics', 'management', 'tuning'
  const [modelInfo, setModelInfo] = useState(null);
  const [retrainStatus, setRetrainStatus] = useState({ status: 'idle', logs: '' });
  const [backups, setBackups] = useState([]);
  const [featureImportance, setFeatureImportance] = useState([]);
  const [driftHistory, setDriftHistory] = useState([]);
  const [retrainHistory, setRetrainHistory] = useState([]);
  const [runningDriftCheck, setRunningDriftCheck] = useState(false);
  const [selectedDriftReport, setSelectedDriftReport] = useState(null);
  const [, setLoadingManagement] = useState(false);
  const [triggeringRetrain, setTriggeringRetrain] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);

  // Ensemble Sensitivity & Policy Tuning States
  const [tuning, setTuning] = useState({
    block_threshold: 0.85,
    rate_limit_threshold: 0.70,
    log_threshold: 0.40,
    crs_block_threshold: 4.0,
    crs_weight: 0.50,
    xgb_weight: 0.30,
    iso_weight: 0.20,
    reputation_boost_max: 0.15,
    abuseipdb_boost_max: 0.15,
    sensitivity_preset: 'balanced',
    moderate_risk_action: 'log',
    auto_retrain_schedule: 'weekly',
  });
  const [loadingTuning, setLoadingTuning] = useState(false);
  const [savingTuning, setSavingTuning] = useState(false);

  // Simulation Playground States
  const [simInput, setSimInput] = useState({
    crs_score: 2.5,
    xgb_prob: 0.75,
    iso_score: -0.35,
    redis_rep: 1,
    abuse_score: 25,
  });
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const TUNING_PRESETS = {
    aggressive: {
      name: 'Aggressive (Zero-Trust)',
      block_threshold: 0.75,
      rate_limit_threshold: 0.60,
      log_threshold: 0.30,
      crs_block_threshold: 4.0,
      crs_weight: 0.45,
      xgb_weight: 0.35,
      iso_weight: 0.20,
      reputation_boost_max: 0.20,
      abuseipdb_boost_max: 0.20,
      moderate_risk_action: 'challenge',
      description: 'Strict blocking on moderate deviations; triggers interstitial challenges for suspicious clients.',
    },
    balanced: {
      name: 'Balanced (Recommended)',
      block_threshold: 0.85,
      rate_limit_threshold: 0.70,
      log_threshold: 0.40,
      crs_block_threshold: 4.0,
      crs_weight: 0.50,
      xgb_weight: 0.30,
      iso_weight: 0.20,
      reputation_boost_max: 0.15,
      abuseipdb_boost_max: 0.15,
      moderate_risk_action: 'log',
      description: 'Standard production profile balancing active defense with benign traffic fluidity.',
    },
    permissive: {
      name: 'Conservative (Low FP)',
      block_threshold: 0.92,
      rate_limit_threshold: 0.80,
      log_threshold: 0.50,
      crs_block_threshold: 5.0,
      crs_weight: 0.55,
      xgb_weight: 0.25,
      iso_weight: 0.20,
      reputation_boost_max: 0.10,
      abuseipdb_boost_max: 0.10,
      moderate_risk_action: 'log',
      description: 'Maximizes application availability; only high-confidence attacks are actively blocked.',
    },
  };

  const applyPreset = (presetKey) => {
    const p = TUNING_PRESETS[presetKey];
    if (!p) return;
    setTuning(prev => ({
      ...prev,
      block_threshold: p.block_threshold,
      rate_limit_threshold: p.rate_limit_threshold,
      log_threshold: p.log_threshold,
      crs_block_threshold: p.crs_block_threshold,
      crs_weight: p.crs_weight,
      xgb_weight: p.xgb_weight,
      iso_weight: p.iso_weight,
      reputation_boost_max: p.reputation_boost_max,
      abuseipdb_boost_max: p.abuseipdb_boost_max,
      moderate_risk_action: p.moderate_risk_action,
      sensitivity_preset: presetKey,
    }));
  };

  const fetchTuningData = async () => {
    setLoadingTuning(true);
    try {
      const data = await getMLTuning();
      if (data && !data.error) {
        setTuning(data);
      }
    } catch (err) {
      console.error("Failed to load ML tuning:", err);
    } finally {
      setLoadingTuning(false);
    }
  };

  const handleSaveTuning = async () => {
    if (tuning.log_threshold >= tuning.rate_limit_threshold) {
      showToast("Log threshold must be lower than Rate Limit threshold.", "error");
      return;
    }
    if (tuning.rate_limit_threshold >= tuning.block_threshold) {
      showToast("Rate Limit threshold must be lower than Block threshold.", "error");
      return;
    }
    setSavingTuning(true);
    try {
      const res = await updateMLTuning(tuning);
      if (res && res.status === 'success') {
        showToast("ML ensemble tuning saved and synchronized to Redis.");
      } else {
        showToast(res?.message || "Failed to save tuning", "error");
      }
    } catch (err) {
      showToast("Failed to save ML tuning: " + (err.message || 'Error'), "error");
    } finally {
      setSavingTuning(false);
    }
  };

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      const res = await simulateMLTuning({
        crs_score: Number(simInput.crs_score),
        xgb_prob: Number(simInput.xgb_prob),
        iso_score: Number(simInput.iso_score),
        redis_rep: Number(simInput.redis_rep),
        abuse_score: Number(simInput.abuse_score),
        tuning,
      });
      if (res && !res.error) {
        setSimResult(res);
      } else {
        showToast(res?.message || "Simulation failed", "error");
      }
    } catch (err) {
      showToast("Simulation error: " + (err.message || 'Error'), "error");
    } finally {
      setSimulating(false);
    }
  };

  useEffect(() => {
    if (activeSubTab === 'tuning') {
      fetchTuningData();
    }
  }, [activeSubTab]);

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
      if (drift && !drift.error) {
        const dList = drift.data || [];
        setDriftHistory(dList);
        if (dList.length > 0 && !selectedDriftReport) {
          setSelectedDriftReport(dList[0]);
        }
      }

      const rHistory = await getMLRetrainHistory();
      if (rHistory && !rHistory.error) setRetrainHistory(rHistory.data || []);
    } catch (err) {
      console.error("Failed to load ML management data:", err);
    } finally {
      setLoadingManagement(false);
    }
  };

  const handleRunDriftCheck = async () => {
    setRunningDriftCheck(true);
    try {
      const res = await runMLDriftCheck();
      if (res && res.status === 'success') {
        showToast('Drift multi-vector analysis completed successfully.', 'success');
        if (res.report) {
          setSelectedDriftReport(res.report);
        }
        const drift = await getMLDriftHistory();
        if (drift && !drift.error) setDriftHistory(drift.data || []);
      } else {
        showToast(res?.message || 'Drift check finished with notice', 'warning');
      }
    } catch (err) {
      console.error('Failed to run drift check:', err);
      showToast('Failed to execute drift check: ' + err.message, 'error');
    } finally {
      setRunningDriftCheck(false);
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
              const rHistory = await getMLRetrainHistory();
              if (rHistory && !rHistory.error) setRetrainHistory(rHistory.data || []);
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
  const isChartHoveredRef = useRef(false);
  const pendingTimelineRef = useRef(null);

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
        const nextData = timelineData.data || [];
        setTimeline(prev => {
          if (prev.length === nextData.length && JSON.stringify(prev) === JSON.stringify(nextData)) {
            return prev;
          }
          if (isChartHoveredRef.current) {
            pendingTimelineRef.current = nextData;
            return prev;
          }
          return nextData;
        });
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
            aria-label="ML telemetry auto-refresh rate"
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
        <button 
          className={`subtab-btn ${activeSubTab === 'tuning' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('tuning')}
          style={{ padding: '6px 16px', fontSize: '13px', border: 'none', background: 'none', cursor: 'pointer', color: activeSubTab === 'tuning' ? 'var(--accent-color)' : 'var(--text-secondary)', borderBottom: activeSubTab === 'tuning' ? '2px solid var(--accent-color)' : 'none', fontWeight: 600 }}
        >
          Sensitivity & Ensemble Tuning
        </button>
      </div>

      {activeSubTab === 'analytics' && (
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

            <div
              className="chart-container"
              style={{ minHeight: '280px' }}
              onMouseEnter={() => {
                isChartHoveredRef.current = true;
              }}
              onMouseLeave={() => {
                isChartHoveredRef.current = false;
                if (pendingTimelineRef.current) {
                  setTimeline(pendingTimelineRef.current);
                  pendingTimelineRef.current = null;
                }
              }}
            >
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
                      isAnimationActive={false}
                      animationDuration={0}
                      useTranslate3d={false}
                      cursor={{ fill: 'var(--surface-hover)', stroke: 'var(--surface-strong)', strokeWidth: 1, strokeDasharray: '3 3' }}
                      content={
                        <ChartTooltip
                          labelFormatter={(l) => {
                            if (!l) return '';
                            try {
                              const parts = String(l).split(' ');
                              return parts.length > 1 ? parts[1].slice(0, 5) : String(l);
                            } catch {
                              return String(l);
                            }
                          }}
                          valueFormatter={(value, name) =>
                            name === 'avg_score' || name === 'Avg Threat'
                              ? `${(Number(value) * 100).toFixed(1)}%`
                              : Number(value).toLocaleString()
                          }
                        />
                      }
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
                      isAnimationActive={false}
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
                      isAnimationActive={false}
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
                      isAnimationActive={false}
                    >
                      {displayPieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      content={
                        <ChartTooltip
                          valueFormatter={(value) => `${Number(value).toLocaleString()} actions`}
                        />
                      }
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
                  aria-label="Search evaluated ML logs by URI or IP"
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
                  aria-label="Filter evaluated ML logs by decision"
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
                          {(log.iso_score ?? 0).toFixed(3)}
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
      )}

      {activeSubTab === 'management' && (
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

          {/* Multi-Vector Behavioral Drift & Anomaly Profiling (Phase 3.3) */}
          {(() => {
            const activeDrift = selectedDriftReport || (driftHistory.length > 0 ? driftHistory[0] : null);
            const vm = activeDrift?.vector_metrics || {};
            const vMap = vm.vectors || {};
            const overallStatus = vm.status || (activeDrift?.drift_detected ? 'breached' : 'nominal');
            const endpoints = vm.top_drifting_endpoints || [];

            return (
              <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div className="card-title" style={{ marginBottom: 0 }}>
                      <AlertTriangleIcon size={18} color="var(--accent-color)" />
                      <span>Behavioral Drift Multi-Vector Profiling & Health Assessment</span>
                    </div>
                    <span style={{
                      padding: '3px 10px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      background: overallStatus === 'breached' ? 'var(--danger-bg)' : overallStatus === 'warning' ? 'var(--warning-bg)' : 'var(--success-bg)',
                      color: overallStatus === 'breached' ? 'var(--danger-color)' : overallStatus === 'warning' ? 'var(--warning-color)' : 'var(--success-color)',
                      border: `1px solid ${overallStatus === 'breached' ? 'var(--danger-color)' : overallStatus === 'warning' ? 'var(--warning-color)' : 'var(--success-color)'}`,
                    }}>
                      {overallStatus === 'breached' ? 'Drift Breached (Retrain Due/Triggered)' : overallStatus === 'warning' ? 'Drift Warning (Approaching Baseline)' : 'Nominal Baseline (Telemetry Stable)'}
                    </span>
                    <HelpText>
                      Monitors statistical drift across five independent behavioral vectors (threat score baseline, attack confidence, novelty anomaly, analyst feedback, and CRS score elevation). Breaches trigger automated retraining according to policy.
                    </HelpText>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {activeDrift?.timestamp && (
                      <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                        Inspected: {formatLocalTime(activeDrift.timestamp)} ({activeDrift.total_requests?.toLocaleString() || 0} reqs)
                      </span>
                    )}
                    <button
                      onClick={handleRunDriftCheck}
                      disabled={runningDriftCheck}
                      className="modal-btn"
                      style={{ padding: '6px 14px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}
                    >
                      <RefreshCw size={13} className={runningDriftCheck ? 'animate-spin' : ''} />
                      {runningDriftCheck ? 'Analyzing...' : 'Run Drift Analysis Now'}
                    </button>
                  </div>
                </div>

                {/* Vector Metrics Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                  {/* Vector 1: Threat Score Baseline */}
                  <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>Threat Score Baseline</span>
                      <span style={{
                        fontSize: '9px', padding: '1px 5px', borderRadius: '3px', fontWeight: 600, textTransform: 'uppercase',
                        background: vMap.threat_score?.status === 'breached' ? 'var(--danger-bg)' : vMap.threat_score?.status === 'warning' ? 'var(--warning-bg)' : 'var(--success-bg)',
                        color: vMap.threat_score?.status === 'breached' ? 'var(--danger-color)' : vMap.threat_score?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)'
                      }}>
                        {vMap.threat_score?.status || 'nominal'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                      <span style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {(vMap.threat_score?.current ?? (activeDrift?.avg_threat_score || 0)).toFixed(3)}
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>/ {vMap.threat_score?.threshold ?? 0.60}</span>
                    </div>
                    <div style={{ width: '100%', height: '6px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, ((vMap.threat_score?.current ?? (activeDrift?.avg_threat_score || 0)) / (vMap.threat_score?.threshold || 0.60)) * 100)}%`,
                        height: '100%',
                        background: vMap.threat_score?.status === 'breached' ? 'var(--danger-color)' : vMap.threat_score?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)',
                      }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)' }}>
                      <span>Baseline: 0.35</span>
                      <span>Cutoff: &gt;0.60</span>
                    </div>
                  </div>

                  {/* Vector 2: XGBoost Attack Anomaly */}
                  <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>XGBoost Attack Drift</span>
                      <span style={{
                        fontSize: '9px', padding: '1px 5px', borderRadius: '3px', fontWeight: 600, textTransform: 'uppercase',
                        background: vMap.xgb_anomaly?.status === 'breached' ? 'var(--danger-bg)' : vMap.xgb_anomaly?.status === 'warning' ? 'var(--warning-bg)' : 'var(--success-bg)',
                        color: vMap.xgb_anomaly?.status === 'breached' ? 'var(--danger-color)' : vMap.xgb_anomaly?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)'
                      }}>
                        {vMap.xgb_anomaly?.status || 'nominal'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                      <span style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {((vMap.xgb_anomaly?.current ?? (activeDrift?.xgb_anomaly_rate || 0)) * 100).toFixed(1)}%
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>/ 25.0%</span>
                    </div>
                    <div style={{ width: '100%', height: '6px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, ((vMap.xgb_anomaly?.current ?? (activeDrift?.xgb_anomaly_rate || 0)) / 0.25) * 100)}%`,
                        height: '100%',
                        background: vMap.xgb_anomaly?.status === 'breached' ? 'var(--danger-color)' : vMap.xgb_anomaly?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)',
                      }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)' }}>
                      <span>Baseline: 10%</span>
                      <span>Cutoff: &gt;25%</span>
                    </div>
                  </div>

                  {/* Vector 3: Isolation Forest Novelty */}
                  <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>Novelty / Outlier Vector</span>
                      <span style={{
                        fontSize: '9px', padding: '1px 5px', borderRadius: '3px', fontWeight: 600, textTransform: 'uppercase',
                        background: vMap.iso_novelty?.status === 'breached' ? 'var(--danger-bg)' : vMap.iso_novelty?.status === 'warning' ? 'var(--warning-bg)' : 'var(--success-bg)',
                        color: vMap.iso_novelty?.status === 'breached' ? 'var(--danger-color)' : vMap.iso_novelty?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)'
                      }}>
                        {vMap.iso_novelty?.status || 'nominal'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                      <span style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {((vMap.iso_novelty?.current ?? (activeDrift?.iso_anomaly_rate || 0)) * 100).toFixed(1)}%
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>/ 20.0%</span>
                    </div>
                    <div style={{ width: '100%', height: '6px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, ((vMap.iso_novelty?.current ?? (activeDrift?.iso_anomaly_rate || 0)) / 0.20) * 100)}%`,
                        height: '100%',
                        background: vMap.iso_novelty?.status === 'breached' ? 'var(--danger-color)' : vMap.iso_novelty?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)',
                      }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)' }}>
                      <span>Baseline: 10%</span>
                      <span>Cutoff: &gt;20%</span>
                    </div>
                  </div>

                  {/* Vector 4: Analyst FP Feedback */}
                  <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>Analyst FP Feedback</span>
                      <span style={{
                        fontSize: '9px', padding: '1px 5px', borderRadius: '3px', fontWeight: 600, textTransform: 'uppercase',
                        background: vMap.false_positive?.status === 'breached' ? 'var(--danger-bg)' : vMap.false_positive?.status === 'warning' ? 'var(--warning-bg)' : 'var(--success-bg)',
                        color: vMap.false_positive?.status === 'breached' ? 'var(--danger-color)' : vMap.false_positive?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)'
                      }}>
                        {vMap.false_positive?.status || 'nominal'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                      <span style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {((vMap.false_positive?.current ?? (activeDrift?.xgb_fp_rate || 0)) * 100).toFixed(1)}%
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>/ 15.0%</span>
                    </div>
                    <div style={{ width: '100%', height: '6px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, ((vMap.false_positive?.current ?? (activeDrift?.xgb_fp_rate || 0)) / 0.15) * 100)}%`,
                        height: '100%',
                        background: vMap.false_positive?.status === 'breached' ? 'var(--danger-color)' : vMap.false_positive?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)',
                      }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)' }}>
                      <span>Baseline: 3%</span>
                      <span>Cutoff: &gt;15%</span>
                    </div>
                  </div>

                  {/* Vector 5: CRS Anomaly Elevation */}
                  <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>CRS Score Elevation</span>
                      <span style={{
                        fontSize: '9px', padding: '1px 5px', borderRadius: '3px', fontWeight: 600, textTransform: 'uppercase',
                        background: vMap.crs_anomaly?.status === 'breached' ? 'var(--danger-bg)' : vMap.crs_anomaly?.status === 'warning' ? 'var(--warning-bg)' : 'var(--success-bg)',
                        color: vMap.crs_anomaly?.status === 'breached' ? 'var(--danger-color)' : vMap.crs_anomaly?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)'
                      }}>
                        {vMap.crs_anomaly?.status || 'nominal'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                      <span style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {((vMap.crs_anomaly?.current ?? 0) * 100).toFixed(1)}%
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>/ 25.0%</span>
                    </div>
                    <div style={{ width: '100%', height: '6px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, ((vMap.crs_anomaly?.current ?? 0) / 0.25) * 100)}%`,
                        height: '100%',
                        background: vMap.crs_anomaly?.status === 'breached' ? 'var(--danger-color)' : vMap.crs_anomaly?.status === 'warning' ? 'var(--warning-color)' : 'var(--success-color)',
                      }} />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)' }}>
                      <span>Baseline: 8%</span>
                      <span>Cutoff: &gt;25%</span>
                    </div>
                  </div>
                </div>

                {/* Top Drifting Endpoints & Breach Reasons Row */}
                {(activeDrift?.reasons?.length > 0 || endpoints.length > 0) && (
                  <div style={{ display: 'grid', gridTemplateColumns: activeDrift?.reasons?.length > 0 && endpoints.length > 0 ? '1fr 1fr' : '1fr', gap: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
                    {activeDrift?.reasons?.length > 0 && (
                      <div style={{ background: 'var(--danger-bg)', border: '1px solid rgba(255, 69, 58, 0.2)', borderRadius: '6px', padding: '10px 14px' }}>
                        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--danger-color)', marginBottom: '4px' }}>
                          Breach Triggers Detected:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-primary)' }}>
                          {activeDrift.reasons.map((r, i) => (
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {endpoints.length > 0 && (
                      <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px' }}>
                        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                          Top Drifting URIs by Average Threat Score:
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                          {endpoints.map((ep, i) => (
                            <span key={i} style={{
                              fontSize: '11px', padding: '2px 8px', borderRadius: '4px',
                              background: 'var(--surface-subtle)', border: '1px solid var(--border-color)',
                              fontFamily: 'var(--font-mono)', color: 'var(--text-primary)',
                              display: 'inline-flex', alignItems: 'center', gap: '6px'
                            }}>
                              <span>{ep.uri}</span>
                              <strong style={{ color: ep.avg_threat > 0.6 ? 'var(--danger-color)' : 'var(--warning-color)' }}>
                                {ep.avg_threat.toFixed(2)}
                              </strong>
                              <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>({ep.count})</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })()}

          {/* Drift Monitoring History & Automated Retraining Audit Row (Phase 3.3 & 3.4) */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title">
              <AlertTriangleIcon size={18} color="var(--accent-color)" />
              Drift Check Telemetry History
              <HelpText>Periodic and on-demand drift evaluations. Click any row to inspect its multi-vector metrics in the profiling panel above.</HelpText>
            </div>
            <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', maxHeight: '320px' }}>
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
                    driftHistory.map((d) => {
                      const isSelected = selectedDriftReport?.id === d.id;
                      return (
                        <tr
                          key={d.id}
                          onClick={() => setSelectedDriftReport(d)}
                          style={{
                            borderBottom: '1px solid var(--border-subtle)',
                            color: 'var(--text-primary)',
                            cursor: 'pointer',
                            background: isSelected ? 'var(--surface-subtle)' : 'transparent',
                          }}
                        >
                          <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>
                            {formatLocalTime(d.timestamp)}
                          </td>
                          <td style={{ padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>{d.total_requests?.toLocaleString()}</td>
                          <td style={{ padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>{d.avg_threat_score?.toFixed(3)}</td>
                          <td style={{ padding: '10px', textAlign: 'right' }} title={d.reasons?.join('; ') || ''}>
                            <span style={{
                              fontSize: '10px', padding: '1px 6px', borderRadius: '3px',
                              background: d.drift_detected ? 'var(--danger-bg)' : 'var(--success-bg)',
                              color: d.drift_detected ? 'var(--danger-color)' : 'var(--success-color)'
                            }}>
                              {d.drift_detected ? 'Drift Breach' : 'Stable'}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-secondary)' }}>No drift checks recorded yet.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Automated Retraining Audit Trail (Phase 3.4) */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="card-title">
              <Calendar size={18} color="var(--accent-color)" />
              Automated Retraining Execution History
              <HelpText>Audit log of model retraining runs triggered manually, via drift breaches, or via scheduled intervals.</HelpText>
            </div>
            <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', maxHeight: '320px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>
                    <th style={{ padding: '10px' }}>Executed</th>
                    <th style={{ padding: '10px' }}>Trigger</th>
                    <th style={{ padding: '10px', textAlign: 'center' }}>Duration</th>
                    <th style={{ padding: '10px', textAlign: 'center' }}>Accuracy</th>
                    <th style={{ padding: '10px', textAlign: 'right' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {retrainHistory.length > 0 ? (
                    retrainHistory.map((rh) => (
                      <tr key={rh.id} style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                        <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {formatLocalTime(rh.timestamp)}
                        </td>
                        <td style={{ padding: '10px' }}>
                          <span style={{
                            fontSize: '10px', padding: '1px 6px', borderRadius: '3px',
                            background: rh.trigger_type?.startsWith('drift') ? 'var(--warning-bg)' : rh.trigger_type?.startsWith('scheduled') ? 'var(--surface-subtle)' : 'var(--bg-tertiary)',
                            color: rh.trigger_type?.startsWith('drift') ? 'var(--warning-color)' : 'var(--text-primary)',
                            border: '1px solid var(--border-subtle)',
                          }} title={rh.trigger_details || ''}>
                            {rh.trigger_type === 'drift_breach' ? 'Drift Breach' : rh.trigger_type === 'manual' ? 'Manual' : rh.trigger_type}
                          </span>
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                          {rh.duration_seconds ? `${rh.duration_seconds.toFixed(1)}s` : 'N/A'}
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                          {rh.accuracy ? `${(rh.accuracy * 100).toFixed(1)}%` : 'N/A'}
                        </td>
                        <td style={{ padding: '10px', textAlign: 'right' }}>
                          <span style={{
                            fontSize: '10px', padding: '1px 6px', borderRadius: '3px',
                            background: rh.status === 'success' ? 'var(--success-bg)' : 'var(--danger-bg)',
                            color: rh.status === 'success' ? 'var(--success-color)' : 'var(--danger-color)',
                          }}>
                            {rh.status === 'success' ? 'Success' : 'Failed'}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-secondary)' }}>
                        No execution records logged yet. Retraining history will populate after the next training run.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Retrainer Console Terminal */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div className="card-title" style={{ marginBottom: '2px' }}>
                  <Activity size={18} color="var(--accent-color)" />
                  ML Retrainer Console Log
                </div>
                {retrainStatus.trigger_details && (
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Trigger reason: <strong style={{ color: 'var(--text-primary)' }}>{retrainStatus.trigger_details}</strong>
                  </div>
                )}
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

      {activeSubTab === 'tuning' && (
        <>
          {/* Preset Selector Card */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <Sliders size={18} color="var(--accent-color)" />
                  <span>Ensemble Sensitivity & Threat Policy Tuning</span>
                  <HelpText>
                    Tune the multi-signal AI ensemble without taking down the WAF. Changes synchronize instantly to Redis and are evaluated in real time by the Lua & Python ML inspection pipeline.
                  </HelpText>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Select a recommended posture preset or manually calibrate component weights and threshold cutoffs.
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                <button
                  type="button"
                  className="modal-btn"
                  onClick={() => applyPreset('balanced')}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 12px' }}
                >
                  <RotateCcw size={14} /> Reset Defaults
                </button>
                <button
                  type="button"
                  className="modal-btn primary"
                  disabled={savingTuning}
                  onClick={handleSaveTuning}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', padding: '6px 16px' }}
                >
                  <Save size={14} /> {savingTuning ? 'Synchronizing...' : 'Save & Sync Policy'}
                </button>
              </div>
            </div>

            {/* Quick Presets Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
              {Object.entries(TUNING_PRESETS).map(([key, p]) => {
                const isSelected = tuning.sensitivity_preset === key;
                return (
                  <div
                    key={key}
                    onClick={() => applyPreset(key)}
                    style={{
                      background: isSelected ? 'var(--accent-bg, rgba(56, 189, 248, 0.08))' : 'var(--bg-tertiary)',
                      border: `1.5px solid ${isSelected ? 'var(--accent-color)' : 'var(--border-color)'}`,
                      borderRadius: '8px',
                      padding: '12px 14px',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 600, fontSize: '13px', color: isSelected ? 'var(--accent-color)' : 'var(--text-primary)' }}>
                        {p.name}
                      </span>
                      {isSelected && <CheckCircle size={14} color="var(--accent-color)" />}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                      {p.description}
                    </div>
                    <div style={{ display: 'flex', gap: '8px', fontSize: '11px', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: 'var(--danger-color)' }}>Block ≥ {(p.block_threshold * 100).toFixed(0)}%</span>
                      <span style={{ color: 'var(--warning-color)' }}>Rate ≥ {(p.rate_limit_threshold * 100).toFixed(0)}%</span>
                      <span style={{ color: 'var(--sev-low)' }}>Log ≥ {(p.log_threshold * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Decision Cutoff Thresholds Card */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Gauge size={18} color="var(--accent-color)" />
              <span>Graduated Decision Cutoff Thresholds</span>
              <HelpText>
                Calculated combined threat scores fall between 0.0 (benign) and 1.0 (critical attack). Configure where traffic transitions between Allow, Monitor, Throttle, and Hard Block.
              </HelpText>
            </div>

            {/* Visual Colored Threat Zone Range Bar */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                <span>0.00 (Benign)</span>
                <span>Combined Threat Score (0.00 - 1.00)</span>
                <span>1.00 (Critical)</span>
              </div>
              <div style={{ height: '14px', width: '100%', borderRadius: '7px', display: 'flex', overflow: 'hidden', border: '1px solid var(--border-color)' }}>
                <div style={{ width: `${Math.max(0, tuning.log_threshold) * 100}%`, background: 'var(--success-color)' }} title="Allow Band" />
                <div style={{ width: `${Math.max(0, tuning.rate_limit_threshold - tuning.log_threshold) * 100}%`, background: 'var(--sev-low)' }} title="Log / Monitor Band" />
                <div style={{ width: `${Math.max(0, tuning.block_threshold - tuning.rate_limit_threshold) * 100}%`, background: 'var(--warning-color)' }} title="Rate Limit Band" />
                <div style={{ width: `${Math.max(0, 1.0 - tuning.block_threshold) * 100}%`, background: 'var(--danger-color)' }} title="Hard Block Band" />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginTop: '2px', flexWrap: 'wrap', gap: '6px' }}>
                <span style={{ color: 'var(--success-color)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--success-color)' }} />
                  Allow (0 - {(tuning.log_threshold * 100).toFixed(0)}%)
                </span>
                <span style={{ color: 'var(--sev-low)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--sev-low)' }} />
                  Log ({(tuning.log_threshold * 100).toFixed(0)} - {(tuning.rate_limit_threshold * 100).toFixed(0)}%)
                </span>
                <span style={{ color: 'var(--warning-color)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--warning-color)' }} />
                  Rate Limit ({(tuning.rate_limit_threshold * 100).toFixed(0)} - {(tuning.block_threshold * 100).toFixed(0)}%)
                </span>
                <span style={{ color: 'var(--danger-color)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--danger-color)' }} />
                  Block (≥ {(tuning.block_threshold * 100).toFixed(0)}%)
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '8px' }}>
              {/* Block Threshold Slider */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Hard Block Threshold</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--danger-color)', fontWeight: 700 }}>
                    {(tuning.block_threshold * 100).toFixed(0)}% ({tuning.block_threshold.toFixed(2)})
                  </span>
                </div>
                <input
                  type="range"
                  min="0.50"
                  max="0.99"
                  step="0.01"
                  value={tuning.block_threshold}
                  onChange={(e) => {
                    const v = parseFloat(e.target.value);
                    setTuning(prev => ({
                      ...prev,
                      block_threshold: v,
                      rate_limit_threshold: Math.min(prev.rate_limit_threshold, v - 0.02),
                      log_threshold: Math.min(prev.log_threshold, v - 0.05),
                      sensitivity_preset: 'custom',
                    }));
                  }}
                  style={{ width: '100%', accentColor: 'var(--danger-color)', cursor: 'pointer' }}
                />
              </div>

              {/* Rate Limit Threshold Slider */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Rate Limit / Throttle Threshold</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warning-color)', fontWeight: 700 }}>
                    {(tuning.rate_limit_threshold * 100).toFixed(0)}% ({tuning.rate_limit_threshold.toFixed(2)})
                  </span>
                </div>
                <input
                  type="range"
                  min="0.25"
                  max="0.95"
                  step="0.01"
                  value={tuning.rate_limit_threshold}
                  onChange={(e) => {
                    const v = parseFloat(e.target.value);
                    setTuning(prev => ({
                      ...prev,
                      rate_limit_threshold: v,
                      block_threshold: Math.max(prev.block_threshold, v + 0.02),
                      log_threshold: Math.min(prev.log_threshold, v - 0.02),
                      sensitivity_preset: 'custom',
                    }));
                  }}
                  style={{ width: '100%', accentColor: 'var(--warning-color)', cursor: 'pointer' }}
                />
              </div>

              {/* Log Threshold Slider */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Monitor / Log Threshold</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--sev-low)', fontWeight: 700 }}>
                    {(tuning.log_threshold * 100).toFixed(0)}% ({tuning.log_threshold.toFixed(2)})
                  </span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.80"
                  step="0.01"
                  value={tuning.log_threshold}
                  onChange={(e) => {
                    const v = parseFloat(e.target.value);
                    setTuning(prev => ({
                      ...prev,
                      log_threshold: v,
                      rate_limit_threshold: Math.max(prev.rate_limit_threshold, v + 0.02),
                      block_threshold: Math.max(prev.block_threshold, v + 0.05),
                      sensitivity_preset: 'custom',
                    }));
                  }}
                  style={{ width: '100%', accentColor: 'var(--sev-low)', cursor: 'pointer' }}
                />
              </div>

              {/* Moderate Risk Action Dropdown */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', gap: '12px' }}>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>Moderate Risk Action (Log Band)</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Action to execute when traffic falls into the monitor range</div>
                </div>
                <select
                  value={tuning.moderate_risk_action}
                  onChange={(e) => setTuning(prev => ({ ...prev, moderate_risk_action: e.target.value, sensitivity_preset: 'custom' }))}
                  className="filter-select"
                  style={{ minWidth: '150px' }}
                >
                  <option value="log">Log Only (Passive)</option>
                  <option value="challenge">Challenge Interstitial</option>
                  <option value="rate_limit">Rate Limit</option>
                </select>
              </div>

              {/* CRS Critical Override Threshold */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px', gap: '12px' }}>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>CRS Anomaly Hard Override</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Immediate block if raw CRS score reaches this cutoff</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <input
                    type="number"
                    min="1"
                    max="10"
                    step="0.5"
                    value={tuning.crs_block_threshold}
                    onChange={(e) => setTuning(prev => ({ ...prev, crs_block_threshold: parseFloat(e.target.value) || 4.0, sensitivity_preset: 'custom' }))}
                    className="filter-input"
                    style={{ width: '80px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}
                  />
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>pts</span>
                </div>
              </div>
            </div>
          </div>

          {/* Model Weights & Retraining Card */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 6', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={18} color="var(--accent-color)" />
              <span>Ensemble Component Weights & Feedback</span>
              <HelpText>
                Adjust the contribution of each detection mechanism. Weights are automatically normalized to form the composite base score.
              </HelpText>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* CRS Weight */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>OWASP CRS Rules Anomaly Score Weight</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 700 }}>
                    {(tuning.crs_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={tuning.crs_weight}
                  onChange={(e) => setTuning(prev => ({ ...prev, crs_weight: parseFloat(e.target.value), sensitivity_preset: 'custom' }))}
                  style={{ width: '100%', accentColor: 'var(--accent-color)', cursor: 'pointer' }}
                />
              </div>

              {/* XGBoost Weight */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Supervised XGBoost Threat Probability Weight</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 700 }}>
                    {(tuning.xgb_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={tuning.xgb_weight}
                  onChange={(e) => setTuning(prev => ({ ...prev, xgb_weight: parseFloat(e.target.value), sensitivity_preset: 'custom' }))}
                  style={{ width: '100%', accentColor: 'var(--accent-color)', cursor: 'pointer' }}
                />
              </div>

              {/* Isolation Forest Weight */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Isolation Forest Zero-Day Anomaly Weight</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 700 }}>
                    {(tuning.iso_weight * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={tuning.iso_weight}
                  onChange={(e) => setTuning(prev => ({ ...prev, iso_weight: parseFloat(e.target.value), sensitivity_preset: 'custom' }))}
                  style={{ width: '100%', accentColor: 'var(--accent-color)', cursor: 'pointer' }}
                />
              </div>

              {/* Reputation Boost Max Caps */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Max Redis Rep Boost</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
                    <input
                      type="number"
                      min="0.0"
                      max="0.40"
                      step="0.01"
                      value={tuning.reputation_boost_max}
                      onChange={(e) => setTuning(prev => ({ ...prev, reputation_boost_max: parseFloat(e.target.value) || 0.15 }))}
                      className="filter-input"
                      style={{ width: '70px', fontFamily: 'var(--font-mono)' }}
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>({(tuning.reputation_boost_max * 100).toFixed(0)}% max)</span>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Max AbuseIPDB Boost</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
                    <input
                      type="number"
                      min="0.0"
                      max="0.40"
                      step="0.01"
                      value={tuning.abuseipdb_boost_max}
                      onChange={(e) => setTuning(prev => ({ ...prev, abuseipdb_boost_max: parseFloat(e.target.value) || 0.15 }))}
                      className="filter-input"
                      style={{ width: '70px', fontFamily: 'var(--font-mono)' }}
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>({(tuning.abuseipdb_boost_max * 100).toFixed(0)}% max)</span>
                  </div>
                </div>
              </div>

              {/* Automated Retraining Schedule */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>Automated Model Retraining Schedule</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Periodic background retraining on ClickHouse telemetry</div>
                </div>
                <select
                  value={tuning.auto_retrain_schedule}
                  onChange={(e) => setTuning(prev => ({ ...prev, auto_retrain_schedule: e.target.value }))}
                  className="filter-select"
                  style={{ minWidth: '150px' }}
                >
                  <option value="weekly">Weekly (Sundays 02:00 UTC)</option>
                  <option value="monthly">Monthly (1st at 02:00 UTC)</option>
                  <option value="drift_only">On Drift Breach Only</option>
                  <option value="disabled">Manual Retraining Only</option>
                </select>
              </div>
            </div>
          </div>

          {/* Real-Time Decision Simulator Playground */}
          <div className="chart-card glass-panel" style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sparkles size={18} color="var(--accent-color)" />
              <span>Interactive Decision Matrix & Simulator Playground</span>
              <HelpText>
                Simulate how specific payload scores evaluate against your active or pending policy before applying changes to live traffic.
              </HelpText>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>CRS Score (0 - 20)</label>
                <input
                  type="number"
                  min="0"
                  max="20"
                  step="0.5"
                  value={simInput.crs_score}
                  onChange={(e) => setSimInput(prev => ({ ...prev, crs_score: parseFloat(e.target.value) || 0 }))}
                  className="filter-input"
                  style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>XGBoost Prob (0.0 - 1.0)</label>
                <input
                  type="number"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={simInput.xgb_prob}
                  onChange={(e) => setSimInput(prev => ({ ...prev, xgb_prob: parseFloat(e.target.value) || 0 }))}
                  className="filter-input"
                  style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>Isolation Score (-0.5 - 0.5)</label>
                <input
                  type="number"
                  min="-0.5"
                  max="0.5"
                  step="0.05"
                  value={simInput.iso_score}
                  onChange={(e) => setSimInput(prev => ({ ...prev, iso_score: parseFloat(e.target.value) || 0 }))}
                  className="filter-input"
                  style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>IP Offenses in Redis</label>
                <input
                  type="number"
                  min="0"
                  max="20"
                  value={simInput.redis_rep}
                  onChange={(e) => setSimInput(prev => ({ ...prev, redis_rep: parseInt(e.target.value, 10) || 0 }))}
                  className="filter-input"
                  style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>AbuseIPDB Conf (0 - 100%)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={simInput.abuse_score}
                  onChange={(e) => setSimInput(prev => ({ ...prev, abuse_score: parseFloat(e.target.value) || 0 }))}
                  className="filter-input"
                  style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button
                  type="button"
                  className="modal-btn primary"
                  disabled={simulating}
                  onClick={handleSimulate}
                  style={{ width: '100%', height: '36px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '6px' }}
                >
                  <Play size={14} /> {simulating ? 'Evaluating...' : 'Simulate Decision'}
                </button>
              </div>
            </div>

            {simResult && (
              <div
                style={{
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '8px',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                  marginTop: '8px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Calculated Action:</div>
                    <span
                      style={{
                        padding: '4px 12px',
                        borderRadius: '6px',
                        fontWeight: 700,
                        fontSize: '12px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        background:
                          simResult.decision === 'block' ? 'var(--danger-bg)' :
                          simResult.decision === 'rate_limit' ? 'var(--warning-bg)' :
                          simResult.decision === 'challenge' ? 'var(--warning-bg)' :
                          simResult.decision === 'log' ? 'rgba(56, 189, 248, 0.15)' :
                          'var(--success-bg)',
                        color:
                          simResult.decision === 'block' ? 'var(--danger-color)' :
                          simResult.decision === 'rate_limit' ? 'var(--warning-color)' :
                          simResult.decision === 'challenge' ? 'var(--warning-color)' :
                          simResult.decision === 'log' ? 'var(--accent-color)' :
                          'var(--success-color)',
                        border: `1px solid ${
                          simResult.decision === 'block' ? 'var(--danger-color)' :
                          simResult.decision === 'rate_limit' ? 'var(--warning-color)' :
                          simResult.decision === 'challenge' ? 'var(--warning-color)' :
                          simResult.decision === 'log' ? 'var(--accent-color)' :
                          'var(--success-color)'
                        }`,
                      }}
                    >
                      {simResult.decision.replace('_', ' ')}
                    </span>
                    <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Threat Score:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', fontWeight: 700, color: 'var(--accent-color)' }}>
                      {(simResult.threat_score.total * 100).toFixed(1)}% ({simResult.threat_score.total.toFixed(3)})
                    </span>
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                    {simResult.reason}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px', fontSize: '11px' }}>
                  <div>
                    <span style={{ color: 'var(--text-secondary)' }}>CRS Normalized: </span>
                    <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{(simResult.threat_score.crs * 100).toFixed(1)}%</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-secondary)' }}>XGBoost Probability: </span>
                    <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{(simResult.threat_score.xgb * 100).toFixed(1)}%</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-secondary)' }}>Isolation Anomaly: </span>
                    <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{(simResult.threat_score.iso * 100).toFixed(1)}%</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-secondary)' }}>Reputation Boost: </span>
                    <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>+{(simResult.threat_score.reputation * 100).toFixed(1)}%</strong>
                  </div>
                </div>
              </div>
            )}
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

