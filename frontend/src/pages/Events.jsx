import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, ChevronLeft, ChevronRight, Code, FileText, Globe, Search, ShieldCheck } from 'lucide-react';
import { getLogs, getGeneralSettings } from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import LogDetailsModal from '../components/LogDetailsModal';
import { NoLogsEmptyState, NoSearchResultsEmptyState } from '../components/EmptyStates';

export default function LiveLogs({ onMarkFalsePositive }) {
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
