import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion } from 'framer-motion';
import { Activity, ChevronLeft, ChevronRight, Code, FileText, Globe, Layers, Search, ShieldCheck } from 'lucide-react';
import { getLogs, getGroupedLogs, getGeneralSettings } from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import LogDetailsModal from '../components/LogDetailsModal';
import { NoLogsEmptyState, NoSearchResultsEmptyState } from '../components/EmptyStates';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';

export default function LiveLogs({ onMarkFalsePositive, onCreateRule, initialSearch, initialSeverity, initialAttackType, onConsumeInitialSearch }) {
  const { toast, showToast } = useToast();
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
  // Seeded once from the command palette's IP search, or from clicking a
  // segment on Overview's Attack Vectors / Threat Severity charts, if
  // that's how this page was reached (App.jsx remounts this component on
  // every tab switch, so this only ever applies at that first mount).
  const [search, setSearch] = useState(initialSearch || '');
  const [severityFilter, setSeverityFilter] = useState(initialSeverity || '');
  const [attackFilter, setAttackFilter] = useState(initialAttackType || '');

  useEffect(() => {
    if (initialSearch || initialSeverity || initialAttackType) onConsumeInitialSearch?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [trafficTab, setTrafficTab] = useState('all');
  const [focusMode, setFocusMode] = useState(false);
  const [sortField, setSortField] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');
  const [selectedLog, setSelectedLog] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [expandedLogs, setExpandedLogs] = useState(new Set());

  // Whichever list the currently-open drawer's row came from (the flat
  // timeline, or one group's drill-down events) — lets Up/Down in
  // LogDetailsModal step through the same rows the analyst was scanning,
  // without caring which table they opened it from.
  const [activeLogList, setActiveLogList] = useState([]);
  const [activeLogIndex, setActiveLogIndex] = useState(-1);

  const openLogDetails = (list, index) => {
    setActiveLogList(list);
    setActiveLogIndex(index);
    setSelectedLog(list[index]);
    setIsModalOpen(true);
  };

  const handleNavigateLog = (direction) => {
    setActiveLogIndex((prevIndex) => {
      const nextIndex = direction === 'next' ? prevIndex + 1 : prevIndex - 1;
      if (nextIndex < 0 || nextIndex >= activeLogList.length) return prevIndex;
      setSelectedLog(activeLogList[nextIndex]);
      return nextIndex;
    });
  };

  // Grouped ("collapse repeats by IP+Rule") view — opt-in alongside the
  // default flat timeline. See backend query_waf_events_grouped().
  const [viewMode, setViewMode] = useState('flat'); // 'flat' | 'grouped'
  const [groupedLogs, setGroupedLogs] = useState([]);
  const [groupedTotal, setGroupedTotal] = useState(0);
  // Per-group drill-down state, keyed by `${client_ip}::${rule_id}`.
  const [expandedGroups, setExpandedGroups] = useState({});
  const [exporting, setExporting] = useState(false);

  const toggleFocusMode = () => {
    setFocusMode(prev => {
      const next = !prev;
      // When enabling, clear the severity dropdown and let min_severity handle it
      if (next) setSeverityFilter('');
      return next;
    });
  };

  // Shared with fetchLogs() below — kept as one function so the export and
  // the live table can never silently drift on what a given filter means.
  const buildFilters = () => {
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
    return filters;
  };

  // Exports the FULL filtered result set, not just the current page — a
  // page-sized export silently under-reports on any filtered view larger
  // than one page, which is exactly the situation an analyst pulling an
  // incident report is usually in. Capped at 3000 rows (the backend's own
  // per-request ceiling on `size`) since a bigger single export would need
  // real multi-request pagination.
  const EXPORT_ROW_CAP = 3000;

  const handleExportReport = async () => {
    const totalToExport = viewMode === 'grouped' ? groupedTotal : total;
    if (!totalToExport) {
      showToast('No log data available to export. Please wait for data to load.', 'error');
      return;
    }
    setExporting(true);
    try {
      const filters = buildFilters();
      const exportSize = Math.min(totalToExport, EXPORT_ROW_CAP);
      const dateStr = new Date().toISOString().split('T')[0];
      const tabLabel = trafficTab === 'all' ? 'all' : trafficTab === 'api' ? 'api' : 'web';

      let csv;
      let filenameSuffix;
      if (viewMode === 'grouped') {
        const result = await getGroupedLogs(1, exportSize, filters);
        const headers = [
          'Client IP', 'Rule ID', 'Event Count', 'First Seen', 'Last Seen',
          'Severity', 'Attack Type', 'Sample URI', 'Country', 'Message'
        ];
        const rows = (result.data || []).map(g => [
          g.client_ip || '', g.rule_id || '', g.event_count || 0,
          g.first_seen || '', g.last_seen || '', g.severity || '',
          g.attack_type || '', g.sample_uri || '', g.country || 'Unknown',
          (g.message || '').replace(/"/g, '""'),
        ]);
        csv = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
        filenameSuffix = 'grouped';
      } else {
        const result = await getLogs(1, exportSize, filters);
        const headers = [
          'Transaction ID', 'Timestamp', 'Client IP', 'Country',
          'Method', 'URI', 'HTTP Code', 'Severity', 'Attack Type',
          'Rule ID', 'Message', 'Source ASN'
        ];
        const rows = (result.data || []).map(log => [
          log.id || '', log.timestamp || '', log.client_ip || '',
          log.country || 'Unknown', log.method || '', log.uri || '',
          log.http_code || '', log.severity || '', log.attack_type || '',
          log.rule_id || '', (log.message || '').replace(/"/g, '""'),
          log.source_asn_org || ''
        ]);
        csv = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
        filenameSuffix = tabLabel;
      }

      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waf_events_${filenameSuffix}_${dateStr}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      if (totalToExport > EXPORT_ROW_CAP) {
        showToast(`Exported the first ${EXPORT_ROW_CAP.toLocaleString()} of ${totalToExport.toLocaleString()} matching rows — narrow the filters to capture the rest.`, 'error');
      }
    } catch (err) {
      showToast('Failed to export report: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setExporting(false);
    }
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

  const GROUP_DRILLDOWN_CAP = 50;

  const groupKey = (g) => `${g.client_ip}::${g.rule_id}`;

  // Drill-down for a collapsed group: reuses the existing GET /logs
  // endpoint's ip/rule_id filters (no new backend endpoint needed) to fetch
  // the individual events behind a group, on demand, capped at 50 — a
  // group with more than that is directed to narrow filters rather than
  // rendering a second pagination layer inside an expanded row.
  const toggleGroupExpand = async (group) => {
    const key = groupKey(group);
    setExpandedGroups(prev => {
      if (prev[key]) {
        const next = { ...prev };
        delete next[key];
        return next;
      }
      return { ...prev, [key]: { loading: true, events: [], error: '' } };
    });
    if (expandedGroups[key]) return; // was open — the toggle above just closed it

    try {
      const result = await getLogs(1, GROUP_DRILLDOWN_CAP, {
        ...buildFilters(),
        ip: group.client_ip,
        rule_id: group.rule_id,
      });
      setExpandedGroups(prev => (
        prev[key] ? { ...prev, [key]: { loading: false, events: result.data, error: '' } } : prev
      ));
    } catch (err) {
      setExpandedGroups(prev => (
        prev[key] ? { ...prev, [key]: { loading: false, events: [], error: err.message || 'Failed to load events.' } } : prev
      ));
    }
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
  }, [search, severityFilter, attackFilter, focusMode, trafficTab, viewMode]);

  // Grouped view sorts by a different field set than the flat view (there's
  // no per-event 'timestamp' on a group) — reset to each view's natural
  // default whenever the mode switches, rather than carrying over a sort
  // field the new view doesn't have.
  useEffect(() => {
    setSortField(viewMode === 'grouped' ? 'last_seen' : 'timestamp');
    setSortOrder('desc');
    setExpandedGroups({});
  }, [viewMode]);

  const isFetchingLogsRef = useRef(false);

  const fetchLogs = async () => {
    // setInterval fires unconditionally regardless of whether the previous
    // fetch resolved — under any latency spike this stacks overlapping
    // requests, each one adding more backend load than the last cycle.
    if (isFetchingLogsRef.current) return;
    isFetchingLogsRef.current = true;
    try {
      const filters = buildFilters();
      if (viewMode === 'grouped') {
        const groupedData = await getGroupedLogs(page, size, filters);
        setGroupedLogs(groupedData.data);
        setGroupedTotal(groupedData.total);
      } else {
        const logsData = await getLogs(page, size, filters);
        setLogs(logsData.data);
        setTotal(logsData.total);
      }
    } catch (err) {
      console.error('Error fetching logs', err);
    } finally {
      setLoading(false);
      isFetchingLogsRef.current = false;
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
  }, [page, size, search, severityFilter, attackFilter, focusMode, trafficTab, viewMode, refreshInterval, liveUpdates]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  // Recomputing this filter+sort on every render (including renders
  // triggered by unrelated state like search-box keystrokes or row hover)
  // is wasted work on a security log table meant to grow — memoize it to
  // only re-run when the inputs that actually affect the result change.
  const sortedLogs = useMemo(() => {
    return [...logs]
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
  }, [logs, trafficTab, sortField, sortOrder]);

  // Sorts only the currently-fetched page of groups — matches sortedLogs'
  // same within-page-only sort semantics above (both views are server-
  // paginated by a fixed order; column-header sort just reorders what's
  // already on screen, it doesn't re-page).
  const sortedGroupedLogs = useMemo(() => {
    return [...groupedLogs].sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];

      if (sortField === 'last_seen' || sortField === 'first_seen') {
        valA = Date.parse(valA) || 0;
        valB = Date.parse(valB) || 0;
      } else if (sortField === 'severity') {
        const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
        valA = severityOrder[valA] || 0;
        valB = severityOrder[valB] || 0;
      } else {
        valA = valA ?? '';
        valB = valB ?? '';
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }, [groupedLogs, sortField, sortOrder]);

  const totalPages = Math.ceil((viewMode === 'grouped' ? groupedTotal : total) / size);

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
          <Activity size={20} color="var(--sev-low)" />
          <span>Real-Time CyberSentinel Engine Logs</span>
          <div className="pulse-container">
            <div className="pulse-dot"></div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div className="search-input-wrapper">
            <Search size={14} color="var(--text-secondary)" style={{ position: 'absolute', left: '12px' }} />
            <input
              type="text"
              placeholder="Search IP, URI, rule..."
              aria-label="Search events by IP, URI, or rule"
              className="search-input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          {/* Severity dropdown: hidden when Focus Mode is active to prevent conflicting filter state */}
          {!focusMode && (
            <select
              className="filter-select"
              aria-label="Filter by severity"
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
            aria-label="Filter by attack type"
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

          {/* Grouped view: collapses repeated events by (Client IP, Rule ID)
              into one row with a count, so a scanner sweep or a repeat
              offender doesn't bury the signal under dozens of identical-
              looking rows. Flat view stays the default/raw timeline. */}
          <button
            onClick={() => setViewMode(prev => prev === 'grouped' ? 'flat' : 'grouped')}
            title={viewMode === 'grouped' ? 'Switch to flat event timeline' : 'Group repeated events by IP + Rule ID'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '8px',
              border: viewMode === 'grouped'
                ? '1px solid var(--accent-color)'
                : '1px solid rgba(161, 161, 170, 0.3)',
              background: viewMode === 'grouped' ? 'rgba(0,212,255,0.12)' : 'var(--border-subtle)',
              color: viewMode === 'grouped' ? 'var(--accent-color)' : 'var(--text-secondary)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
          >
            <Layers size={14} />
            {viewMode === 'grouped' ? 'Grouped View' : 'Flat View'}
          </button>

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
                ? '1px solid var(--danger-border)'
                : '1px solid rgba(161, 161, 170, 0.3)',
              background: focusMode
                ? 'linear-gradient(135deg, var(--danger-border), var(--sev-high-border))'
                : 'var(--border-subtle)',
              color: focusMode ? 'var(--danger-color)' : 'var(--text-secondary)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: focusMode ? '0 0 12px var(--danger-border)' : 'none',
              whiteSpace: 'nowrap',
            }}
          >
            <span style={{ fontSize: '15px' }}>🎯</span>
            {focusMode ? 'Focus: Critical + High' : 'Focus Mode'}
          </button>

          {/* Export Report: downloads the full filtered result set (not just
              the visible page) as structured CSV — see EXPORT_ROW_CAP above. */}
          <button
            onClick={handleExportReport}
            disabled={exporting}
            title="Export all currently filtered events as a structured CSV report"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '8px',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              background: 'rgba(16, 185, 129, 0.08)',
              color: 'var(--success-color)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: exporting ? 'default' : 'pointer',
              opacity: exporting ? 0.6 : 1,
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
            onMouseEnter={e => {
              if (exporting) return;
              e.currentTarget.style.background = 'rgba(16,185,129,0.15)';
              e.currentTarget.style.borderColor = 'rgba(16,185,129,0.6)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'rgba(16,185,129,0.08)';
              e.currentTarget.style.borderColor = 'rgba(16,185,129,0.35)';
            }}
          >
            <FileText size={14} />
            {exporting ? 'Exporting...' : 'Export Report'}
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
          background: 'var(--danger-bg)',
          border: '1px solid var(--danger-border)',
          fontSize: '12px',
          color: 'var(--text-muted)',
          transition: 'all 0.3s ease',
        }}>
          <ShieldCheck size={13} color="var(--danger-color)" style={{ flexShrink: 0 }} />
          <span><strong style={{ color: 'var(--danger-color)' }}>Focus Mode active</strong> · Showing Critical &amp; High severity events only · <span style={{ color: 'var(--text-secondary)' }}>{viewMode === 'grouped' ? `${groupedTotal} group${groupedTotal !== 1 ? 's' : ''}` : `${total} event${total !== 1 ? 's' : ''}`} matched</span></span>
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
        background: 'var(--inset-bg)',
        border: '1px solid var(--surface-hover)',
        borderRadius: '12px',
        backdropFilter: 'blur(10px)',
      }}>
        {[
          {
            id: 'all',
            label: 'All Traffic',
            icon: Activity,
            color: 'var(--text-secondary)',
            activeBg: 'rgba(161,161,170,0.15)',
            activeBorder: 'rgba(161,161,170,0.3)',
          },
          {
            id: 'api',
            label: 'API Traffic',
            icon: Code,
            color: 'var(--warning-color)',
            activeBg: 'rgba(245,158,11,0.15)',
            activeBorder: 'rgba(245,158,11,0.3)',
          },
          {
            id: 'web',
            label: 'Web Application',
            icon: Globe,
            color: 'var(--sev-low)',
            activeBg: 'var(--sev-low-border)',
            activeBorder: 'var(--sev-low-border)',
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
                color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
                fontSize: '13px',
                fontWeight: isActive ? 600 : 500,
                transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                whiteSpace: 'nowrap',
                boxShadow: isActive ? `0 4px 12px ${tab.activeBg}` : 'none',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-secondary)';
                  e.currentTarget.style.background = 'var(--surface-subtle)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.color = 'var(--text-muted)';
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
                  background: 'var(--inset-bg)',
                  border: `1px solid ${tab.activeBorder}`,
                  color: tab.color,
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: '"JetBrains Mono", monospace',
                  boxShadow: `inset 0 1px 2px rgba(0,0,0,0.5)`,
                }}>
                  {(viewMode === 'grouped' ? groupedTotal : total).toLocaleString()}
                </div>
              )}
            </button>
          );
        })}
      </div>

      {viewMode === 'grouped' && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px',
          padding: '8px 14px', borderRadius: '8px',
          background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.2)',
          fontSize: '12px', color: 'var(--text-muted)',
        }}>
          <Layers size={13} color="var(--accent-color)" style={{ flexShrink: 0 }} />
          <span>
            <strong style={{ color: 'var(--accent-color)' }}>Grouped View</strong> · Repeated events from the
            same IP against the same rule are collapsed into one row · click a row to see the individual events
          </span>
        </div>
      )}

      {viewMode === 'flat' ? (
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
                    <td colSpan="8" style={{ textAlign: 'center', padding: '60px', color: 'var(--text-secondary)' }}>
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
                          <td style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>{formatLocalTime(log?.timestamp)}</td>
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
                            style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)', maxBreakWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '300px' }}
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
                                  style={{ borderColor: 'rgba(16, 185, 129, 0.4)', color: 'var(--success-color)' }}
                                >
                                  Mark as FP
                                </button>
                              )}
                              <button
                                  className="action-btn-inspect"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    openLogDetails(sortedLogs, index);
                                  }}
                              >
                                Inspect Log
                              </button>
                            </div>
                          </td>
                        </tr>
                        {expandedLogs.has(rowId) && (
                          <tr className="expanded-log-row">
                            <td colSpan="8" style={{ padding: '16px 24px', background: 'var(--sev-low-bg)', borderBottom: '1px solid var(--sev-low-border)' }}>
                              <div style={{ fontFamily: 'monospace', fontSize: '13px', color: 'var(--sev-low)', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                                <strong style={{ color: 'var(--sev-low)', marginRight: '8px' }}>RECONSTRUCTED COMMAND:</strong><br />
                                <span style={{ marginTop: '8px', display: 'block', padding: '12px', background: 'var(--inset-bg)', borderRadius: '6px', border: '1px solid var(--surface-hover)' }}>
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
      ) : (
        <div className="logs-table-wrapper" style={{ marginTop: '0', borderTopLeftRadius: '0', borderTopRightRadius: '0' }}>
          <table className="logs-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('last_seen')} style={{ cursor: 'pointer', userSelect: 'none' }}>Last Seen {getSortIcon('last_seen')}</th>
                <th onClick={() => handleSort('client_ip')} style={{ cursor: 'pointer', userSelect: 'none' }}>Source IP {getSortIcon('client_ip')}</th>
                <th onClick={() => handleSort('severity')} style={{ cursor: 'pointer', userSelect: 'none' }}>Severity {getSortIcon('severity')}</th>
                <th onClick={() => handleSort('attack_type')} style={{ cursor: 'pointer', userSelect: 'none' }}>Attack Type {getSortIcon('attack_type')}</th>
                <th onClick={() => handleSort('rule_id')} style={{ cursor: 'pointer', userSelect: 'none' }}>Rule ID {getSortIcon('rule_id')}</th>
                <th onClick={() => handleSort('event_count')} style={{ cursor: 'pointer', userSelect: 'none' }}>Count {getSortIcon('event_count')}</th>
                <th>Sample URI</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && sortedGroupedLogs.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '60px', color: 'var(--text-secondary)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
                      <Activity className="animate-spin" size={20} /> Loading live CyberSentinel Engine logs...
                    </div>
                  </td>
                </tr>
              ) : sortedGroupedLogs.length === 0 && search.trim() === '' ? (
                <tr>
                  <td colSpan="8" style={{ padding: 0 }}>
                    <NoLogsEmptyState />
                  </td>
                </tr>
              ) : sortedGroupedLogs.length === 0 ? (
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
                sortedGroupedLogs.map((group, index) => {
                  const key = groupKey(group);
                  const expanded = expandedGroups[key];
                  return (
                    <React.Fragment key={key}>
                      <tr style={{ background: index === 0 ? 'rgba(0, 212, 255, 0.03)' : 'transparent' }}>
                        <td style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>{formatLocalTime(group.last_seen)}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)', fontWeight: 600 }}>
                          <span style={{ marginRight: '6px' }} title={group.severity}>
                            {group.severity === 'Critical' ? '💀' : group.severity === 'High' ? '🔥' : 'ℹ️'}
                          </span>
                          {group.client_ip || '-'}
                        </td>
                        <td>
                          <span className={`severity-badge severity-${(group.severity || 'low').toLowerCase()}`}>
                            {group.severity || 'Low'}
                          </span>
                        </td>
                        <td style={{ fontWeight: 500 }}>{group.attack_type || '-'}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{group.rule_id || '-'}</td>
                        <td>
                          <span style={{
                            fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '13px',
                            color: group.event_count >= 10 ? 'var(--danger-color)' : 'var(--text-primary)',
                          }}>
                            {group.event_count}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '300px' }}>
                          {group.sample_uri || '-'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="action-btn-inspect"
                            onClick={(e) => { e.stopPropagation(); toggleGroupExpand(group); }}
                          >
                            {expanded ? 'Hide Events' : 'View Events'}
                          </button>
                        </td>
                      </tr>
                      {expanded && (
                        <tr className="expanded-log-row">
                          <td colSpan="8" style={{ padding: '16px 24px', background: 'var(--sev-low-bg)', borderBottom: '1px solid var(--sev-low-border)' }}>
                            {expanded.loading ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                                <Activity className="animate-spin" size={14} /> Loading individual events...
                              </div>
                            ) : expanded.error ? (
                              <div style={{ color: 'var(--danger-color)', fontSize: '12px' }}>{expanded.error}</div>
                            ) : (
                              <>
                                {group.event_count > GROUP_DRILLDOWN_CAP && (
                                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                                    Showing {GROUP_DRILLDOWN_CAP} of {group.event_count} — narrow filters (e.g. add a time window) to see the rest.
                                  </div>
                                )}
                                <table className="logs-table" style={{ background: 'var(--inset-bg)' }}>
                                  <thead>
                                    <tr>
                                      <th>Time</th>
                                      <th>Status</th>
                                      <th>URI</th>
                                      <th style={{ textAlign: 'right' }}>Actions</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {expanded.events.map((ev, evIndex) => (
                                      <tr key={ev.id}>
                                        <td style={{ color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>{formatLocalTime(ev.timestamp)}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{ev.http_code || '-'}</td>
                                        <td style={{ fontFamily: 'monospace', fontSize: '12px', maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.uri || '-'}</td>
                                        <td style={{ textAlign: 'right' }}>
                                          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                                            {onMarkFalsePositive && (
                                              <button
                                                className="action-btn-inspect"
                                                onClick={() => onMarkFalsePositive(ev)}
                                                style={{ borderColor: 'rgba(16, 185, 129, 0.4)', color: 'var(--success-color)' }}
                                              >
                                                Mark as FP
                                              </button>
                                            )}
                                            <button
                                              className="action-btn-inspect"
                                              onClick={() => openLogDetails(expanded.events, evIndex)}
                                            >
                                              Inspect Log
                                            </button>
                                          </div>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </>
                            )}
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
      )}

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
              Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong> ({viewMode === 'grouped' ? `${groupedTotal} groups` : `${total} total logs`})
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
            setActiveLogList([]);
            setActiveLogIndex(-1);
          }}
          onMarkFalsePositive={onMarkFalsePositive}
          onCreateRule={onCreateRule}
          onNavigate={handleNavigateLog}
          canGoPrev={activeLogIndex > 0}
          canGoNext={activeLogIndex < activeLogList.length - 1}
        />
        <Toast toast={toast} />
    </motion.div>
  );
}
