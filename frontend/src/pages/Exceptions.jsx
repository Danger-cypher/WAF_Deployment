import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Check, Copy, Database, Search, ShieldCheck, X } from 'lucide-react';
import {
  getExclusions, deleteExclusion, getExclusionsAnalytics, getExclusionsHistory,
  previewExclusionRule, updateExclusionNote, updateExclusionStatus,
} from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import { NoExceptionsEmptyState } from '../components/EmptyStates';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { usePagination } from '../hooks/usePagination';
import Pagination from '../components/Pagination';
import Button from '../components/Button';

export function CreateExceptionModal({ isOpen, log, onClose, onSubmit }) {
  const [exclusionType, setExclusionType] = useState('uri');
  const [uri, setUri] = useState('');
  const [parameterName, setParameterName] = useState('');
  const [httpMethod, setHttpMethod] = useState('GET');
  const [clientIp, setClientIp] = useState('');
  const [notes, setNotes] = useState('');
  const [previewRule, setPreviewRule] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  useEscapeToClose(onClose, isOpen);

  useEffect(() => {
    if (isOpen && log) {
      const timer = setTimeout(() => {
        const suggestion = log.suggested_exclusion;
        setExclusionType(suggestion?.exclusion_type || 'uri');
        setUri(log.uri || '/');
        setParameterName(suggestion?.parameter_name || '');
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
            <AlertTriangle size={20} color="var(--sev-high)" />
            <span>Create WAF Exception Exclusions</span>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {errorMsg && (
              <div style={{ background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', color: 'var(--danger-color)', padding: '10px 14px', borderRadius: '6px', fontSize: '13px' }}>
                {errorMsg}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'var(--surface-subtle)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '12px' }}>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Origin Log Rule ID:</span>
                <div style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>{log.rule_id}</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Attack Category:</span>
                <div style={{ fontWeight: 600, color: 'var(--sev-medium)', marginTop: '2px' }}>{log.attack_type}</div>
              </div>
            </div>

            {log.suggested_exclusion && (
              <div style={{
                display: 'flex', gap: '8px', alignItems: 'flex-start',
                background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)',
                borderRadius: '6px', padding: '10px 12px', fontSize: '12px',
              }}>
                <ShieldCheck size={16} color="var(--sev-low)" style={{ flexShrink: 0, marginTop: '1px' }} />
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--sev-low)', textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.03em', marginBottom: '2px' }}>
                    Suggested strategy ({log.suggested_exclusion.confidence} confidence) — prefilled below, review before applying
                  </div>
                  <div style={{ color: 'var(--text-secondary)' }}>{log.suggested_exclusion.reasoning}</div>
                </div>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Exception Strategy</label>
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
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Target Endpoint URI</label>
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
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Target Parameter Name</label>
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
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>HTTP Method</label>
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
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Target Client IP Address</label>
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
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Justification Reason</label>
              <textarea
                className="settings-input"
                style={{ height: '80px', resize: 'none', background: 'var(--inset-bg)', padding: '10px' }}
                placeholder="E.g., verified search query parameters as legitimate business traffic..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                required
              />
            </div>

            {previewRule && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Auto-Generated CyberSentinel Engine Rule Preview</span>
                <pre style={{ margin: 0, padding: '12px', background: 'var(--inset-bg)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--success-color)', fontFamily: 'monospace', fontSize: '11px', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {previewRule}
                </pre>
              </div>
            )}
          </div>
          <div className="modal-footer" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button type="button" className="modal-btn secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="modal-btn primary" disabled={submitting} style={{ background: 'var(--sev-high)', borderColor: 'var(--sev-high)', color: '#000', fontWeight: 600 }}>
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

  useEscapeToClose(onClose, isOpen);

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
            <ShieldCheck size={20} color="var(--success-color)" />
            <span>Active Exclusion Rule Config</span>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'var(--surface-subtle)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '13px' }}>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Exclusion Policy ID:</span>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px', fontFamily: 'monospace' }}>EX-Ref #{exclusion.id}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Target WAF Rule ID:</span>
              <div style={{ fontWeight: 600, color: 'var(--sev-high)', marginTop: '2px', fontFamily: 'monospace' }}>Rule #{exclusion.rule_id}</div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Strategy Type:</span>
              <div style={{ fontWeight: 600, color: 'var(--sev-low)', marginTop: '2px' }}>{typeLabels[exclusion.exclusion_type] || exclusion.exclusion_type}</div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Created By / When:</span>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px', fontSize: '12px' }}>@{exclusion.created_by} on <span style={{ color: 'var(--text-secondary)' }}>{exclusion.created_at}</span></div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Scope Targets</span>
            <div style={{ background: 'var(--inset-bg)', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '6px', fontFamily: 'monospace', fontSize: '12px' }}>
              {exclusion.uri && (
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>URI Endpoint:</span> <span style={{ color: 'var(--sev-low)' }}>{exclusion.uri}</span>
                </div>
              )}
              {exclusion.parameter_name && (
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>Parameter:</span> <span style={{ color: 'var(--sev-high)' }}>{exclusion.parameter_name}</span>
                </div>
              )}
              {exclusion.http_method && (
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>HTTP Method:</span> <span style={{ color: 'var(--danger-color)' }}>{exclusion.http_method}</span>
                </div>
              )}
              {exclusion.client_ip && (
                <div>
                  <span style={{ color: 'var(--text-secondary)' }}>Client IP:</span> <span style={{ color: 'var(--success-color)' }}>{exclusion.client_ip}</span>
                </div>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Justification Notes</span>
            <div style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px', fontSize: '13px', color: 'var(--text-primary)', fontStyle: exclusion.notes ? 'normal' : 'italic', whiteSpace: 'pre-wrap' }}>
              {exclusion.notes || "No justification reason recorded."}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Compiled CyberSentinel Engine Rule Directive</span>
              <Button
                variant="ghost" size="sm"
                icon={copied ? Check : Copy}
                onClick={handleCopy}
                style={{ color: copied ? 'var(--success-color)' : 'var(--sev-low)', padding: '2px 6px' }}
              >
                {copied ? 'Copied' : 'Copy Directive'}
              </Button>
            </div>
            <pre style={{ margin: 0, padding: '12px', background: 'var(--inset-bg)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--success-color)', fontFamily: 'monospace', fontSize: '11px', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
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

export default function Exceptions() {
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
  const [errorMsg, setErrorMsg] = useState('');
  const { toast, showToast } = useToast();
  const confirm = useConfirm();
  const exclusionsPage = usePagination(exclusions, 15);
  const historyPage = usePagination(history, 15);

  const [selectedExclusion, setSelectedExclusion] = useState(null);
  const [isExclusionModalOpen, setIsExclusionModalOpen] = useState(false);

  useEscapeToClose(() => setIsNoteModalOpen(false), isNoteModalOpen);

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
      showToast('Failed to load exclusions: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchExclusions();
      exclusionsPage.resetPage();
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, statusFilter]);

  const handleToggleStatus = async (id, currentStatus) => {
    const nextStatus = currentStatus === 'Active' ? 'Disabled' : 'Active';
    try {
      await updateExclusionStatus(id, nextStatus);
      showToast(`Exception rule successfully ${nextStatus === 'Active' ? 'activated' : 'disabled'}.`);
      fetchExclusions();
    } catch (err) {
      showToast(err.message || "Failed to update exception status.", "error");
    }
  };

  const handleSaveNotes = async (e) => {
    e.preventDefault();
    try {
      await updateExclusionNote(editingExclusion.id, editNotes);
      showToast("Exclusion notes updated successfully.");
      setIsNoteModalOpen(false);
      fetchExclusions();
    } catch (err) {
      setErrorMsg(err.message || "Failed to update notes.");
    }
  };

  const handleDeleteExclusion = async (id) => {
    if (!(await confirm({
      title: 'Delete exception policy',
      message: 'Are you sure you want to permanently delete this exception policy? The target rule will instantly resume blocking traffic.',
      confirmLabel: 'Delete',
      danger: true,
    }))) return;
    try {
      await deleteExclusion(id);
      showToast("Exclusion policy deleted and WAF synchronized.");
      fetchExclusions();
    } catch (err) {
      showToast(err.message || "Failed to remove exclusion.", "error");
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
      <Toast toast={toast} />

      {analytics && (
        <div className="dashboard-grid animate-fade-in" style={{ gap: '16px', marginBottom: '8px' }}>
          <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
            <div className="metric-header">
              <span>Active WAF Exclusions</span>
              <div className="metric-icon-wrapper orange" style={{ background: 'var(--sev-high-bg)', color: 'var(--sev-high)' }}><AlertTriangle size={18} /></div>
            </div>
            <div className="metric-value" style={{ color: 'var(--sev-high)' }}>{analytics.active_exclusions}</div>
            <div className="metric-trend trend-up">
              <span>Active bypass rules overriding CRS</span>
            </div>
          </div>

          <div className="metric-card glass-panel" style={{ gridColumn: 'span 4' }}>
            <div className="metric-header">
              <span>Global System Health</span>
              <div className={`metric-icon-wrapper ${analytics.config_valid ? 'green' : 'red'}`}>
                <ShieldCheck size={18} />
              </div>
            </div>
            <div className="metric-value" style={{ color: analytics.config_valid ? 'var(--success-color)' : 'var(--danger-color)' }}>
              {analytics.config_valid ? '100%' : 'Error'}
            </div>
            <div className="metric-trend trend-down" title={analytics.config_error || ''}>
              <span>
                {analytics.config_valid
                  ? 'NGINX/ModSecurity config sync OK'
                  : 'Config validation failed — see server logs'}
              </span>
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
              <Search size={16} color="var(--text-secondary)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
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
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>Syncing exceptions database...</div>
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
                    {exclusionsPage.pageItems.map((entry) => {
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
                            <span className="log-rule-id" style={{ background: 'var(--surface-hover)', color: 'var(--text-primary)', fontSize: '11px', padding: '3px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>
                              {entry.rule_id}
                            </span>
                          </td>
                          <td style={{ fontWeight: 600, fontSize: '12px', color: 'var(--sev-high)' }}>
                            {typeLabels[entry.exclusion_type] || entry.exclusion_type}
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {entry.exclusion_type === 'parameter' && `Param: ${entry.parameter_name}`}
                            {entry.exclusion_type === 'uri' && `URI: ${entry.uri}`}
                            {entry.exclusion_type === 'uri_parameter' && `URI: ${entry.uri} [Param: ${entry.parameter_name}]`}
                            {entry.exclusion_type === 'endpoint_method' && `URI: ${entry.uri} [Method: ${entry.http_method}]`}
                            {entry.exclusion_type === 'ip_suppression' && `URI: ${entry.uri} [IP: ${entry.client_ip}]`}
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>@{entry.created_by}</td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.notes}>
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
                                background: entry.status === 'Active' ? 'rgba(16,185,129,0.1)' : 'var(--danger-bg)',
                                color: entry.status === 'Active' ? 'var(--success-color)' : 'var(--danger-color)',
                                border: entry.status === 'Active' ? '1px solid rgba(16,185,129,0.2)' : '1px solid var(--danger-border)',
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
                                style={{ padding: '4px 8px', fontSize: '11px', borderColor: 'var(--sev-low-border)', color: 'var(--sev-low)' }}
                              >
                                Edit Note
                              </button>

                              <button
                                className="action-btn-inspect"
                                onClick={() => handleDeleteExclusion(entry.id)}
                                style={{ padding: '4px 8px', fontSize: '11px', borderColor: 'var(--danger-border)', color: 'var(--danger-color)' }}
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
          <Pagination
            page={exclusionsPage.page} totalPages={exclusionsPage.totalPages} total={exclusionsPage.total}
            itemLabel="exceptions" onPrev={exclusionsPage.goToPrev} onNext={exclusionsPage.goToNext}
          />

          {analytics && analytics.top_excluded_rules && analytics.top_excluded_rules.length > 0 && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '10px' }}>
              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <AlertTriangle size={16} color="var(--sev-high)" />
                  <span>Most Frequently Excluded WAF Rules</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {analytics.top_excluded_rules.map((rule) => (
                    <div key={rule.rule_id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                        <span style={{ fontFamily: 'monospace', color: 'var(--sev-high)' }}>Rule #{rule.rule_id}</span>
                        <span style={{ fontWeight: 600 }}>{rule.count} Exception Policies</span>
                      </div>
                      <div style={{ width: '100%', height: '5px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min((rule.count / (analytics.top_excluded_rules[0]?.count || 1)) * 100, 100)}%`, height: '100%', background: 'linear-gradient(90deg, color-mix(in srgb, var(--sev-high) 55%, transparent), var(--sev-high))', borderRadius: '3px' }}></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={16} color="var(--success-color)" />
                  <span>Top False Positive Generating Rules (Tuning Candidates)</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {analytics.top_fp_rules && analytics.top_fp_rules.length > 0 ? (
                    analytics.top_fp_rules.map((rule) => (
                      <div key={rule.rule_id} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                          <span style={{ fontFamily: 'monospace', color: 'var(--success-color)' }}>Rule #{rule.rule_id}</span>
                          <span style={{ fontWeight: 600 }}>{rule.count} False Positives Flagged</span>
                        </div>
                        <div style={{ width: '100%', height: '5px', background: 'var(--surface-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                          <div style={{ width: `${Math.min((rule.count / (analytics.top_fp_rules[0]?.count || 1)) * 100, 100)}%`, height: '100%', background: 'linear-gradient(90deg, color-mix(in srgb, var(--success-color) 45%, transparent), var(--success-color))', borderRadius: '3px' }}></div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-secondary)', fontSize: '12px', textAlign: 'center', padding: '20px' }}>No marked false positives triggers discovered yet.</div>
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
            <div style={{ padding: '60px 40px', textAlign: 'center', color: 'var(--text-secondary)' }}>No exceptions audit history recorded yet.</div>
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
                {historyPage.pageItems.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{formatLocalTime(log.timestamp)}</td>
                    <td>
                      <span style={{
                        fontSize: '9px',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: log.action === 'Create' ? 'rgba(16,185,129,0.1)' : log.action === 'Delete' ? 'var(--danger-bg)' : 'var(--sev-low-bg)',
                        color: log.action === 'Create' ? 'var(--success-color)' : log.action === 'Delete' ? 'var(--danger-color)' : 'var(--sev-low)',
                        textTransform: 'uppercase'
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '12px', fontWeight: 500 }}>@{log.username}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>Ex-Ref #{log.exclusion_id}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-primary)' }}>{log.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <Pagination
            page={historyPage.page} totalPages={historyPage.totalPages} total={historyPage.total}
            itemLabel="audit entries" onPrev={historyPage.goToPrev} onNext={historyPage.goToNext}
          />
        </div>
      )}

      <AnimatePresence>
        {isNoteModalOpen && editingExclusion && (
          <div className="modal-overlay" onClick={() => setIsNoteModalOpen(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '440px' }}>
              <div className="modal-header">
                <div className="modal-title">
                  <Database size={18} color="var(--sev-low)" />
                  <span>Update Exception Justification</span>
                </div>
                <button className="modal-close-btn" onClick={() => setIsNoteModalOpen(false)} aria-label="Close">
                  <X size={18} />
                </button>
              </div>
              <form onSubmit={handleSaveNotes}>
                <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {errorMsg && (
                    <div style={{ background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', color: 'var(--danger-color)', padding: '8px 12px', borderRadius: '6px', fontSize: '12px' }}>
                      {errorMsg}
                    </div>
                  )}
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Edit the administrative review notes for Rule <strong style={{ color: 'var(--text-primary)' }}>{editingExclusion.rule_id}</strong> exception:
                  </div>
                  <textarea
                    className="settings-input"
                    style={{ height: '100px', resize: 'none', background: 'var(--inset-bg)', padding: '12px' }}
                    placeholder="Enter revised justification notes..."
                    value={editNotes}
                    onChange={(e) => setEditNotes(e.target.value)}
                    maxLength={400}
                    required
                  />
                </div>
                <div className="modal-footer" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                  <button type="button" className="modal-btn secondary" onClick={() => setIsNoteModalOpen(false)}>Cancel</button>
                  <button type="submit" className="modal-btn primary" style={{ background: 'var(--sev-low)', borderColor: 'var(--sev-low)', color: '#fff', fontWeight: 600 }}>
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

