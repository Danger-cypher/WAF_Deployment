import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion } from 'framer-motion';
import { Check, Clock, Copy, Database, Filter, Search, ShieldCheck, X } from 'lucide-react';
import { getFalsePositives, deleteFalsePositive, updateFalsePositiveNote, updateFalsePositiveStatus } from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import { HelpText } from '../components/Tooltip';
import HighlightedJson from '../components/JsonViewer';
import { NoFalsePositivesEmptyState } from '../components/EmptyStates';
import { useToast } from '../hooks/useToast';
import Toast from '../components/Toast';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { usePagination } from '../hooks/usePagination';
import Pagination from '../components/Pagination';
import Button from '../components/Button';

export function FlagFpModal({ isOpen, log, onClose, onSubmit }) {
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEscapeToClose(onClose, isOpen);

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
            <ShieldCheck size={20} color="var(--success-color)" />
            <span>Mark as False Positive</span>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ background: 'var(--surface-subtle)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Rule ID:</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{log.rule_id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Client IP:</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--sev-low)' }}>{log.client_ip}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Request URI:</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--danger-color)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', maxWidth: '240px' }}>{log.uri}</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label htmlFor="analyst-note" style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Analyst Justification Note</label>
              <textarea
                id="analyst-note"
                className="settings-input"
                style={{ height: '100px', resize: 'none', background: 'var(--inset-bg)', padding: '12px' }}
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
            <button type="submit" className="modal-btn primary" disabled={submitting} style={{ background: 'var(--success-color)', borderColor: 'var(--success-color)', color: '#000', fontWeight: 600 }}>
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

  useEscapeToClose(onClose, isOpen);

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
            <ShieldCheck size={20} color="var(--sev-low)" />
            <span>False Positive Report Details</span>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxHeight: '75vh', overflowY: 'auto', paddingRight: '4px' }}>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'var(--surface-subtle)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '13px' }}>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Incident Rule ID:</span>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px', fontFamily: 'monospace' }}>Rule #{entry.rule_id}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Flagged Severity:</span>
              <div style={{ marginTop: '2px' }}>
                <span className={`severity-badge severity-${entry.severity?.toLowerCase() || 'medium'}`}>
                  {entry.severity}
                </span>
              </div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Source Client IP:</span>
              <div style={{ fontWeight: 600, color: 'var(--sev-low)', marginTop: '2px', fontFamily: 'monospace' }}>{entry.client_ip}</div>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Attack Type Category:</span>
              <div style={{ fontWeight: 600, color: 'var(--sev-medium)', marginTop: '2px' }}>{entry.attack_type}</div>
            </div>
            <div style={{ marginTop: '8px', gridColumn: 'span 2' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Target Request URI:</span>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px', fontFamily: 'monospace', wordBreak: 'break-all' }}>{entry.uri}</div>
            </div>
            <div style={{ marginTop: '8px', gridColumn: 'span 2' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>Timestamp Reported:</span>
              <div style={{ fontWeight: 500, color: 'var(--text-primary)', marginTop: '2px' }}>{formatLocalTime(entry.timestamp)}</div>
            </div>
          </div>

          {entry.linked_exclusion_id != null && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 12px',
              background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)',
              borderRadius: '6px', fontSize: '12.5px', color: 'var(--sev-low)',
            }}>
              <ShieldCheck size={14} />
              <span>
                This report already has a linked exclusion (<strong>#{entry.linked_exclusion_id}</strong>) —
                see the Exceptions page to view/edit it before creating another.
              </span>
            </div>
          )}

          {/* Review Status Selector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Triage Review Stage</span>
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
                    background: entry.status === st ? (st === 'Resolved' ? 'rgba(16,185,129,0.15)' : st === 'Reviewed' ? 'var(--sev-low-border)' : 'var(--sev-medium-border)') : 'var(--surface-subtle)',
                    color: entry.status === st ? (st === 'Resolved' ? 'var(--success-color)' : st === 'Reviewed' ? 'var(--sev-low)' : 'var(--sev-medium)') : 'var(--text-secondary)',
                    border: entry.status === st ? (st === 'Resolved' ? '1px solid rgba(16,185,129,0.3)' : st === 'Reviewed' ? '1px solid var(--sev-low-border)' : '1px solid var(--sev-medium-border)') : '1px solid var(--surface-hover)',
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
              <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Analyst Justification Notes</span>
              {!isEditingNote && (
                <button
                  onClick={() => setIsEditingNote(true)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--sev-low)', fontSize: '11.5px', fontWeight: 600, cursor: 'pointer' }}
                >
                  Edit Note
                </button>
              )}
            </div>
            {isEditingNote ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <textarea
                  className="settings-input"
                  style={{ height: '80px', resize: 'none', background: 'var(--inset-bg)', padding: '10px', fontSize: '13px' }}
                  value={noteVal}
                  onChange={(e) => setNoteVal(e.target.value)}
                  placeholder="Describe why this request is a false positive..."
                />
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                  <button className="modal-btn secondary" style={{ padding: '4px 10px', fontSize: '11px' }} onClick={() => { setNoteVal(entry.analyst_note || ''); setIsEditingNote(false); }}>Cancel</button>
                  <button className="modal-btn primary" style={{ padding: '4px 10px', fontSize: '11px', background: 'var(--sev-low)', borderColor: 'var(--sev-low)', color: '#fff' }} onClick={handleSave}>Save</button>
                </div>
              </div>
            ) : (
              <div style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px', fontSize: '13px', color: 'var(--text-primary)', fontStyle: entry.analyst_note ? 'normal' : 'italic', whiteSpace: 'pre-wrap' }}>
                {entry.analyst_note || "No analyst review notes recorded. Click 'Edit Note' to add details."}
              </div>
            )}
          </div>

          {/* Trigger Event Log JSON */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Origin Transaction Trigger Log JSON</span>
              <Button
                variant="ghost" size="sm"
                icon={copied ? Check : Copy}
                onClick={handleCopy}
                style={{ color: copied ? 'var(--success-color)' : 'var(--sev-low)', padding: '2px 6px' }}
              >
                {copied ? 'Copied JSON!' : 'Copy Raw JSON'}
              </Button>
            </div>
            <div style={{ maxHeight: '250px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '6px' }}>
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
              style={{ borderColor: 'var(--danger-border)', color: 'var(--danger-color)' }}
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
                style={{ background: 'var(--sev-high)', borderColor: 'var(--sev-high)', color: '#000', fontWeight: 600 }}
              >
                {entry.linked_exclusion_id != null ? 'Create Additional Exception' : 'Bypass & Create Exception'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

export default function FalsePositives({ userRole, onCreateException }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [search, setSearch] = useState('');
  const [ruleIdSearch, setRuleIdSearch] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [isLogModalOpen, setIsLogModalOpen] = useState(false);
  const { toast, showToast } = useToast();
  const confirm = useConfirm();
  const { page, totalPages, total, pageItems, goToPrev, goToNext, resetPage } = usePagination(entries, 15);

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
      showToast('Failed to load false positives: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchFP();
      resetPage();
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, severityFilter, ruleIdSearch, search]);

  const handleUpdateStatus = async (id, status) => {
    try {
      await updateFalsePositiveStatus(id, status);
      showToast(`Triage status updated to ${status}.`);
      fetchFP();
      setSelectedLog(prev => prev ? { ...prev, status: status } : null);
    } catch (err) {
      showToast('Failed to update status: ' + (err.message || 'Unknown error'), 'error');
    }
  };

  const handleSaveNote = async (id, noteText) => {
    try {
      await updateFalsePositiveNote(id, noteText);
      showToast('Analyst note updated successfully.');
      fetchFP();
      setSelectedLog(prev => prev ? { ...prev, analyst_note: noteText } : null);
    } catch (err) {
      showToast('Failed to update note: ' + (err.message || 'Unknown error'), 'error');
    }
  };

  const handleDeleteEntry = async (id) => {
    if (!(await confirm({
      title: 'Remove false positive',
      message: 'Are you sure you want to remove this false positive record from WAF diagnostics?',
      confirmLabel: 'Remove',
      danger: true,
    }))) return;
    try {
      await deleteFalsePositive(id);
      showToast('Record removed successfully.');
      fetchFP();
    } catch (err) {
      showToast('Failed to delete false positive entry: ' + (err.message || 'Unknown error'), 'error');
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
      <Toast toast={toast} />

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
          <div className="metric-value" style={{ color: 'var(--sev-medium)' }}>
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
          <div className="metric-value" style={{ color: 'var(--success-color)' }}>
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
          <Search size={16} color="var(--text-secondary)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
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
            <Filter size={14} color="var(--text-secondary)" />
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
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>Loading review registry...</div>
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
                {pageItems.map((entry) => {
                  const statusColors = {
                    Pending: { bg: 'var(--sev-medium-bg)', color: 'var(--sev-medium)', border: '1px solid var(--sev-medium-border)' },
                    Reviewed: { bg: 'var(--sev-low-bg)', color: 'var(--sev-low)', border: '1px solid var(--sev-low-border)' },
                    Resolved: { bg: 'rgba(16,185,129,0.1)', color: 'var(--success-color)', border: '1px solid rgba(16,185,129,0.2)' },
                  };
                  const colors = statusColors[entry.status] || statusColors.Pending;

                  return (
                    <tr
                      key={entry.id}
                      className="log-row"
                    >
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{formatLocalTime(entry.timestamp)}</td>
                      <td>
                        <span className="log-rule-id" style={{ background: 'var(--surface-hover)', color: 'var(--text-primary)', fontSize: '11px', padding: '3px 6px', borderRadius: '4px', fontFamily: 'monospace', border: '1px solid var(--surface-strong)' }}>
                          {entry.rule_id}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'monospace', color: 'var(--sev-low)', fontSize: '13px' }}>{entry.client_ip}</td>
                      <td className="payload-cell" style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.uri}>
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
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={entry.analyst_note}>
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
                              title={entry.linked_exclusion_id != null ? `Already has exclusion #${entry.linked_exclusion_id} — this creates an additional one` : undefined}
                              style={{ padding: '4px 8px', fontSize: '11px', borderColor: 'var(--sev-high-border)', color: 'var(--sev-high)' }}
                            >
                              {entry.linked_exclusion_id != null ? `Bypass WAF (#${entry.linked_exclusion_id} linked)` : 'Bypass WAF'}
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
      <Pagination page={page} totalPages={totalPages} total={total} itemLabel="records" onPrev={goToPrev} onNext={goToNext} />

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

