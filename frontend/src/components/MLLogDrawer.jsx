import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { Activity, AlertTriangle as AlertTriangleIcon, Brain, Check, Copy, X } from 'lucide-react';
import { getLogById, labelMLEvent } from '../services/api';
import { formatLocalTime } from '../utils/helpers';
import HighlightedJson from './JsonViewer';
import { useEscapeToClose } from '../hooks/useEscapeToClose';

/**
 * The "inspect this ML evaluation" drawer opened from the MLEngine analytics
 * table — split out of pages/MLEngine.jsx (was pushing that file past 1300
 * lines) since this drawer's state (tabs, copy feedback, the correlated
 * audit-log lookup) is entirely self-contained once you have the log.
 */
export default function MLLogDrawer({ log, onClose, onLabelUpdate, showToast }) {
  const [modalActiveTab, setModalActiveTab] = useState('scores');
  const [correlatedLog, setCorrelatedLog] = useState(null);
  const [loadingCorrelated, setLoadingCorrelated] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [labeling, setLabeling] = useState(false);

  useEscapeToClose(onClose, !!log);

  useEffect(() => {
    if (log && log.unique_id) {
      setLoadingCorrelated(true);
      setModalActiveTab('scores');
      getLogById(log.unique_id)
        .then((data) => {
          setCorrelatedLog(data && !data.error ? data : null);
        })
        .catch((err) => {
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
  }, [log]);

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

  if (!log) return null;

  const handleCopy = () => {
    const textToCopy = JSON.stringify(log, null, 2);
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(textToCopy)
        .then(() => setCopied(true))
        .catch((err) => console.error("Copy failed", err));
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
        .catch((err) => console.error("Copy failed", err));
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

  const handleLabelEvent = async (label) => {
    setLabeling(true);
    try {
      await labelMLEvent(log.id, label);
      const updated = { ...log, admin_label: label };
      onLabelUpdate(updated);
      showToast(
        label === 'false_positive' ? 'Marked as false positive.' : 'Confirmed as true positive.'
      );
    } catch (err) {
      showToast('Failed to save label: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setLabeling(false);
    }
  };

  return createPortal(
    <div className="log-drawer-overlay" onClick={onClose}>
      <div className="log-drawer" role="dialog" aria-modal="true" aria-labelledby="ml-log-drawer-title" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="log-drawer-header">
          <div className="log-drawer-title" id="ml-log-drawer-title">
            <Brain size={18} color="var(--accent-color)" />
            Threat Evaluation
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>
              {log.remote_addr}
            </span>
          </div>
          <button className="log-drawer-close" onClick={onClose} aria-label="Close log details"><X size={16} /></button>
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
                    <div className="drawer-info-value" style={{ fontSize: '11px' }}>{formatLocalTime(log.timestamp)}</div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Client IP</div>
                    <div className="drawer-info-value" style={{ color: 'var(--accent-color)' }}>{log.remote_addr}</div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Method</div>
                    <div className="drawer-info-value">{log.method}</div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Body Length</div>
                    <div className="drawer-info-value">{log.body_len} bytes</div>
                  </div>
                </div>
              </div>

              {/* URI */}
              <div>
                <div className="drawer-section-title">Target URI</div>
                <div className="drawer-code-block" style={{ color: 'var(--accent-color)' }}>{log.uri}</div>
              </div>

              {/* Args */}
              {log.args && (
                <div>
                  <div className="drawer-section-title">Payload Arguments</div>
                  <div className="drawer-code-block" style={{ color: 'var(--warning-color)' }}>{log.args}</div>
                </div>
              )}

              {/* Matched vars */}
              {log.matched_vars && (
                <div>
                  <div className="drawer-section-title">OWASP CRS Matched Variables</div>
                  <div className="drawer-code-block" style={{ color: 'var(--danger-color)' }}>{log.matched_vars}</div>
                </div>
              )}

              {/* ML scores */}
              <div>
                <div className="drawer-section-title">ML Diagnostics Vector</div>
                <div className="drawer-ml-grid">
                  <div className="drawer-ml-cell">
                    <div className="drawer-ml-label">XGBoost Prob</div>
                    <div className="drawer-ml-value">{(log.xgb_prob * 100).toFixed(1)}%</div>
                  </div>
                  <div className="drawer-ml-cell">
                    <div className="drawer-ml-label">Isolation Forest</div>
                    <div className="drawer-ml-value">{log.iso_score?.toFixed(4)}</div>
                  </div>
                  <div className="drawer-ml-cell">
                    <div className="drawer-ml-label">CRS Anomaly</div>
                    <div className="drawer-ml-value">{log.crs_score}</div>
                  </div>
                  <div className="drawer-ml-cell">
                    <div className="drawer-ml-label">Redis IP Rep</div>
                    <div className="drawer-ml-value" style={{ fontSize: '14px' }}>{log.redis_rep} pts</div>
                  </div>
                </div>
              </div>

              {/* Reconstructed request */}
              <div>
                <div className="drawer-section-title">Reconstructed HTTP Signature</div>
                <div className="drawer-code-block" style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>
                  {`${log.method} ${log.uri}${log.args ? `?${log.args}` : ''} HTTP/1.1\n` +
                    `Host: localhost\n` +
                    (log.ua ? `User-Agent: ${log.ua}\n` : '') +
                    (log.ct ? `Content-Type: ${log.ct}\n` : '') +
                    (log.body_len ? `Content-Length: ${log.body_len}\n` : '')}
                </div>
              </div>

              {/* Analyst feedback — feeds drift_monitor's xgb_fp_rate signal */}
              <div>
                <div className="drawer-section-title">Analyst Feedback</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button
                    className="pagination-btn"
                    disabled={labeling}
                    onClick={() => handleLabelEvent('false_positive')}
                    style={{
                      padding: '6px 12px', fontSize: '11px',
                      borderColor: log.admin_label === 'false_positive' ? 'var(--warning-color)' : undefined,
                      color: log.admin_label === 'false_positive' ? 'var(--warning-color)' : undefined,
                    }}
                  >
                    Mark False Positive
                  </button>
                  <button
                    className="pagination-btn"
                    disabled={labeling}
                    onClick={() => handleLabelEvent('true_positive')}
                    style={{
                      padding: '6px 12px', fontSize: '11px',
                      borderColor: log.admin_label === 'true_positive' ? 'var(--danger-color)' : undefined,
                      color: log.admin_label === 'true_positive' ? 'var(--danger-color)' : undefined,
                    }}
                  >
                    Confirm Threat
                  </button>
                  {log.admin_label && (
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Labeled: {log.admin_label.replace('_', ' ')}
                    </span>
                  )}
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
                <HighlightedJson json={log} />
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
  );
}
