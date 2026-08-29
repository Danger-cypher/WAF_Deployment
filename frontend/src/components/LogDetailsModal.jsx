import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { ShieldAlert as AlertIcon, Globe, X, ShieldCheck, Copy, Check, ChevronUp, ChevronDown, Ban } from 'lucide-react';
import { formatLocalTime } from '../utils/helpers';
import HighlightedJson from './JsonViewer';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { getLogExplain } from '../services/api';

/**
 * Slide-out drawer for inspecting a single WAF event, opened from Events.jsx.
 * Uses the same .log-drawer-* pattern as MLLogDrawer.jsx (opened from the
 * ML Engine page) instead of the old centered .modal-overlay — the event
 * list stays visible behind the dimmed drawer rather than being replaced by
 * it, and Up/Down lets an analyst step through a triage queue without
 * closing and reopening for every row.
 */
export default function LogDetailsModal({ isOpen, log, onClose, onMarkFalsePositive, onCreateRule, onNavigate, canGoPrev, canGoNext }) {
  const [activeTab, setActiveTab] = useState('details');
  const [copied, setCopied] = useState(false);
  const [showReqHeaders, setShowReqHeaders] = useState(false);
  const [showResHeaders, setShowResHeaders] = useState(false);
  const [showExplain, setShowExplain] = useState(false);
  const [explainData, setExplainData] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState('');

  useEscapeToClose(onClose, isOpen);

  useEffect(() => {
    if (!isOpen || !onNavigate) return;
    const handleKeyDown = (e) => {
      // Ignore navigation while focus is inside a text field (e.g. a future
      // in-drawer search box) so arrow keys behave normally there.
      const tag = document.activeElement?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      if (e.key === 'ArrowUp' && canGoPrev) { e.preventDefault(); onNavigate('prev'); }
      else if (e.key === 'ArrowDown' && canGoNext) { e.preventDefault(); onNavigate('next'); }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onNavigate, canGoPrev, canGoNext]);

  useEffect(() => {
    if (copied) {
      const t = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(t);
    }
  }, [copied]);

  useEffect(() => {
    if (isOpen) {
      const timer = setTimeout(() => {
        setActiveTab('details');
        setShowReqHeaders(false);
        setShowResHeaders(false);
        setShowExplain(false);
        setExplainData(null);
        setExplainError('');
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [isOpen, log?.id]);

  useEffect(() => {
    if (showExplain && !explainData && !explainLoading && log?.id) {
      setExplainLoading(true);
      setExplainError('');
      getLogExplain(log.id)
        .then(setExplainData)
        .catch((err) => setExplainError(err.message || 'Failed to load explain data'))
        .finally(() => setExplainLoading(false));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showExplain]);

  if (!isOpen || !log) return null;

  // ── Derived fields ───────────────────────────────────────────────────────
  const reqHeaders = log.request_headers || {};
  const userAgent = reqHeaders['User-Agent'] || reqHeaders['user-agent'] || '';
  const referer = reqHeaders['Referer'] || reqHeaders['referer'] || '';

  // Determine target application from hostname + uri
  const hostname = log.hostname || '';
  let targetApp = 'Unknown Application';
  if (log.uri && (log.uri.startsWith('/api/auth') || log.uri.startsWith('/api/logs') || log.uri.startsWith('/api/settings'))) {
    targetApp = 'CyberSentinel WAF Dashboard';
  } else if (hostname) {
    targetApp = 'MSSP Application';
  }
  if (hostname) targetApp += ' · ' + hostname;

  const collapsibleHeader = (label, count, open, toggle) => (
    <div
      onClick={toggle}
      style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '10px 14px', background: 'var(--cyan-bg)',
        border: '1px solid var(--cyan-bg)',
        borderRadius: open ? '10px 10px 0 0' : '10px',
        cursor: 'pointer', userSelect: 'none',
      }}
    >
      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>{label}{count !== undefined ? ` (${count})` : ''}</span>
      <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{open ? '▼' : '►'}</span>
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
    <div className="log-drawer-overlay" onClick={onClose}>
      <div className="log-drawer" onClick={(e) => e.stopPropagation()}>
        <div className="log-drawer-header">
          <div className="log-drawer-title">
            <AlertIcon size={18} color="var(--danger-color)" />
            Inspection: Log Transaction
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>
              {log.id}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {onNavigate && (
              <div style={{ display: 'flex', border: '1px solid var(--surface-strong)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
                <button
                  className="log-drawer-close"
                  onClick={() => onNavigate('prev')}
                  disabled={!canGoPrev}
                  aria-label="Previous event"
                  title="Previous event (↑)"
                  style={{ borderRadius: 0, border: 'none', borderRight: '1px solid var(--surface-strong)', opacity: canGoPrev ? 1 : 0.35, cursor: canGoPrev ? 'pointer' : 'default' }}
                >
                  <ChevronUp size={16} />
                </button>
                <button
                  className="log-drawer-close"
                  onClick={() => onNavigate('next')}
                  disabled={!canGoNext}
                  aria-label="Next event"
                  title="Next event (↓)"
                  style={{ borderRadius: 0, border: 'none', opacity: canGoNext ? 1 : 0.35, cursor: canGoNext ? 'pointer' : 'default' }}
                >
                  <ChevronDown size={16} />
                </button>
              </div>
            )}
            {onMarkFalsePositive && (
              <button
                className="pagination-btn"
                onClick={() => onMarkFalsePositive(log)}
                style={{ padding: '3px 10px', fontSize: '11px', borderColor: 'rgba(16, 185, 129, 0.4)', background: 'rgba(16, 185, 129, 0.05)', color: 'var(--success-color)' }}
              >
                <ShieldCheck size={13} color="var(--success-color)" />
                <span>Mark as FP</span>
              </button>
            )}
            {onCreateRule && (
              <button
                className="pagination-btn"
                onClick={() => onCreateRule(log)}
                title="Jump to Virtual Patching with this event's IP/URI pre-filled"
                style={{ padding: '3px 10px', fontSize: '11px', borderColor: 'var(--danger-border)', background: 'var(--danger-bg)', color: 'var(--danger-color)' }}
              >
                <Ban size={13} color="var(--danger-color)" />
                <span>Create Rule</span>
              </button>
            )}
            <button className="log-drawer-close" onClick={onClose} aria-label="Close log details">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="log-drawer-tabs">
          <span className={`log-drawer-tab ${activeTab === 'details' ? 'active' : ''}`} onClick={() => setActiveTab('details')}>Event Details</span>
          <span className={`log-drawer-tab ${activeTab === 'raw' ? 'active' : ''}`} onClick={() => setActiveTab('raw')}>Raw Audit Log</span>
        </div>

        <div className="log-drawer-body">
          {activeTab === 'details' ? (
            <>
              {/* Metadata */}
              <div>
                <div className="drawer-section-title">Request Metadata</div>
                <div className="drawer-info-grid">
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Timestamp</div>
                    <div className="drawer-info-value" style={{ fontSize: '12px' }}>{formatLocalTime(log.timestamp)}</div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Attacker IP</div>
                    <div className="drawer-info-value" style={{ color: 'var(--accent-color)' }}>{log.client_ip}</div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Attack Vector</div>
                    <div className="drawer-info-value" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'inherit' }}>
                      <span className={`severity-badge severity-${(log.severity || 'low').toLowerCase()}`}>{log.severity}</span>
                      {log.attack_type}
                    </div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Country</div>
                    <div className="drawer-info-value" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Globe size={13} color="var(--accent-color)" />
                      {log.country || 'Unknown'}
                    </div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">Source ASN / Org</div>
                    <div className="drawer-info-value" style={{ color: 'var(--accent-color)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={log.source_asn_org}>
                      {log.source_asn_org || 'Unknown'}
                    </div>
                  </div>
                  <div className="drawer-info-cell">
                    <div className="drawer-info-label">HTTP Response</div>
                    <div className="drawer-info-value" style={{ color: 'var(--danger-color)' }}>{log.http_code || '403'}</div>
                  </div>
                  <div className="drawer-info-cell" style={{ gridColumn: 'span 2' }}>
                    <div className="drawer-info-label">Target Application</div>
                    <div className="drawer-info-value" style={{ color: 'var(--success-color)', fontFamily: 'inherit' }}>{targetApp}</div>
                  </div>
                </div>
              </div>

              {/* URI */}
              <div>
                <div className="drawer-section-title">Requested URI</div>
                <div className="drawer-code-block" style={{ color: 'var(--danger-color)' }}>
                  <span style={{ color: 'var(--text-muted)', fontWeight: 700, marginRight: '6px' }}>{log.method}</span>
                  {log.uri}
                </div>
              </div>

              {/* User-Agent */}
              {userAgent && (
                <div>
                  <div className="drawer-section-title">User-Agent (Client Tool / Browser)</div>
                  <div className="drawer-code-block" style={{ color: 'var(--accent-color)' }}>
                    {userAgent}
                    {(userAgent.toLowerCase().includes('sqlmap') || userAgent.toLowerCase().includes('nikto') || userAgent.toLowerCase().includes('nmap') || userAgent.toLowerCase().includes('dirbuster') || userAgent.toLowerCase().includes('burp')) && (
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '8px', background: 'rgba(251,146,60,0.12)', border: '1px solid rgba(251,146,60,0.3)', borderRadius: '4px', padding: '2px 8px', fontSize: '11px', color: 'var(--sev-high)', fontWeight: 600 }}>⚠ Known Attack Tool Detected</div>
                    )}
                  </div>
                </div>
              )}

              {/* Referer */}
              {referer && (
                <div>
                  <div className="drawer-section-title">Referer (Attack Origin Page)</div>
                  <div className="drawer-code-block" style={{ color: 'var(--success-color)' }}>{referer}</div>
                </div>
              )}

              {/* Request Headers */}
              <div>
                {collapsibleHeader('Request Headers', Object.keys(reqHeaders).length, showReqHeaders, () => setShowReqHeaders(!showReqHeaders))}
                {showReqHeaders && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid var(--cyan-bg)', borderTop: 'none', borderBottomLeftRadius: '10px', borderBottomRightRadius: '10px', maxHeight: '200px', overflowY: 'auto' }}>
                    {Object.keys(reqHeaders).length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>No request headers recorded.</div>
                    ) : (
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                        {Object.entries(reqHeaders).map(([k, v]) => (
                          <tr key={k} style={{ borderBottom: '1px solid var(--cyan-bg)' }}>
                            <td style={{ color: 'var(--text-muted)', padding: '5px 0', fontWeight: 600, width: '30%', verticalAlign: 'top', wordBreak: 'break-all' }}>{k}</td>
                            <td style={{ color: 'var(--text-primary)', padding: '5px 8px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', verticalAlign: 'top' }}>{v}</td>
                          </tr>
                        ))}
                      </tbody></table>
                    )}
                  </div>
                )}
              </div>

              {/* Response Headers */}
              <div>
                {collapsibleHeader('Response Headers', Object.keys(log.response_headers || {}).length, showResHeaders, () => setShowResHeaders(!showResHeaders))}
                {showResHeaders && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid var(--cyan-bg)', borderTop: 'none', borderBottomLeftRadius: '10px', borderBottomRightRadius: '10px', maxHeight: '200px', overflowY: 'auto' }}>
                    {Object.keys(log.response_headers || {}).length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>
                        No response headers recorded.
                        {log.http_code && (log.http_code.startsWith('4') || log.http_code.startsWith('5')) && (
                          <div style={{ marginTop: '6px', fontSize: '11px', opacity: 0.8 }}>ℹ️ Blocked requests (HTTP {log.http_code}) may not log backend response headers.</div>
                        )}
                      </div>
                    ) : (
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                        {Object.entries(log.response_headers || {}).map(([k, v]) => (
                          <tr key={k} style={{ borderBottom: '1px solid var(--cyan-bg)' }}>
                            <td style={{ color: 'var(--text-muted)', padding: '5px 0', fontWeight: 600, width: '30%', verticalAlign: 'top', wordBreak: 'break-all' }}>{k}</td>
                            <td style={{ color: 'var(--text-primary)', padding: '5px 8px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', verticalAlign: 'top' }}>{v}</td>
                          </tr>
                        ))}
                      </tbody></table>
                    )}
                  </div>
                )}
              </div>

              {/* Explain This Block (ML correlation) */}
              <div>
                {collapsibleHeader('Why Was This Blocked? (ML Correlation)', undefined, showExplain, () => setShowExplain(!showExplain))}
                {showExplain && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', border: '1px solid var(--cyan-bg)', borderTop: 'none', borderBottomLeftRadius: '10px', borderBottomRightRadius: '10px' }}>
                    {explainLoading && (
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>Loading...</div>
                    )}
                    {explainError && (
                      <div style={{ color: 'var(--danger-color)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>{explainError}</div>
                    )}
                    {explainData && !explainData.ml_event && (
                      <div style={{ color: 'var(--text-muted)', fontSize: '12px', padding: '4px 0' }}>{explainData.ml_match_note}</div>
                    )}
                    {explainData && explainData.ml_event && (
                      <>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px' }}>{explainData.ml_match_note}</div>
                        <div className="drawer-ml-grid">
                          <div className="drawer-ml-cell">
                            <div className="drawer-ml-label">Blended Threat Score</div>
                            <div className="drawer-ml-value">{explainData.ml_event.threat_score?.toFixed(3)}</div>
                          </div>
                          <div className="drawer-ml-cell">
                            <div className="drawer-ml-label">XGBoost Probability</div>
                            <div className="drawer-ml-value">{explainData.ml_event.xgb_prob?.toFixed(3)}</div>
                          </div>
                          <div className="drawer-ml-cell">
                            <div className="drawer-ml-label">CRS Anomaly Score</div>
                            <div className="drawer-ml-value">{explainData.ml_event.crs_score}</div>
                          </div>
                          <div className="drawer-ml-cell">
                            <div className="drawer-ml-label">Isolation Forest</div>
                            <div className="drawer-ml-value">{explainData.ml_event.iso_score?.toFixed(3)}</div>
                          </div>
                          <div className="drawer-ml-cell">
                            <div className="drawer-ml-label">IP Reputation</div>
                            <div className="drawer-ml-value" style={{ fontSize: '14px' }}>{explainData.ml_event.redis_rep}</div>
                          </div>
                          <div className="drawer-ml-cell">
                            <div className="drawer-ml-label">ML Decision</div>
                            <div className="drawer-ml-value" style={{ fontSize: '14px', color: 'var(--danger-color)' }}>{explainData.ml_event.decision}</div>
                          </div>
                        </div>
                        {explainData.ml_event.matched_vars && (
                          <div style={{ marginTop: '10px' }}>
                            <div className="drawer-info-label" style={{ marginBottom: '4px' }}>Matched Variables</div>
                            <div className="drawer-code-block" style={{ fontSize: '11px' }}>{explainData.ml_event.matched_vars}</div>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div className="drawer-section-title" style={{ marginBottom: 0 }}>Raw Audit Log (JSON)</div>
                <button className="pagination-btn" onClick={handleCopy}
                  style={{ padding: '4px 10px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', margin: 0 }}>
                  {copied ? <Check size={13} color="var(--success-color)" /> : <Copy size={13} />}
                  <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
                </button>
              </div>
              <HighlightedJson json={log.raw_log || log} />
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}
