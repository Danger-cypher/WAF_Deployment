import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { ShieldAlert as AlertIcon, Globe, X, ShieldCheck, Copy, Check } from 'lucide-react';
import { formatLocalTime } from '../utils/helpers';
import HighlightedJson from './JsonViewer';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { getLogExplain } from '../services/api';

export default function LogDetailsModal({ isOpen, log, onClose, onMarkFalsePositive }) {
  const [copied, setCopied] = useState(false);
  const [showReqHeaders, setShowReqHeaders] = useState(false);
  const [showResHeaders, setShowResHeaders] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);
  const [showExplain, setShowExplain] = useState(false);
  const [explainData, setExplainData] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState('');

  useEscapeToClose(onClose, isOpen);

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
        setShowRawJson(false);
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

  // Collect OWASP tags from raw_log
  const owaspTags = [];
  try {
    const msgs = log.raw_log?.transaction?.messages || [];
    msgs.forEach(m => {
      (m.details?.tags || []).forEach(tag => {
        if (!owaspTags.includes(tag) && tag !== 'OWASP_CRS') owaspTags.push(tag);
      });
    });
  } catch {
    // ignore malformed raw_log
  }

  const sectionStyle = { marginBottom: '14px' };
  const collapsibleHeader = (label, count, open, toggle) => (
    <div
      onClick={toggle}
      style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '10px 14px', background: 'var(--surface-subtle)',
        border: '1px solid var(--glass-border)',
        borderRadius: open ? '6px 6px 0 0' : '6px',
        cursor: 'pointer', userSelect: 'none',
      }}
    >
      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>{label}{count !== undefined ? ` (${count})` : ''}</span>
      <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>{open ? '▼' : '►'}</span>
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
            <AlertIcon size={20} color="var(--danger-color)" />
            <span>Inspection: Log Transaction ID: <span style={{ fontFamily: 'monospace', color: 'var(--sev-low)' }}>{log.id}</span></span>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close log details">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body" style={{ maxHeight: '80vh', overflowY: 'auto' }}>

          {/* Metadata Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px', background: 'var(--surface-subtle)', padding: '16px', borderRadius: '8px', border: '1px solid var(--surface-hover)' }}>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Timestamp</div>
              <div style={{ fontSize: '14px', fontWeight: 500, marginTop: '4px' }}>{formatLocalTime(log.timestamp)}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Attacker IP</div>
              <div style={{ fontSize: '14px', fontWeight: 500, fontFamily: 'monospace', color: 'var(--sev-low)', marginTop: '4px' }}>{log.client_ip}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Attack Vector</div>
              <div style={{ fontSize: '14px', marginTop: '4px' }}>
                <span className={`severity-badge severity-${(log.severity || 'low').toLowerCase()}`} style={{ marginRight: '8px' }}>
                  {log.severity}
                </span>
                {log.attack_type}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Country</div>
              <div style={{ fontSize: '14px', fontWeight: 500, marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Globe size={14} color="var(--sev-low)" />
                <span>{log.country || 'Unknown'}</span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Source ASN / Org</div>
              <div style={{ fontSize: '14px', fontWeight: 500, fontFamily: 'monospace', color: 'var(--sev-low)', marginTop: '4px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={log.source_asn_org}>
                {log.source_asn_org || 'Unknown'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>HTTP Response</div>
              <div style={{ fontSize: '14px', fontFamily: 'monospace', fontWeight: 700, color: 'var(--danger-color)', marginTop: '4px' }}>{log.http_code || '403'}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Target Application</div>
              <div style={{ fontSize: '13px', color: 'var(--success-color)', fontWeight: 500, marginTop: '4px' }}>{targetApp}</div>
            </div>
            <div style={{ gridColumn: 'span 2' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Requested URI</div>
              <div style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--danger-color)', wordBreak: 'break-all', marginTop: '4px' }}>
                <span style={{ color: 'var(--text-secondary)', fontWeight: 600, marginRight: '6px' }}>{log.method}</span>
                {log.uri}
              </div>
            </div>
          </div>

          {/* ── User-Agent ── */}
          {userAgent && (
            <div style={{ ...sectionStyle, background: 'var(--surface-subtle)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px 14px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '6px' }}>🌐 User-Agent (Client Tool / Browser)</div>
              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--sev-low)', wordBreak: 'break-all' }}>{userAgent}</div>
              {(userAgent.toLowerCase().includes('sqlmap') || userAgent.toLowerCase().includes('nikto') || userAgent.toLowerCase().includes('nmap') || userAgent.toLowerCase().includes('dirbuster') || userAgent.toLowerCase().includes('burp')) && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '6px', background: 'rgba(251,146,60,0.12)', border: '1px solid rgba(251,146,60,0.3)', borderRadius: '4px', padding: '2px 8px', fontSize: '11px', color: 'var(--sev-high)', fontWeight: 600 }}>⚠ Known Attack Tool Detected</span>
              )}
            </div>
          )}

          {/* ── Referer ── */}
          {referer && (
            <div style={{ ...sectionStyle, background: 'var(--surface-subtle)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px 14px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '6px' }}>🔗 Referer (Attack Origin Page)</div>
              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--success-color)', wordBreak: 'break-all' }}>{referer}</div>
            </div>
          )}

          {/* ── Request Headers ── */}
          <div style={sectionStyle}>
            {collapsibleHeader('Request Headers', Object.keys(reqHeaders).length, showReqHeaders, () => setShowReqHeaders(!showReqHeaders))}
            {showReqHeaders && (
              <div style={{ background: 'var(--inset-bg)', padding: '12px', border: '1px solid var(--surface-hover)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', maxHeight: '200px', overflowY: 'auto' }}>
                {Object.keys(reqHeaders).length === 0 ? (
                  <div style={{ color: 'var(--text-secondary)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>No request headers recorded.</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                    {Object.entries(reqHeaders)
                      .map(([k, v]) => (
                        <tr key={k} style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                          <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600, width: '30%', verticalAlign: 'top', wordBreak: 'break-all' }}>{k}</td>
                          <td style={{ color: 'var(--text-primary)', padding: '5px 8px', fontFamily: 'monospace', wordBreak: 'break-all', verticalAlign: 'top' }}>{v}</td>
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
              <div style={{ background: 'var(--inset-bg)', padding: '12px', border: '1px solid var(--surface-hover)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', maxHeight: '200px', overflowY: 'auto' }}>
                {Object.keys(log.response_headers || {}).length === 0 ? (
                  <div style={{ color: 'var(--text-secondary)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>
                    No response headers recorded.
                    {log.http_code && (log.http_code.startsWith('4') || log.http_code.startsWith('5')) && (
                      <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>ℹ️ Blocked requests (HTTP {log.http_code}) may not log backend response headers.</div>
                    )}
                  </div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                    {Object.entries(log.response_headers || {}).map(([k, v]) => (
                      <tr key={k} style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600, width: '30%', verticalAlign: 'top', wordBreak: 'break-all' }}>{k}</td>
                        <td style={{ color: 'var(--text-primary)', padding: '5px 8px', fontFamily: 'monospace', wordBreak: 'break-all', verticalAlign: 'top' }}>{v}</td>
                      </tr>
                    ))}
                  </tbody></table>
                )}
              </div>
            )}
          </div>


          {/* ── Explain This Block (ML correlation) ── */}
          <div style={sectionStyle}>
            {collapsibleHeader('Why Was This Blocked? (ML Correlation)', undefined, showExplain, () => setShowExplain(!showExplain))}
            {showExplain && (
              <div style={{ background: 'var(--inset-bg)', padding: '12px', border: '1px solid var(--surface-hover)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px' }}>
                {explainLoading && (
                  <div style={{ color: 'var(--text-secondary)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>Loading...</div>
                )}
                {explainError && (
                  <div style={{ color: 'var(--danger-color)', fontSize: '12px', textAlign: 'center', padding: '10px' }}>{explainError}</div>
                )}
                {explainData && !explainData.ml_event && (
                  <div style={{ color: 'var(--text-secondary)', fontSize: '12px', padding: '4px 0' }}>{explainData.ml_match_note}</div>
                )}
                {explainData && explainData.ml_event && (
                  <>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '10px' }}>{explainData.ml_match_note}</div>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}><tbody>
                      <tr style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600 }}>ML Decision</td>
                        <td style={{ padding: '5px 8px', fontFamily: 'monospace', color: 'var(--danger-color)', fontWeight: 700 }}>{explainData.ml_event.decision}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600 }}>Blended Threat Score</td>
                        <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}>{explainData.ml_event.threat_score?.toFixed(3)}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600 }}>CRS Anomaly Score</td>
                        <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}>{explainData.ml_event.crs_score}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600 }}>XGBoost Probability</td>
                        <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}>{explainData.ml_event.xgb_prob?.toFixed(3)}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600 }}>Isolation Forest Score</td>
                        <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}>{explainData.ml_event.iso_score?.toFixed(3)}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid var(--surface-subtle)' }}>
                        <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600 }}>IP Reputation</td>
                        <td style={{ padding: '5px 8px', fontFamily: 'monospace' }}>{explainData.ml_event.redis_rep}</td>
                      </tr>
                      {explainData.ml_event.matched_vars && (
                        <tr>
                          <td style={{ color: 'var(--text-secondary)', padding: '5px 0', fontWeight: 600, verticalAlign: 'top' }}>Matched Variables</td>
                          <td style={{ padding: '5px 8px', fontFamily: 'monospace', wordBreak: 'break-all' }}>{explainData.ml_event.matched_vars}</td>
                        </tr>
                      )}
                    </tbody></table>
                  </>
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
                background: 'var(--surface-subtle)',
                border: '1px solid var(--border-color)',
                borderRadius: showRawJson ? '6px 6px 0 0' : '6px',
                cursor: 'pointer', userSelect: 'none',
              }}
            >
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Raw Audit Log (JSON)</span>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                {onMarkFalsePositive && (
                  <button
                    className="pagination-btn"
                    onClick={(e) => { e.stopPropagation(); onMarkFalsePositive(log); }}
                    style={{ padding: '3px 8px', fontSize: '11px', borderColor: 'rgba(16, 185, 129, 0.4)', background: 'rgba(16, 185, 129, 0.05)', color: 'var(--success-color)' }}
                  >
                    <ShieldCheck size={13} color="var(--success-color)" />
                    <span>Mark as FP</span>
                  </button>
                )}
                <button
                  className="pagination-btn"
                  onClick={(e) => { e.stopPropagation(); handleCopy(); }}
                  style={{ padding: '3px 8px', fontSize: '11px' }}
                >
                  {copied ? <Check size={13} color="var(--success-color)" /> : <Copy size={13} />}
                  <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
                </button>
                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{showRawJson ? '▼' : '►'}</span>
              </div>
            </div>
            {showRawJson && (
              <div style={{ border: '1px solid var(--border-color)', borderTop: 'none', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', overflow: 'hidden' }}>
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
