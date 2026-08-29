import { useState, useEffect } from 'react';
import { ShieldAlert, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { getVirtualPatchLibrary, deployVirtualPatch, undeployVirtualPatch, getVirtualPatchHits } from '../services/api';
import Button from './Button';

const SEVERITY_COLORS = {
  critical: { bg: 'var(--danger-bg)', color: 'var(--danger-color)', border: 'var(--danger-border)' },
  high: { bg: 'var(--sev-high-bg, var(--danger-bg))', color: 'var(--sev-high, var(--danger-color))', border: 'var(--danger-border)' },
};

function SeverityBadge({ severity }) {
  const c = SEVERITY_COLORS[severity] || SEVERITY_COLORS.high;
  return (
    <span style={{
      fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: 'var(--radius-pill, 999px)',
      textTransform: 'uppercase', background: c.bg, color: c.color, border: `1px solid ${c.border}`,
    }}>
      {severity}
    </span>
  );
}

function DeployStatusBadge({ mode }) {
  if (!mode) {
    return (
      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Not deployed</span>
    );
  }
  const isBlock = mode === 'block';
  return (
    <span style={{
      fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: 'var(--radius-pill, 999px)',
      textTransform: 'uppercase',
      background: isBlock ? 'var(--success-bg)' : 'var(--accent-bg)',
      color: isBlock ? 'var(--success-color)' : 'var(--accent-color)',
      border: isBlock ? '1px solid rgba(16,185,129,0.3)' : '1px solid var(--accent-border)',
    }}>
      {isBlock ? 'Blocking' : 'Detect only'}
    </span>
  );
}

export default function CveTemplateLibrary({ userRole, showToast }) {
  const [library, setLibrary] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [hits, setHits] = useState({});
  const isAdmin = userRole === 'admin';

  const fetchLibrary = async () => {
    try {
      const data = await getVirtualPatchLibrary();
      setLibrary(data);
    } catch (err) {
      showToast('Failed to load CVE template library: ' + (err.message || 'Unknown error'), 'error');
    }
  };

  useEffect(() => { fetchLibrary(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleExpand = async (entry) => {
    const next = expandedId === entry.cve_id ? null : entry.cve_id;
    setExpandedId(next);
    if (next && entry.deployed_mode && !hits[entry.cve_id]) {
      try {
        const h = await getVirtualPatchHits(entry.cve_id, 24);
        setHits((prev) => ({ ...prev, [entry.cve_id]: h }));
      } catch {
        // Hit-count is a nice-to-have on an already-successful expand — don't toast on failure.
      }
    }
  };

  const handleDeploy = async (cveId, mode) => {
    setBusyId(cveId);
    try {
      await deployVirtualPatch(cveId, mode);
      showToast(`${cveId} deployed in ${mode === 'block' ? 'blocking' : 'detect-only'} mode.`);
      fetchLibrary();
    } catch (err) {
      showToast(`Failed to deploy ${cveId}: ` + (err.message || 'Unknown error'), 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleUndeploy = async (cveId) => {
    setBusyId(cveId);
    try {
      await undeployVirtualPatch(cveId);
      showToast(`${cveId} removed.`);
      fetchLibrary();
    } catch (err) {
      showToast(`Failed to remove ${cveId}: ` + (err.message || 'Unknown error'), 'error');
    } finally {
      setBusyId(null);
    }
  };

  if (!library) {
    return (
      <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', padding: '24px', marginBottom: '20px', color: 'var(--text-secondary)' }}>
        Loading CVE template library…
      </div>
    );
  }

  return (
    <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', padding: '24px', marginBottom: '20px' }}>
      <div style={{ marginBottom: '16px' }}>
        <h3 style={{ margin: 0, color: 'var(--text-primary)', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={20} color="var(--danger-color)" />
          CVE Virtual Patch Library
        </h3>
        <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
          Curated, pre-built rules for well-known CVEs — deploy in Detect mode to observe real hits before
          switching to Block. These are signature-based mitigations to buy time, not a substitute for patching
          the underlying software.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {library.map((entry) => {
          const expanded = expandedId === entry.cve_id;
          const busy = busyId === entry.cve_id;
          const h = hits[entry.cve_id];
          return (
            <div key={entry.cve_id} style={{
              border: '1px solid var(--border-color)', borderRadius: '10px', overflow: 'hidden',
              background: entry.deployed_mode ? 'var(--surface-subtle)' : 'transparent',
            }}>
              <div
                onClick={() => toggleExpand(entry)}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', padding: '12px 14px', cursor: 'pointer' }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-color)', fontWeight: 600 }}>{entry.cve_id}</span>
                    <SeverityBadge severity={entry.severity} />
                    <DeployStatusBadge mode={entry.deployed_mode} />
                  </div>
                  <span style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: 600 }}>{entry.title}</span>
                  <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>{entry.affected_product}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                  {expanded ? <ChevronUp size={16} color="var(--text-muted)" /> : <ChevronDown size={16} color="var(--text-muted)" />}
                </div>
              </div>

              {expanded && (
                <div style={{ padding: '0 14px 16px', borderTop: '1px solid var(--border-color)' }}>
                  <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: '12px 0' }}>
                    {entry.description}
                  </p>
                  <div style={{ display: 'flex', gap: '14px', marginBottom: '10px', flexWrap: 'wrap' }}>
                    {entry.references.map((url) => (
                      <a key={url} href={url} target="_blank" rel="noreferrer" style={{ fontSize: '11.5px', color: 'var(--accent-color)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <ExternalLink size={11} /> {url.replace(/^https?:\/\//, '')}
                      </a>
                    ))}
                  </div>

                  {entry.deployed_mode && h && (
                    <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                      Last 24h: <strong style={{ color: 'var(--text-primary)' }}>{h.total_matches}</strong> match{h.total_matches === 1 ? '' : 'es'}
                      {entry.deployed_mode === 'block' && h.total_matches > 0 && ` (${h.sole_match_count} would have gone unblocked without this rule)`}
                    </div>
                  )}

                  <details style={{ marginBottom: '12px' }}>
                    <summary style={{ fontSize: '11.5px', color: 'var(--text-muted)', cursor: 'pointer' }}>View generated rule (id {entry.rule_id})</summary>
                    <pre style={{
                      fontSize: '11px', background: 'var(--editor-bg, #0d1117)', color: 'var(--editor-string, #a5d6ff)',
                      padding: '10px', borderRadius: '6px', overflowX: 'auto', marginTop: '8px', whiteSpace: 'pre-wrap',
                    }}>
                      {entry.rule_body.replace(/__ID__/g, entry.rule_id).replace(/__MODE__/g, entry.deployed_mode === 'block' ? 'block' : 'pass')}
                    </pre>
                  </details>

                  {isAdmin && (
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {!entry.deployed_mode && (
                        <>
                          <Button variant="secondary" size="sm" loading={busy} onClick={() => handleDeploy(entry.cve_id, 'detect')}>
                            Deploy (Detect Only)
                          </Button>
                          <Button variant="danger" size="sm" loading={busy} onClick={() => handleDeploy(entry.cve_id, 'block')}>
                            Deploy (Block)
                          </Button>
                        </>
                      )}
                      {entry.deployed_mode === 'detect' && (
                        <>
                          <Button variant="danger" size="sm" loading={busy} onClick={() => handleDeploy(entry.cve_id, 'block')}>
                            Promote to Block
                          </Button>
                          <Button variant="secondary" size="sm" loading={busy} onClick={() => handleUndeploy(entry.cve_id)}>
                            Undeploy
                          </Button>
                        </>
                      )}
                      {entry.deployed_mode === 'block' && (
                        <>
                          <Button variant="secondary" size="sm" loading={busy} onClick={() => handleDeploy(entry.cve_id, 'detect')}>
                            Downgrade to Detect
                          </Button>
                          <Button variant="secondary" size="sm" loading={busy} onClick={() => handleUndeploy(entry.cve_id)}>
                            Undeploy
                          </Button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
