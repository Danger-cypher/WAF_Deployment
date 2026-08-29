import { useState, useEffect } from 'react';
import { Check, Code, RefreshCw, X } from 'lucide-react';
import { getCustomRules, saveCustomRules } from '../services/api';
import Button from '../components/Button';
import CveTemplateLibrary from '../components/CveTemplateLibrary';
import Toast from '../components/Toast';
import { useToast } from '../hooks/useToast';

// ModSecurity SecRule string literals are double-quoted — real request data
// (URI, User-Agent) landing in one of these templates could otherwise break
// the generated rule's syntax if it happens to contain a literal quote.
const escapeForSecRule = (value) => String(value || '').replace(/"/g, '\\"');

const randomRuleId = () => 1000000 + Math.floor(Math.random() * 900000);

// Custom Rules Editor (Virtual Patching) Component
export default function CustomRulesEditor({ userRole, initialLogContext, onConsumeInitialLogContext }) {
  const [rulesContent, setRulesContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const { toast, showToast } = useToast();

  // Captured once at mount ("Create Rule from This Event" in the Events
  // drawer hands this off via App.jsx) — pre-fills the quick templates
  // below with the real IP/URI/User-Agent instead of placeholder values.
  const [logContext] = useState(initialLogContext || null);
  const [bannerDismissed, setBannerDismissed] = useState(false);
  useEffect(() => {
    if (initialLogContext) onConsumeInitialLogContext?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
    <div>
      {logContext && !bannerDismissed && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px',
          background: 'var(--danger-bg)', border: '1px solid var(--danger-border)', borderRadius: '10px',
          padding: '12px 16px', marginBottom: '20px', fontSize: '13px',
        }}>
          <span style={{ color: 'var(--text-primary)' }}>
            Creating a rule from a flagged event —
            {logContext.client_ip && <> IP <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--danger-color)' }}>{logContext.client_ip}</code></>}
            {logContext.uri && <>, URI <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--danger-color)' }}>{logContext.uri}</code></>}
            . Pick a quick template below — it's pre-filled with these real values.
          </span>
          <button
            onClick={() => setBannerDismissed(true)}
            aria-label="Dismiss"
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex' }}
          >
            <X size={16} />
          </button>
        </div>
      )}

      <CveTemplateLibrary userRole={userRole} showToast={showToast} />
      <Toast toast={toast} />

      {/* These are two distinct mental models sharing this page — the
          library above deploys curated, pre-vetted rules for known CVEs;
          this editor below is free-form for anything not in that library.
          A plain divider row makes that split explicit instead of letting
          two similarly-named cards run together. */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: '24px 0' }}>
        <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
        <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
          Or write a custom rule
        </span>
        <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
      </div>

    <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ margin: 0, color: 'var(--text-primary)', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Code size={20} color="var(--sev-low)" />
            Custom Rule Editor <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)' }}>(Advanced)</span>
          </h3>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
            Write custom CyberSentinel Engine rules to mitigate zero-day vulnerabilities in real time. Rules are validated for syntax before reload.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <Button
            variant="secondary"
            icon={RefreshCw}
            loading={loading}
            disabled={saving}
            onClick={fetchRules}
          >
            Reload File
          </Button>
          <Button
            variant="primary"
            icon={Check}
            loading={saving}
            disabled={loading || userRole !== 'admin'}
            onClick={handleSave}
            style={{ background: 'var(--sev-low)', color: '#fff' }}
          >
            {saving ? 'Validating & Applying...' : 'Apply & Reload WAF'}
          </Button>
        </div>
      </div>

      {message.text && (
        <div style={{
          padding: '12px 16px', borderRadius: '8px', marginBottom: '16px', fontSize: '13px', fontWeight: 500,
          background: message.type === 'success' ? 'var(--success-bg)' : 'var(--danger-bg)',
          border: message.type === 'success' ? '1px solid var(--success-glow)' : '1px solid var(--danger-border)',
          color: message.type === 'success' ? 'var(--success-color)' : 'var(--danger-color)',
          whiteSpace: 'pre-wrap', fontFamily: 'var(--font-mono)'
        }}>
          {message.text}
        </div>
      )}

      {/* Quick Snippet Helpers */}
      <div style={{ marginBottom: '16px', display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600 }}>Quick Patch Templates:</span>
        <button
          onClick={() => insertSnippet(`SecRule REQUEST_HEADERS:User-Agent "@contains ${escapeForSecRule(logContext?.user_agent) || 'BadBot'}" "id:${randomRuleId()},phase:1,deny,status:403,msg:'Blocked Bad Bot'"`)}
          style={{ background: 'var(--surface-hover)', border: '1px solid var(--border-strong)', color: 'var(--editor-key)', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Block User-Agent
        </button>
        <button
          onClick={() => insertSnippet(`SecRule REQUEST_URI "@contains ${escapeForSecRule(logContext?.uri) || '/vulnerable-endpoint'}" "id:${randomRuleId()},phase:1,deny,status:403,msg:'Virtual Patch Endpoint'"`)}
          style={{ background: 'var(--surface-hover)', border: '1px solid var(--border-strong)', color: 'var(--editor-key)', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Block URI Endpoint
        </button>
        <button
          onClick={() => insertSnippet(`SecRule REMOTE_ADDR "@ipMatch ${escapeForSecRule(logContext?.client_ip) || '192.168.1.100'}" "id:${randomRuleId()},phase:1,deny,status:403,msg:'Blocked Attacker IP'"`)}
          style={{ background: 'var(--surface-hover)', border: '1px solid var(--border-strong)', color: 'var(--editor-key)', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Block IP Address
        </button>
        <button
          onClick={() => insertSnippet(`SecRule ARGS:payload "@rx (?i)<script>" "id:${randomRuleId()},phase:2,deny,status:403,msg:'Parameter Regex Filter'"`)}
          style={{ background: 'var(--surface-hover)', border: '1px solid var(--border-strong)', color: 'var(--editor-key)', padding: '5px 12px', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}
        >
          + Parameter Regex Filter
        </button>
      </div>

      {/* Code Editor */}
      <div style={{ position: 'relative', borderRadius: '8px', border: '1px solid var(--editor-border)', overflow: 'hidden' }}>
        <div style={{ background: 'var(--editor-header-bg)', padding: '8px 16px', borderBottom: '1px solid var(--editor-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>/etc/nginx/modsec/custom-rules.conf</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '11px', color: 'var(--success-color)', background: 'var(--success-bg)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
              {rulesContent.split('\n').filter(line => line.trim().startsWith('SecRule')).length} Active Custom Rules
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>CyberSentinel Engine v2.0</span>
          </div>
        </div>
        <textarea
          value={rulesContent}
          onChange={(e) => setRulesContent(e.target.value)}
          disabled={loading || userRole !== 'admin'}
          placeholder="# Write custom CyberSentinel Engine rules here...&#10;&#10;# Example:&#10;SecRule REQUEST_URI &quot;@contains /vulnerable-api&quot; &quot;id:1000001,phase:1,deny,status:403,msg:'Zero-day Virtual Patch'&quot;"
          rows={18}
          style={{
            width: '100%',
            background: 'var(--editor-bg)',
            color: 'var(--editor-string)',
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
    </div>
  );
}
