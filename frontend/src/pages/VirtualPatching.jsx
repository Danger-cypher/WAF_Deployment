import { useState, useEffect } from 'react';
import { Check, Code, RefreshCw } from 'lucide-react';
import { getCustomRules, saveCustomRules } from '../services/api';

// Custom Rules Editor (Virtual Patching) Component
export default function CustomRulesEditor({ userRole }) {
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
            Virtual Patching (Custom CyberSentinel Engine Rules)
          </h3>
          <p style={{ margin: '4px 0 0 0', color: '#71717a', fontSize: '13px' }}>
            Write custom CyberSentinel Engine rules to mitigate zero-day vulnerabilities in real time. Rules are validated for syntax before reload.
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
            <span style={{ fontSize: '11px', color: '#52525b' }}>CyberSentinel Engine v2.0</span>
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
