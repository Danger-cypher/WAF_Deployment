import { useState, useEffect, useRef, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { Search, CornerDownLeft, ArrowUp, ArrowDown, Loader2 } from 'lucide-react';
import { getRuleDetails } from '../services/api';
import { getFlatNavItems } from '../navigation';
import { useEscapeToClose } from '../hooks/useEscapeToClose';

const IP_PATTERN = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const RULE_ID_PATTERN = /^\d{3,7}$/;

/**
 * Ctrl/Cmd+K jump-to-anywhere. v1 scope, deliberately: navigate to any of
 * the app's destinations, or resolve an IP / rule ID against the endpoints
 * those pages already query themselves (GET /rules/{id} to validate a rule
 * exists before navigating; IP search reuses Events' own free-text filter —
 * no new backend, no new search index, matching what each target page
 * would do with the same input typed directly into its own search box.
 */
export default function CommandPalette({ isOpen, onClose, isAdmin, onNavigate, onSearchIp, onSearchRule }) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [ruleLookupState, setRuleLookupState] = useState({ loading: false, error: '' });
  const inputRef = useRef(null);

  useEscapeToClose(onClose, isOpen);

  useEffect(() => {
    if (isOpen) {
      const t = setTimeout(() => {
        setQuery('');
        setActiveIndex(0);
        setRuleLookupState({ loading: false, error: '' });
        // Portal content mounts a tick after isOpen flips — focus once it's there.
        inputRef.current?.focus();
      }, 0);
      return () => clearTimeout(t);
    }
  }, [isOpen]);

  const navItems = useMemo(() => getFlatNavItems().filter((item) => !item.adminOnly || isAdmin), [isAdmin]);

  const results = useMemo(() => {
    const q = query.trim();
    const items = [];

    if (q) {
      const matches = navItems.filter((item) => item.label.toLowerCase().includes(q.toLowerCase()));
      matches.forEach((item) => items.push({ kind: 'nav', key: `nav-${item.id}`, item }));
    } else {
      navItems.forEach((item) => items.push({ kind: 'nav', key: `nav-${item.id}`, item }));
    }

    if (IP_PATTERN.test(q)) {
      items.push({ kind: 'ip', key: 'action-ip', value: q });
    } else if (RULE_ID_PATTERN.test(q)) {
      items.push({ kind: 'rule', key: 'action-rule', value: q });
    }

    return items.slice(0, 9);
  }, [query, navItems]);

  useEffect(() => {
    const t = setTimeout(() => {
      setActiveIndex(0);
      setRuleLookupState({ loading: false, error: '' });
    }, 0);
    return () => clearTimeout(t);
  }, [query]);

  if (!isOpen) return null;

  const selectResult = async (result) => {
    if (!result) return;
    if (result.kind === 'nav') {
      onNavigate(result.item.id);
      onClose();
    } else if (result.kind === 'ip') {
      onSearchIp(result.value);
      onClose();
    } else if (result.kind === 'rule') {
      setRuleLookupState({ loading: true, error: '' });
      try {
        await getRuleDetails(result.value);
        onSearchRule(result.value);
        onClose();
      } catch {
        setRuleLookupState({ loading: false, error: `No rule with ID ${result.value} found.` });
      }
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      selectResult(results[activeIndex]);
    }
  };

  const resultLabel = (result) => {
    if (result.kind === 'nav') return { icon: result.item.icon, label: result.item.label, meta: result.item.group };
    if (result.kind === 'ip') return { icon: Search, label: `Search "${result.value}" in Security Events`, meta: 'IP lookup' };
    return { icon: Search, label: `Look up rule ${result.value} in WAF Rules`, meta: 'Rule ID lookup' };
  };

  return createPortal(
    <div className="log-drawer-overlay" style={{ alignItems: 'flex-start', justifyContent: 'center', paddingTop: '12vh' }} onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(560px, 92vw)', maxHeight: '70vh', display: 'flex', flexDirection: 'column',
          background: 'rgba(8, 16, 30, 0.97)', backdropFilter: 'blur(24px)', WebkitBackdropFilter: 'blur(24px)',
          border: '1px solid var(--cyan-bg)', borderRadius: '14px',
          boxShadow: '0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px var(--cyan-bg)',
          overflow: 'hidden',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '14px 16px', borderBottom: '1px solid var(--cyan-bg)' }}>
          <Search size={16} color="var(--text-muted)" style={{ flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Jump to a page, or search an IP / rule ID…"
            aria-label="Command palette search"
            style={{
              flex: 1, background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--text-primary)', fontSize: '14px', fontFamily: 'inherit',
            }}
          />
          <kbd style={{
            fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)',
            border: '1px solid var(--surface-strong)', borderRadius: '4px', padding: '2px 6px',
          }}>ESC</kbd>
        </div>

        <div style={{ overflowY: 'auto', padding: '6px' }}>
          {ruleLookupState.error && (
            <div style={{ padding: '10px 12px', fontSize: '12px', color: 'var(--danger-color)' }}>
              {ruleLookupState.error}
            </div>
          )}
          {results.length === 0 && !ruleLookupState.error ? (
            <div style={{ padding: '24px 12px', textAlign: 'center', fontSize: '13px', color: 'var(--text-muted)' }}>
              No matches. Try a page name, a full IP address, or a numeric rule ID.
            </div>
          ) : (
            results.map((result, index) => {
              const { icon: Icon, label, meta } = resultLabel(result);
              const isActive = index === activeIndex;
              const isLoadingThis = ruleLookupState.loading && result.kind === 'rule';
              return (
                <div
                  key={result.key}
                  onClick={() => selectResult(result)}
                  onMouseEnter={() => setActiveIndex(index)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '10px',
                    padding: '10px 12px', borderRadius: '8px', cursor: 'pointer',
                    background: isActive ? 'var(--cyan-bg)' : 'transparent',
                  }}
                >
                  {isLoadingThis ? (
                    <Loader2 size={15} className="animate-spin" color="var(--accent-color)" style={{ flexShrink: 0 }} />
                  ) : (
                    <Icon size={15} color={isActive ? 'var(--accent-color)' : 'var(--text-muted)'} style={{ flexShrink: 0 }} />
                  )}
                  <span style={{ fontSize: '13px', color: 'var(--text-primary)', flex: 1 }}>{label}</span>
                  {meta && (
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>{meta}</span>
                  )}
                </div>
              );
            })
          )}
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: '16px', padding: '8px 16px',
          borderTop: '1px solid var(--cyan-bg)', fontSize: '11px', color: 'var(--text-muted)',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><ArrowUp size={11} /><ArrowDown size={11} /> Navigate</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><CornerDownLeft size={11} /> Select</span>
        </div>
      </div>
    </div>,
    document.body
  );
}
