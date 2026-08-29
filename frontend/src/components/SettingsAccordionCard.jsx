import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

const TONES = {
  active: { bg: 'var(--success-bg)', color: 'var(--success-color)' },
  inactive: { bg: 'var(--surface-hover)', color: 'var(--text-secondary)' },
  warn: { bg: 'var(--sev-low-bg)', color: 'var(--sev-low)' },
};

/**
 * Collapsible wrapper for one Settings sub-section (P1: Settings redesign,
 * Phase 1 — "wrap, don't rewrite"). Purely presentational: the caller's
 * existing form/state/handlers/API calls are passed through as `children`
 * completely unchanged. Built entirely on classes/CSS vars that already
 * exist in index.css (.panel-card) — no new design system, no Tailwind.
 *
 * `status`/`tone` let an admin see whether a section is doing anything
 * without opening it — the actual problem this exists to fix (Hardening
 * used to stack 6 always-expanded forms with no way to tell which were
 * active short of reading each one).
 */
export default function SettingsAccordionCard({ icon: Icon, title, status, tone = 'inactive', defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  const t = TONES[tone] || TONES.inactive;

  return (
    <div className="panel-card" style={{ padding: 0, overflow: 'hidden' }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '16px 20px', background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left',
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
          {Icon && <Icon size={18} color="var(--sev-low)" />}
          {title}
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
          {status && (
            <span style={{
              fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '999px',
              textTransform: 'uppercase', background: t.bg, color: t.color, whiteSpace: 'nowrap',
            }}>
              {status}
            </span>
          )}
          <ChevronDown size={16} color="var(--text-muted)" style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
        </span>
      </button>
      {open && (
        <div style={{ padding: '4px 20px 20px', borderTop: '1px solid var(--surface-hover)' }}>
          {children}
        </div>
      )}
    </div>
  );
}
