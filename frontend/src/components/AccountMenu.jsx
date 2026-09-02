import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, LogOut, ChevronDown, Sun, Moon, Monitor } from 'lucide-react';
import { initialsFor } from '../utils/helpers';
import { useTheme } from '../hooks/useTheme';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { getMyProfile } from '../services/api';

const THEME_OPTIONS = [
  { mode: 'light', label: 'Light', icon: Sun },
  { mode: 'dark', label: 'Dark', icon: Moon },
  { mode: 'system', label: 'System', icon: Monitor },
];

// A light spring reads as more "expensive" than a flat duration-based fade —
// snappy but soft, rather than linear.
const PANEL_SPRING = { type: 'spring', stiffness: 420, damping: 32 };

const menuItemStyle = {
  width: '100%', display: 'flex', alignItems: 'center', gap: '10px', padding: '11px 14px',
  background: 'none', border: 'none', fontSize: '13px', fontWeight: 600,
  cursor: 'pointer', transition: 'background 0.15s, color 0.15s', textAlign: 'left',
};

export default function AccountMenu({ username, userRole, onOpenProfile, onLogout }) {
  const [isOpen, setIsOpen] = useState(false);
  // Best-effort — the menu is fully usable off `username` alone the instant
  // it mounts; a nicer first+last-name avatar/header is a bonus once this
  // resolves, never a dependency (see initialsFor's fallback behavior).
  const [displayName, setDisplayName] = useState('');
  const menuRef = useRef(null);
  const isAdmin = userRole === 'admin';
  const { mode, setTheme } = useTheme();

  useEscapeToClose(() => setIsOpen(false), isOpen);

  useEffect(() => {
    getMyProfile().then((p) => setDisplayName(p?.display_name || '')).catch(() => {});
  }, []);

  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  // Standard menu-button behavior (WAI-ARIA Menu Button pattern): opening
  // the menu moves focus into it, onto the first actionable item.
  useEffect(() => {
    if (!isOpen) return;
    const timer = setTimeout(() => {
      menuRef.current?.querySelector('[role="menuitem"]')?.focus();
    }, 0);
    return () => clearTimeout(timer);
  }, [isOpen]);

  // Arrow-key traversal across just the menuitem-role actions (Profile,
  // Sign out) — deliberately not the theme radiogroup above them, which is
  // its own ARIA widget with its own (tab-reachable) interaction model.
  const handleMenuKeyDown = (e) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const items = Array.from(menuRef.current?.querySelectorAll('[role="menuitem"]') || []);
    if (!items.length) return;
    e.preventDefault();
    const currentIndex = items.indexOf(document.activeElement);
    const delta = e.key === 'ArrowDown' ? 1 : -1;
    items[(currentIndex + delta + items.length) % items.length]?.focus();
  };

  const initials = initialsFor(username, displayName);
  const roleBadgeStyle = {
    background: isAdmin ? 'var(--danger-bg)' : 'var(--accent-bg)',
    color: isAdmin ? 'var(--danger-color)' : 'var(--accent-color)',
    border: isAdmin ? '1px solid var(--danger-border)' : '1px solid var(--accent-border)',
  };

  // Mouse hover and keyboard focus get identical visual feedback — a
  // keyboard user arrowing through the menu needs the same "which item is
  // active" signal a mouse user gets, not just the browser's default
  // (often near-invisible) focus outline.
  const focusHover = (hoverBg, hoverColor, restColor) => ({
    onMouseEnter: (e) => { e.currentTarget.style.background = hoverBg; e.currentTarget.style.color = hoverColor; },
    onMouseLeave: (e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = restColor; },
    onFocus: (e) => { e.currentTarget.style.background = hoverBg; e.currentTarget.style.color = hoverColor; },
    onBlur: (e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = restColor; },
  });

  return (
    <div ref={menuRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }} onKeyDown={handleMenuKeyDown}>
      <button
        onClick={() => setIsOpen((v) => !v)}
        aria-label="Account menu"
        aria-haspopup="true"
        aria-expanded={isOpen}
        title="Account menu"
        style={{
          position: 'relative', display: 'flex', alignItems: 'center', gap: '4px',
          background: 'transparent', border: 'none', padding: '2px', cursor: 'pointer',
        }}
      >
        <span
          style={{
            width: '30px', height: '30px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '12px', fontWeight: 700, transition: 'transform 0.15s ease',
            background: isAdmin ? 'var(--danger-bg)' : 'var(--accent-bg)',
            color: isAdmin ? 'var(--danger-color)' : 'var(--accent-color)',
            border: isAdmin ? '1.5px solid var(--danger-color)' : '1.5px solid var(--accent-color)',
          }}
        >
          {initials}
        </span>
        {/* Active-session dot — the cutout border matches the topbar
            background so it reads as a notch out of the avatar, not a
            sticker on top of it. */}
        <span
          aria-hidden="true"
          style={{
            position: 'absolute', bottom: '0', right: '13px',
            width: '9px', height: '9px', borderRadius: '50%',
            background: 'var(--success-color)', border: '2px solid var(--topbar-bg)',
          }}
        />
        <ChevronDown size={13} style={{ color: 'var(--text-muted)', transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            role="menu"
            aria-label="Account"
            initial={{ opacity: 0, y: 8, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.96 }}
            transition={PANEL_SPRING}
            style={{
              position: 'absolute', top: '42px', right: 0, width: '248px',
              background: 'var(--bg-secondary)', backdropFilter: 'blur(20px)',
              border: '1px solid var(--border-color)', borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-card)', zIndex: 9999, overflow: 'hidden',
            }}
          >
            {/* Identity — the avatar trigger stays icon-only, so the panel is
                the one place identity is actually spelled out (matches
                GitHub's split rather than repeating @username in both). */}
            <div style={{ padding: '14px 14px 12px' }}>
              <div style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {displayName || `@${username}`}
              </div>
              {displayName && (
                <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '1px' }}>@{username}</div>
              )}
              <span style={{
                display: 'inline-block', marginTop: '7px', fontSize: '10px', fontWeight: 700, padding: '2px 8px',
                borderRadius: 'var(--radius-pill)', textTransform: 'uppercase', ...roleBadgeStyle,
              }}>
                {userRole}
              </span>
            </div>

            <div style={{ height: '1px', background: 'var(--border-color)' }} />

            <div style={{ padding: '10px 14px 12px' }}>
              <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                Theme
              </div>
              <div
                role="radiogroup"
                aria-label="Theme"
                style={{ display: 'flex', gap: '4px', background: 'var(--surface-subtle)', borderRadius: 'var(--radius-md)', padding: '3px' }}
              >
                {THEME_OPTIONS.map(({ mode: optionMode, label, icon: Icon }) => {
                  const active = mode === optionMode;
                  return (
                    <button
                      key={optionMode}
                      role="radio"
                      aria-checked={active}
                      title={label}
                      onClick={() => setTheme(optionMode)}
                      style={{
                        flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '3px',
                        padding: '6px 4px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                        background: active ? 'var(--accent-bg)' : 'transparent',
                        color: active ? 'var(--accent-color)' : 'var(--text-secondary)',
                        transition: 'background 0.15s, color 0.15s',
                      }}
                    >
                      <Icon size={14} />
                      <span style={{ fontSize: '10px', fontWeight: 600 }}>{label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div style={{ height: '1px', background: 'var(--border-color)' }} />

            <button
              role="menuitem"
              onClick={() => { setIsOpen(false); onOpenProfile(); }}
              style={{ ...menuItemStyle, color: 'var(--text-primary)' }}
              {...focusHover('var(--surface-hover)', 'var(--text-primary)', 'var(--text-primary)')}
            >
              <User size={15} />
              Profile
            </button>

            <div style={{ height: '1px', background: 'var(--border-color)' }} />

            {/* Muted until interacted with, not red-by-default — sign-out is
                a normal action, not a warning (the "scary red logout button"
                is a known anti-pattern; Vercel/Linear both avoid it). */}
            <button
              role="menuitem"
              onClick={() => { setIsOpen(false); onLogout(); }}
              style={{ ...menuItemStyle, color: 'var(--text-secondary)' }}
              {...focusHover('var(--danger-bg)', 'var(--danger-color)', 'var(--text-secondary)')}
            >
              <LogOut size={15} />
              Sign out
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
