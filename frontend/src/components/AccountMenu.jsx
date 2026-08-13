import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, LogOut, ChevronDown, Sun, Moon, Monitor } from 'lucide-react';
import { initialsFor } from '../utils/helpers';
import { useTheme } from '../hooks/useTheme';

const THEME_OPTIONS = [
  { mode: 'light', label: 'Light', icon: Sun },
  { mode: 'dark', label: 'Dark', icon: Moon },
  { mode: 'system', label: 'System', icon: Monitor },
];

export default function AccountMenu({ username, userRole, onOpenProfile, onLogout }) {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);
  const isAdmin = userRole === 'admin';
  const { mode, setTheme } = useTheme();

  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  return (
    <div ref={menuRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <button
        onClick={() => setIsOpen((v) => !v)}
        title="Account menu"
        style={{
          display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--surface-subtle)',
          border: '1px solid var(--border-color)', padding: '4px 10px 4px 4px', borderRadius: 'var(--radius-pill)',
          cursor: 'pointer', transition: 'background 0.2s',
        }}
        className="hover-glow"
      >
        <span
          style={{
            width: '26px', height: '26px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '11px', fontWeight: 700,
            background: isAdmin ? 'var(--danger-bg)' : 'var(--accent-bg)',
            color: isAdmin ? 'var(--danger-color)' : 'var(--accent-color)',
            border: isAdmin ? '1px solid var(--danger-border)' : '1px solid var(--accent-border)',
          }}
        >
          {initialsFor(username)}
        </span>
        <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 500 }}>@{username}</span>
        <ChevronDown size={14} style={{ color: 'var(--text-secondary)', transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            style={{
              position: 'absolute', top: '42px', right: 0, width: '240px',
              background: 'var(--bg-secondary)', backdropFilter: 'blur(20px)',
              border: '1px solid var(--border-color)', borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-card)', zIndex: 9999, overflow: 'hidden',
            }}
          >
            <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>@{username}</div>
              <span style={{
                display: 'inline-block', marginTop: '4px', fontSize: '10px', fontWeight: 700, padding: '2px 8px',
                borderRadius: 'var(--radius-pill)', textTransform: 'uppercase',
                background: isAdmin ? 'var(--danger-bg)' : 'var(--accent-bg)',
                color: isAdmin ? 'var(--danger-color)' : 'var(--accent-color)',
                border: isAdmin ? '1px solid var(--danger-border)' : '1px solid var(--accent-border)',
              }}>
                {userRole}
              </span>
            </div>

            <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border-color)' }}>
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

            <button
              onClick={() => { setIsOpen(false); onOpenProfile(); }}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: '10px', padding: '11px 14px',
                background: 'none', border: 'none', color: 'var(--text-primary)', fontSize: '13px', fontWeight: 600,
                cursor: 'pointer', transition: 'background 0.15s', textAlign: 'left',
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-hover)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <User size={15} />
              Profile
            </button>
            <button
              onClick={() => { setIsOpen(false); onLogout(); }}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: '10px', padding: '11px 14px',
                background: 'none', border: 'none', borderTop: '1px solid var(--border-color)', color: 'var(--danger-color)',
                fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'background 0.15s', textAlign: 'left',
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = 'var(--danger-bg)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <LogOut size={15} />
              Log out
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
