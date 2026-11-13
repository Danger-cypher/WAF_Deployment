import { useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Keyboard, X, ArrowDown, ArrowUp, CornerDownLeft, Search } from 'lucide-react';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { useBodyScrollLock } from '../hooks/useBodyScrollLock';
import { useFocusTrap } from '../hooks/useFocusTrap';

const SHORTCUT_GROUPS = [
  {
    category: 'Global Navigation',
    items: [
      { keys: ['Ctrl', 'K'], altKeys: ['⌘', 'K'], description: 'Open Command Palette / Fast Page Jump' },
      { keys: ['?'], description: 'Show or hide this keyboard shortcuts cheatsheet' },
      { keys: ['Esc'], description: 'Close any active modal, drawer, or dropdown' },
    ],
  },
  {
    category: 'Events & Alert Triage (Queue Mode)',
    items: [
      { keys: ['j'], altKeys: ['↓'], description: 'Select next security event row' },
      { keys: ['k'], altKeys: ['↑'], description: 'Select previous security event row' },
      { keys: ['Enter'], description: 'Inspect selected event (open inspection drawer)' },
      { keys: ['f'], description: 'Flag selected event as False Positive' },
      { keys: ['x'], description: 'Create WAF rule / exception from selected event' },
      { keys: ['e'], description: 'Toggle inline payload expansion' },
      { keys: ['/'], description: 'Jump to search and filter input' },
    ],
  },
  {
    category: 'Log Inspection Drawer',
    items: [
      { keys: ['↓'], altKeys: ['j'], description: 'Step to next event in queue' },
      { keys: ['↑'], altKeys: ['k'], description: 'Step to previous event in queue' },
      { keys: ['c'], description: 'Copy raw event JSON to clipboard' },
      { keys: ['f'], description: 'Mark current event as False Positive' },
      { keys: ['Esc'], description: 'Close inspection drawer' },
    ],
  },
];

export default function KeyboardShortcutsModal({ isOpen, onClose }) {
  const modalRef = useRef(null);

  useEscapeToClose(onClose, isOpen);
  useBodyScrollLock(isOpen);
  useFocusTrap(modalRef, isOpen);

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="modal-overlay" style={{ zIndex: 'var(--z-dialog, 1500)' }} onClick={onClose}>
        <motion.div
          ref={modalRef}
          className="modal-content"
          role="dialog"
          aria-modal="true"
          aria-labelledby="shortcuts-modal-title"
          style={{
            maxWidth: '640px',
            width: '92vw',
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            gap: '18px',
            padding: '24px',
            overflowY: 'auto',
          }}
          onClick={(e) => e.stopPropagation()}
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
        >
          {/* Header */}
          <div className="modal-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '14px' }}>
            <div id="shortcuts-modal-title" style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)' }}>
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                width: '32px', height: '32px', borderRadius: '8px',
                background: 'var(--accent-bg)', border: '1px solid var(--accent-border)',
              }}>
                <Keyboard size={18} color="var(--accent-color)" />
              </div>
              <span>SecOps Analyst Keyboard Shortcuts</span>
            </div>
            <button
              type="button"
              className="modal-close-btn"
              onClick={onClose}
              aria-label="Close shortcuts cheatsheet"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
            >
              <X size={18} />
            </button>
          </div>

          {/* Body */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {SHORTCUT_GROUPS.map((group) => (
              <div key={group.category} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ fontSize: '11.5px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-secondary)' }}>
                  {group.category}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', background: 'var(--surface-subtle)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)', padding: '6px 12px' }}>
                  {group.items.map((item, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '7px 4px',
                        borderBottom: idx < group.items.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                        fontSize: '13px',
                      }}
                    >
                      <span style={{ color: 'var(--text-primary)' }}>{item.description}</span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        {item.keys.map((k, i) => (
                          <kbd
                            key={i}
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              fontWeight: 600,
                              color: 'var(--text-primary)',
                              background: 'var(--bg-card)',
                              border: '1px solid var(--border-strong)',
                              borderRadius: '4px',
                              padding: '2px 7px',
                              boxShadow: '0 1px 2px rgba(0,0,0,0.3)',
                            }}
                          >
                            {k}
                          </kbd>
                        ))}
                        {item.altKeys && (
                          <>
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px', margin: '0 2px' }}>or</span>
                            {item.altKeys.map((k, i) => (
                              <kbd
                                key={i}
                                style={{
                                  fontFamily: 'var(--font-mono)',
                                  fontSize: '11px',
                                  fontWeight: 600,
                                  color: 'var(--text-primary)',
                                  background: 'var(--bg-card)',
                                  border: '1px solid var(--border-strong)',
                                  borderRadius: '4px',
                                  padding: '2px 7px',
                                  boxShadow: '0 1px 2px rgba(0,0,0,0.3)',
                                }}
                              >
                                {k}
                              </kbd>
                            ))}
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-color)', paddingTop: '14px', marginTop: '4px' }}>
            <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
              Press <kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 5px', background: 'var(--bg-card)', border: '1px solid var(--border-strong)', borderRadius: '3px' }}>?</kbd> anytime to open this view.
            </span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onClose}
            >
              Done
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
