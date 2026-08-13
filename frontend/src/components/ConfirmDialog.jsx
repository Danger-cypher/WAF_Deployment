import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle } from 'lucide-react';
import Button from './Button';

/**
 * The one shared confirmation modal — pair with useConfirm(). Replaces
 * window.confirm() across the app so destructive actions get the same
 * themed, keyboard-accessible dialog instead of an unstyled OS prompt.
 */
export default function ConfirmDialog({ request, onConfirm, onCancel }) {
  const confirmBtnRef = useRef(null);
  const cancelBtnRef = useRef(null);

  useEffect(() => {
    if (!request) return;
    (request.danger ? cancelBtnRef : confirmBtnRef).current?.focus();

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [request, onCancel]);

  return (
    <AnimatePresence>
      {request && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          style={{
            position: 'fixed', inset: 0, background: 'var(--overlay-bg)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100000, padding: '24px',
          }}
          onClick={onCancel}
        >
          <motion.div
            initial={{ opacity: 0, y: 12, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8, scale: 0.97 }}
            transition={{ duration: 0.15 }}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
            aria-describedby="confirm-dialog-message"
            style={{
              width: '420px', maxWidth: '92vw', background: 'var(--bg-card)',
              border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-lg)', padding: '20px',
              boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', gap: '12px', marginBottom: '18px' }}>
              {request.danger && (
                <span style={{
                  flexShrink: 0, width: '34px', height: '34px', borderRadius: '50%',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'var(--danger-bg)', color: 'var(--danger-color)',
                }}>
                  <AlertTriangle size={17} />
                </span>
              )}
              <div>
                <h3 id="confirm-dialog-title" style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {request.title || 'Confirm action'}
                </h3>
                <p id="confirm-dialog-message" style={{ margin: '6px 0 0', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {request.message}
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <Button ref={cancelBtnRef} variant="secondary" size="sm" onClick={onCancel}>
                {request.cancelLabel || 'Cancel'}
              </Button>
              <Button
                ref={confirmBtnRef}
                variant={request.danger ? 'danger' : 'primary'}
                size="sm"
                onClick={onConfirm}
              >
                {request.confirmLabel || 'Confirm'}
              </Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
