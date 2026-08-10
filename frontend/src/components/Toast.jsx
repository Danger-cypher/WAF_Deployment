import { motion, AnimatePresence } from 'framer-motion';
import { Check, X } from 'lucide-react';

/**
 * The one shared "success/error" popup — pair with useToast(). Previously
 * reimplemented independently in 6 different files with drifting position,
 * color, and z-index; this is the single canonical version.
 */
export default function Toast({ toast }) {
  return (
    <AnimatePresence>
      {toast && (
        <motion.div
          initial={{ opacity: 0, y: 20, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 10, scale: 0.95 }}
          role="status"
          style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            zIndex: 99999,
            padding: '12px 20px',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontWeight: 600,
            fontSize: '13px',
            color: '#fff',
            background: toast.type === 'error' ? 'var(--danger-color)' : 'var(--success-color)',
            border: `1px solid ${toast.type === 'error' ? 'var(--danger-color)' : 'var(--success-color)'}`,
            boxShadow: `0 10px 30px rgba(0,0,0,0.4), 0 0 20px ${toast.type === 'error' ? 'var(--danger-glow)' : 'var(--success-glow)'}`,
          }}
        >
          {toast.type === 'error' ? <X size={16} /> : <Check size={16} />}
          <span>{toast.message}</span>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
