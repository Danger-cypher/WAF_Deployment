import { useEffect } from 'react';

/**
 * Closes a modal/drawer on Escape. None of the app's modals supported this
 * before — mouse was the only way out. Pass `active` (usually the modal's
 * own `isOpen`) so the listener only attaches while it's actually open.
 */
export function useEscapeToClose(onClose, active = true) {
  useEffect(() => {
    if (!active) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [active, onClose]);
}
