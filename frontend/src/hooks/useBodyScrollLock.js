import { useEffect } from 'react';

// Counter to track how many modals/drawers are currently open,
// ensuring nested modals don't prematurely unlock body scroll when one closes.
let activeModalsCount = 0;
let originalOverflow = '';

export function useBodyScrollLock(active = true) {
  useEffect(() => {
    if (!active || typeof document === 'undefined') return;

    if (activeModalsCount === 0) {
      originalOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    }
    activeModalsCount += 1;

    return () => {
      activeModalsCount = Math.max(0, activeModalsCount - 1);
      if (activeModalsCount === 0) {
        document.body.style.overflow = originalOverflow || '';
      }
    };
  }, [active]);
}
