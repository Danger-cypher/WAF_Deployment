import { useEffect, useRef } from 'react';

const FOCUSABLE_SELECTORS = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

export function useFocusTrap(ref, active = true) {
  const previousActiveElement = useRef(null);

  useEffect(() => {
    if (!active || !ref.current || typeof document === 'undefined') return;

    previousActiveElement.current = document.activeElement;

    const container = ref.current;
    const focusable = container.querySelectorAll(FOCUSABLE_SELECTORS);
    let timer = null;
    if (focusable.length > 0) {
      // Focus first element or container
      timer = setTimeout(() => {
        if (typeof document === 'undefined' || !container) return;
        if (container.contains(document.activeElement)) return;
        const initialFocus = container.querySelector('[autofocus]') || focusable[0];
        initialFocus?.focus();
      }, 50);
    }

    const handleKeyDown = (e) => {
      if (e.key !== 'Tab') return;

      const elements = Array.from(container.querySelectorAll(FOCUSABLE_SELECTORS)).filter(
        (el) => el.offsetParent !== null // Visible elements only
      );

      if (elements.length === 0) {
        e.preventDefault();
        return;
      }

      const firstElement = elements[0];
      const lastElement = elements[elements.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === firstElement || !container.contains(document.activeElement)) {
          e.preventDefault();
          lastElement.focus();
        }
      } else {
        if (document.activeElement === lastElement || !container.contains(document.activeElement)) {
          e.preventDefault();
          firstElement.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      if (timer) clearTimeout(timer);
      document.removeEventListener('keydown', handleKeyDown);
      if (previousActiveElement.current && typeof previousActiveElement.current.focus === 'function') {
        try {
          previousActiveElement.current.focus();
        } catch {
          // Element unmounted
        }
      }
    };
  }, [ref, active]);
}
