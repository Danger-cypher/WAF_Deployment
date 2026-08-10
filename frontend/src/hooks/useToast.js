import { useState, useRef, useCallback, useEffect } from 'react';

const TOAST_DURATION_MS = 4000;

/**
 * Shared toast state for the small "success/error" popup pattern used across
 * the dashboard. Pair with <Toast toast={toast} /> to render it.
 */
export function useToast() {
  const [toast, setToast] = useState(null);
  const timerRef = useRef(null);

  useEffect(() => () => clearTimeout(timerRef.current), []);

  const showToast = useCallback((message, type = 'success') => {
    clearTimeout(timerRef.current);
    setToast({ message, type });
    timerRef.current = setTimeout(() => setToast(null), TOAST_DURATION_MS);
  }, []);

  return { toast, showToast };
}
