import { useState, useCallback, useRef, useMemo } from 'react';
import { ConfirmContext } from './confirm-context.js';
import ConfirmDialog from '../components/ConfirmDialog.jsx';

export function ConfirmProvider({ children }) {
  const [request, setRequest] = useState(null);
  const resolveRef = useRef(null);

  const confirm = useCallback((options) => {
    return new Promise((resolve) => {
      resolveRef.current = resolve;
      setRequest(typeof options === 'string' ? { message: options } : options);
    });
  }, []);

  const settle = useCallback((result) => {
    resolveRef.current?.(result);
    resolveRef.current = null;
    setRequest(null);
  }, []);

  const value = useMemo(() => ({ confirm }), [confirm]);

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      <ConfirmDialog request={request} onConfirm={() => settle(true)} onCancel={() => settle(false)} />
    </ConfirmContext.Provider>
  );
}
