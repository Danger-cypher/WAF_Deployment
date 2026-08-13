import { useContext } from 'react';
import { ConfirmContext } from '../context/confirm-context.js';

/**
 * Promise-based replacement for window.confirm(). Usage:
 *   const confirm = useConfirm();
 *   if (!(await confirm({ message: '...', danger: true }))) return;
 * Accepts a plain string as shorthand for { message: string }.
 */
export function useConfirm() {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error('useConfirm must be used within a ConfirmProvider');
  return ctx.confirm;
}
