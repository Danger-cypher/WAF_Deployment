import { useEffect, useState, useCallback, useMemo } from 'react';
import { ThemeContext } from './theme-context.js';

const STORAGE_KEY = 'cybersentinel-theme';
const VALID_MODES = ['dark', 'light', 'system'];

function getSystemPrefersLight() {
  return window.matchMedia('(prefers-color-scheme: light)').matches;
}

function resolveTheme(mode) {
  if (mode === 'system') {
    return getSystemPrefersLight() ? 'light' : 'dark';
  }
  return mode;
}

function readStoredMode() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return VALID_MODES.includes(stored) ? stored : 'dark';
  } catch {
    return 'dark';
  }
}

export function ThemeProvider({ children }) {
  const [mode, setMode] = useState(readStoredMode);
  const [resolvedTheme, setResolvedTheme] = useState(() => resolveTheme(readStoredMode()));

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', resolvedTheme);
  }, [resolvedTheme]);

  useEffect(() => {
    setResolvedTheme(resolveTheme(mode));

    if (mode !== 'system') return;

    const mql = window.matchMedia('(prefers-color-scheme: light)');
    const handleChange = () => setResolvedTheme(resolveTheme('system'));
    mql.addEventListener('change', handleChange);
    return () => mql.removeEventListener('change', handleChange);
  }, [mode]);

  const setTheme = useCallback((next) => {
    if (!VALID_MODES.includes(next)) return;
    setMode(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // localStorage unavailable (private browsing, quota) — preference just won't persist
    }
  }, []);

  const value = useMemo(() => ({ mode, resolvedTheme, setTheme }), [mode, resolvedTheme, setTheme]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
