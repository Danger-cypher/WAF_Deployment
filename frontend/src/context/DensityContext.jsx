import { useEffect, useState, useCallback, useMemo } from 'react';
import { DensityContext } from './density-context.js';

const STORAGE_KEY = 'cybersentinel-density';
const VALID_DENSITIES = ['comfortable', 'compact'];

function readStoredDensity() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return VALID_DENSITIES.includes(stored) ? stored : 'comfortable';
  } catch {
    return 'comfortable';
  }
}

export function DensityProvider({ children }) {
  const [density, setDensityState] = useState(readStoredDensity);

  useEffect(() => {
    document.documentElement.setAttribute('data-density', density);
  }, [density]);

  const setDensity = useCallback((next) => {
    if (!VALID_DENSITIES.includes(next)) return;
    setDensityState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // localStorage unavailable (e.g. private browsing quota)
    }
  }, []);

  const toggleDensity = useCallback(() => {
    setDensity((prev) => (prev === 'compact' ? 'comfortable' : 'compact'));
  }, [setDensity]);

  const value = useMemo(
    () => ({
      density,
      setDensity,
      toggleDensity,
      isCompact: density === 'compact',
    }),
    [density, setDensity, toggleDensity]
  );

  return <DensityContext.Provider value={value}>{children}</DensityContext.Provider>;
}
