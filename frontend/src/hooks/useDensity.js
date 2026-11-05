import { useContext } from 'react';
import { DensityContext } from '../context/density-context.js';

export function useDensity() {
  const ctx = useContext(DensityContext);
  if (!ctx) {
    return {
      density: 'comfortable',
      setDensity: () => {},
      toggleDensity: () => {},
      isCompact: false,
    };
  }
  return ctx;
}
