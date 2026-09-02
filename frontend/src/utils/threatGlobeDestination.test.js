import { describe, it, expect } from 'vitest';
import { resolveDestination } from './threatGlobeDestination';

/**
 * Covers which destination point ThreatGlobe.jsx uses when both an
 * admin override and the startup auto-detection are present. The rest
 * of that component (the Three.js engine, the live WebSocket feed) is
 * exercised by threatGlobeEngine.js's own design — mounting the full
 * page here would mean stubbing out WebGLRenderer's actual GPU context,
 * which jsdom doesn't provide and isn't worth faking for what would
 * still just be testing Three.js itself.
 */
describe('resolveDestination', () => {
  it('prefers the manual override when enabled, even if auto-detection also ran', () => {
    const result = resolveDestination({
      override_enabled: true, override_lat: 10, override_lon: 20, override_label: 'Custom',
      server_lat: 50, server_lon: 8, server_label: 'Auto-detected', auto_detected: true,
    });
    expect(result).toEqual({ lat: 10, lon: 20, label: 'Custom' });
  });

  it('falls back to the auto-detected location when no override is enabled', () => {
    const result = resolveDestination({
      override_enabled: false, override_lat: null, override_lon: null, override_label: '',
      server_lat: 50.11, server_lon: 8.68, server_label: 'Frankfurt', auto_detected: true,
    });
    expect(result).toEqual({ lat: 50.11, lon: 8.68, label: 'Frankfurt' });
  });

  it('labels an auto-detected location with no city name as "Protected origin"', () => {
    const result = resolveDestination({
      override_enabled: false, server_lat: 50.11, server_lon: 8.68, server_label: '', auto_detected: true,
    });
    expect(result.label).toBe('Protected origin');
  });

  it('falls back to the auto-detected location if override is enabled but its coordinates are missing', () => {
    // A broken/mid-save override state shouldn't blank the globe out
    // when a perfectly good auto-detected point is already on hand.
    const result = resolveDestination({
      override_enabled: true, override_lat: null, override_lon: null,
      server_lat: 50.11, server_lon: 8.68, server_label: 'Frankfurt',
    });
    expect(result).toEqual({ lat: 50.11, lon: 8.68, label: 'Frankfurt' });
  });

  it('returns null when nothing has been detected or configured yet', () => {
    expect(resolveDestination({
      override_enabled: false, server_lat: null, server_lon: null,
    })).toBeNull();
  });

  it('returns null for a missing/empty settings response rather than throwing', () => {
    expect(resolveDestination(null)).toBeNull();
    expect(resolveDestination(undefined)).toBeNull();
  });
});
