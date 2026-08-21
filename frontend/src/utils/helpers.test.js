import { describe, it, expect } from 'vitest';
import { formatLocalTime } from './helpers';

describe('formatLocalTime', () => {
  it('returns a dash for falsy input', () => {
    expect(formatLocalTime(null)).toBe('-');
    expect(formatLocalTime(undefined)).toBe('-');
    expect(formatLocalTime('')).toBe('-');
  });

  it('formats a UTC timestamp string without throwing', () => {
    const result = formatLocalTime('2026-08-07 12:30:45');
    expect(typeof result).toBe('string');
    expect(result).not.toBe('-');
  });

  it('falls back gracefully on unparseable input', () => {
    const result = formatLocalTime('not-a-real-date');
    expect(typeof result).toBe('string');
  });
});
