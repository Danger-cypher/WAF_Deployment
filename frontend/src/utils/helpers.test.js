import { describe, it, expect } from 'vitest';
import { parseJwt, formatLocalTime } from './helpers';

function base64UrlEncode(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('parseJwt', () => {
  it('decodes a well-formed JWT payload', () => {
    const payload = { sub: 'admin', role: 'admin', exp: 9999999999 };
    const token = `header.${base64UrlEncode(payload)}.signature`;
    expect(parseJwt(token)).toEqual(payload);
  });

  it('returns null for a malformed token', () => {
    expect(parseJwt('not-a-jwt')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(parseJwt('')).toBeNull();
  });
});

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
