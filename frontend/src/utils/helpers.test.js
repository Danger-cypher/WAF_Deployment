import { describe, it, expect } from 'vitest';
import { formatLocalTime, initialsFor } from './helpers';

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

describe('initialsFor', () => {
  it('uses first+last name initials when a two-word display name is given', () => {
    expect(initialsFor('jane.doe', 'Jane Doe')).toBe('JD');
  });

  it('uses first+last of a multi-word name, ignoring middle words', () => {
    expect(initialsFor('jsmith', 'John Q. Smith')).toBe('JS');
  });

  it('falls back to the first two letters of a single-word display name', () => {
    expect(initialsFor('admin', 'Madonna')).toBe('MA');
  });

  it('falls back to the username when no display name is given', () => {
    expect(initialsFor('jane.doe')).toBe('JA');
  });

  it('falls back to the username when display name is blank/whitespace', () => {
    expect(initialsFor('jane.doe', '   ')).toBe('JA');
  });

  it('returns "?" when neither username nor display name is available', () => {
    expect(initialsFor(null)).toBe('?');
    expect(initialsFor(undefined, '')).toBe('?');
  });
});
