import { describe, it, expect } from 'vitest';
import { classifyTier } from './threatGlobeTier';

describe('classifyTier', () => {
  it('classifies a denied, rule-matched request as blocked', () => {
    expect(classifyTier({ rule_id: '941100', http_code: '403' })).toBe('blocked');
  });

  it('classifies a rule-matched request that was still allowed through as flagged', () => {
    expect(classifyTier({ rule_id: '941100', http_code: '200' })).toBe('flagged');
  });

  it('classifies a rule match with a non-403 error status as flagged, not blocked', () => {
    expect(classifyTier({ rule_id: '941100', http_code: '500' })).toBe('flagged');
  });

  it('classifies a request with no rule match at all as normal', () => {
    expect(classifyTier({ rule_id: '', http_code: '200' })).toBe('normal');
  });

  it('treats a missing rule_id the same as an empty one', () => {
    expect(classifyTier({ http_code: '200' })).toBe('normal');
  });

  it('classifies a 403 with no rule match as normal, not blocked — a 403 alone is not a WAF block', () => {
    expect(classifyTier({ rule_id: '', http_code: '403' })).toBe('normal');
  });

  it('handles a missing/null event without throwing', () => {
    expect(classifyTier(null)).toBe('normal');
    expect(classifyTier(undefined)).toBe('normal');
  });
});
