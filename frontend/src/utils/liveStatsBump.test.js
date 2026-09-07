import { describe, it, expect } from 'vitest';
import { applyLiveStatsBump } from './liveStatsBump';

const BASE_STATS = { total_requests: 10, total_blocked: 4, sqli_count: 1, xss_count: 0 };

describe('applyLiveStatsBump', () => {
  it('bumps total_requests and total_blocked for a blocked (403) event', () => {
    const result = applyLiveStatsBump(BASE_STATS, { http_code: '403', attack_type: 'Path Traversal' });
    expect(result.total_requests).toBe(11);
    expect(result.total_blocked).toBe(5);
    expect(result.sqli_count).toBe(1); // unchanged — not a SQLi event
    expect(result.xss_count).toBe(0);
  });

  it('also bumps sqli_count for a blocked SQL Injection event, case-insensitively', () => {
    const result = applyLiveStatsBump(BASE_STATS, { http_code: '403', attack_type: 'SQL Injection' });
    expect(result.sqli_count).toBe(2);
    expect(result.xss_count).toBe(0);
  });

  it('bumps xss_count for a blocked XSS event', () => {
    const result = applyLiveStatsBump(BASE_STATS, { http_code: '403', attack_type: 'XSS' });
    expect(result.xss_count).toBe(1);
    expect(result.sqli_count).toBe(1);
  });

  it('leaves stats untouched for a non-blocked http_code (e.g. a 200)', () => {
    const result = applyLiveStatsBump(BASE_STATS, { http_code: '200', attack_type: 'SQL Injection' });
    expect(result).toBe(BASE_STATS); // same reference — no-op, not just equal values
  });

  it('counts every code the backend treats as blocked (401, 403, 405, 406, 415, 429, 444)', () => {
    for (const code of ['401', '403', '405', '406', '415', '429', '444']) {
      const result = applyLiveStatsBump(BASE_STATS, { http_code: code, attack_type: '' });
      expect(result.total_blocked).toBe(5);
    }
  });

  it('does not throw on a missing/malformed event payload', () => {
    expect(applyLiveStatsBump(BASE_STATS, {})).toBe(BASE_STATS);
    expect(applyLiveStatsBump(BASE_STATS, null)).toBe(BASE_STATS);
    expect(applyLiveStatsBump(BASE_STATS, undefined)).toBe(BASE_STATS);
  });
});
