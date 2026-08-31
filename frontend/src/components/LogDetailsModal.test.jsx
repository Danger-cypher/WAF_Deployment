import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LogDetailsModal from './LogDetailsModal';
import * as api from '../services/api';

// Covers just the plain-language "why was this blocked" summary (P2 item
// 7) — the drawer's other tabs/sections predate this change.
vi.mock('../services/api', () => ({ getLogExplain: vi.fn() }));

const SAMPLE_LOG = {
  id: 'req-1', timestamp: '2026-08-31 12:00:00', client_ip: '10.0.0.1',
  uri: '/login', method: 'POST', http_code: '403', rule_id: '942100',
  message: 'SQL Injection Attack Detected', severity: 'Critical', attack_type: 'SQL Injection',
  hostname: 'example.com', country: 'US', source_asn_org: '', request_headers: {}, response_headers: {},
};

describe('LogDetailsModal — Why Was This Blocked?', () => {
  it('shows the plain-language summary above the raw score grid once expanded', async () => {
    api.getLogExplain.mockResolvedValue({
      waf_event: SAMPLE_LOG,
      ml_event: { threat_score: 0.95, xgb_prob: 0.9, crs_score: 20, iso_score: -0.4, redis_rep: 1, decision: 'block', matched_vars: '942100' },
      ml_match_note: 'Matched to an ML scoring event within a 3-second window of this transaction.',
      plain_summary: 'Blocked as a SQL Injection attempt (rule 942100: SQL Injection Attack Detected). The ML risk score was primarily driven by the OWASP Core Rule Set\'s own anomaly scoring (CRS score contribution: 0.50).',
    });

    const user = userEvent.setup();
    render(<LogDetailsModal isOpen log={SAMPLE_LOG} onClose={() => {}} />);
    await user.click(screen.getByText('Why Was This Blocked? (ML Correlation)'));

    const summary = await screen.findByText(/The ML risk score was primarily driven by/);
    expect(summary).toBeInTheDocument();
    // Still there for the analyst who wants it — the summary supplements
    // the raw grid, it doesn't replace it.
    expect(screen.getByText('Blended Threat Score')).toBeInTheDocument();
  });

  it('still shows a plain-language summary when there is no ML event to correlate', async () => {
    api.getLogExplain.mockResolvedValue({
      waf_event: SAMPLE_LOG,
      ml_event: null,
      ml_match_note: 'No ML scoring event found for this request — most likely because ModSecurity blocked it natively.',
      plain_summary: 'Blocked as a SQL Injection attempt (rule 942100: SQL Injection Attack Detected).',
    });

    const user = userEvent.setup();
    render(<LogDetailsModal isOpen log={SAMPLE_LOG} onClose={() => {}} />);
    await user.click(screen.getByText('Why Was This Blocked? (ML Correlation)'));

    expect(await screen.findByText(/Blocked as a SQL Injection attempt/)).toBeInTheDocument();
    expect(screen.queryByText('Blended Threat Score')).not.toBeInTheDocument();
  });
});
