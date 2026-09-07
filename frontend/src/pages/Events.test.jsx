import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Events from './Events';
import * as api from '../services/api';

// Audit finding P3-05: the live event timeline — every analyst's primary
// screen, and the source of "Mark as FP" / "Create Rule" actions used
// elsewhere — had zero coverage.

vi.mock('../services/api', () => ({
  getLogs: vi.fn(),
  getGroupedLogs: vi.fn(),
  getGeneralSettings: vi.fn(),
}));

const LOG = {
  id: 'ev1', timestamp: '2026-09-05T10:00:00', client_ip: '10.0.0.5', severity: 'High',
  attack_type: 'SQL Injection', rule_id: '942100', http_code: '403', uri: '/login?id=1',
};

beforeEach(() => {
  vi.clearAllMocks();
  api.getGeneralSettings.mockResolvedValue({});
  api.getLogs.mockResolvedValue({ data: [LOG], total: 1 });
  api.getGroupedLogs.mockResolvedValue({ data: [], total: 0 });
  // jsdom doesn't implement Blob URL creation.
  window.URL.createObjectURL = vi.fn(() => 'blob:mock');
  window.URL.revokeObjectURL = vi.fn();
});

describe('Events — flat timeline', () => {
  it('renders the fetched log row', async () => {
    render(<Events />);
    expect(await screen.findByText('10.0.0.5')).toBeInTheDocument();
    const row = screen.getByText('10.0.0.5').closest('tr');
    expect(within(row).getByText('SQL Injection')).toBeInTheDocument();
    expect(within(row).getByText('403')).toBeInTheDocument();
  });

  it('shows the empty state with no logs and no search', async () => {
    api.getLogs.mockResolvedValue({ data: [], total: 0 });
    render(<Events />);
    await waitFor(() => expect(api.getLogs).toHaveBeenCalled());
    expect(await screen.findByText(/No.*logs|No.*events/i)).toBeInTheDocument();
  });

  it('searching passes the term to getLogs as a filter', async () => {
    const user = userEvent.setup();
    render(<Events />);
    await screen.findByText('10.0.0.5');
    await user.type(screen.getByLabelText(/Search events/), '10.0.0.5');

    await waitFor(() => expect(api.getLogs).toHaveBeenCalledWith(
      1, expect.any(Number), expect.objectContaining({ search: '10.0.0.5' })
    ));
  });

  it('severity filter is passed through, and hidden while Focus Mode is on', async () => {
    const user = userEvent.setup();
    render(<Events />);
    await screen.findByText('10.0.0.5');
    await user.selectOptions(screen.getByLabelText('Filter by severity'), 'Critical');
    await waitFor(() => expect(api.getLogs).toHaveBeenCalledWith(
      1, expect.any(Number), expect.objectContaining({ severity: 'Critical' })
    ));

    await user.click(screen.getByRole('button', { name: /Focus Mode/ }));
    expect(screen.queryByLabelText('Filter by severity')).not.toBeInTheDocument();
    await waitFor(() => expect(api.getLogs).toHaveBeenCalledWith(
      1, expect.any(Number), expect.objectContaining({ min_severity: 'High' })
    ));
  });

  it('clicking a column header sorts, and clicking again reverses it', async () => {
    api.getLogs.mockResolvedValue({
      data: [
        { ...LOG, id: 'a', client_ip: '1.1.1.1' },
        { ...LOG, id: 'b', client_ip: '9.9.9.9' },
      ], total: 2,
    });
    const user = userEvent.setup();
    render(<Events />);
    await screen.findByText('1.1.1.1');

    const rowsText = () => screen.getAllByRole('row').slice(1).map(r => r.textContent);
    await user.click(screen.getByRole('columnheader', { name: /Source IP/ }));
    await waitFor(() => expect(rowsText()[0]).toContain('9.9.9.9'));
    await user.click(screen.getByRole('columnheader', { name: /Source IP/ }));
    await waitFor(() => expect(rowsText()[0]).toContain('1.1.1.1'));
  });

  it('"Mark as FP" calls the callback with the log row', async () => {
    const onMarkFalsePositive = vi.fn();
    const user = userEvent.setup();
    render(<Events onMarkFalsePositive={onMarkFalsePositive} />);
    await user.click(await screen.findByRole('button', { name: 'Mark as FP' }));
    expect(onMarkFalsePositive).toHaveBeenCalledWith(LOG);
  });

  it('exporting with no data shows an error toast instead of downloading', async () => {
    api.getLogs.mockResolvedValue({ data: [], total: 0 });
    const user = userEvent.setup();
    render(<Events />);
    await waitFor(() => expect(api.getLogs).toHaveBeenCalled());
    await user.click(screen.getByRole('button', { name: /Export Report/ }));
    expect(await screen.findByText(/No log data available to export/)).toBeInTheDocument();
  });

  it('exporting with data builds a CSV download link', async () => {
    const user = userEvent.setup();
    render(<Events />);
    await screen.findByText('10.0.0.5');
    await user.click(screen.getByRole('button', { name: /Export Report/ }));
    await waitFor(() => expect(window.URL.createObjectURL).toHaveBeenCalled());
    const blobArg = window.URL.createObjectURL.mock.calls[0][0];
    expect(blobArg.type).toContain('text/csv');
  });
});

describe('Events — grouped view', () => {
  it('switches to grouped view and fetches grouped data', async () => {
    api.getGroupedLogs.mockResolvedValue({
      data: [{ client_ip: '5.5.5.5', rule_id: '942100', event_count: 12, last_seen: '2026-09-05T10:00:00', severity: 'Critical', attack_type: 'SQLi', sample_uri: '/x' }],
      total: 1,
    });
    const user = userEvent.setup();
    render(<Events />);
    await screen.findByText('10.0.0.5');
    await user.click(screen.getByRole('button', { name: /Flat View/ }));

    expect(await screen.findByText('5.5.5.5')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });

  it('drills down into a group to fetch its individual events', async () => {
    api.getGroupedLogs.mockResolvedValue({
      data: [{ client_ip: '5.5.5.5', rule_id: '942100', event_count: 2, last_seen: '2026-09-05T10:00:00', severity: 'Critical', attack_type: 'SQLi', sample_uri: '/x' }],
      total: 1,
    });
    api.getLogs.mockImplementation((page, size, filters) => {
      if (filters?.ip === '5.5.5.5') {
        return Promise.resolve({ data: [{ id: 'e1', timestamp: '2026-09-05T10:00:00', http_code: '403', uri: '/x' }], total: 1 });
      }
      return Promise.resolve({ data: [LOG], total: 1 });
    });
    const user = userEvent.setup();
    render(<Events />);
    await screen.findByText('10.0.0.5');
    await user.click(screen.getByRole('button', { name: /Flat View/ }));
    await screen.findByText('5.5.5.5');

    await user.click(screen.getByRole('button', { name: 'View Events' }));
    await waitFor(() => expect(api.getLogs).toHaveBeenCalledWith(
      1, 50, expect.objectContaining({ ip: '5.5.5.5', rule_id: '942100' })
    ));
    expect(await screen.findByRole('button', { name: 'Hide Events' })).toBeInTheDocument();
  });
});
