import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Rules from './Rules';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// Audit finding P3-05: rule enable/disable, paranoia-level changes, and
// "Restore WAF defaults" (the exact action a near-miss during this
// remediation pass accidentally triggered against the live system) had
// zero test coverage.

vi.mock('../services/api', () => ({
  getRules: vi.fn(),
  enableRule: vi.fn(),
  disableRule: vi.fn(),
  setParanoiaLevel: vi.fn(),
  getRulesStats: vi.fn(),
  getRulesHistory: vi.fn(),
  resetRules: vi.fn(),
  getRuleDetails: vi.fn(),
  setRuleCanary: vi.fn(),
  getRuleCanaryReport: vi.fn(),
  getRuleCanaryStatus: vi.fn(),
  getCanaryRolloutSettings: vi.fn(),
  saveCanaryRolloutSettings: vi.fn(),
  runCanaryRolloutNow: vi.fn(),
}));

const STATS = {
  total_rules: 200, enabled_rules: 195, disabled_rules: 5, paranoia_level: 1,
  top_triggered_rules: [], category_distribution: [], tuning_candidates: [],
};

const RULE = {
  id: '942100', name: 'SQL Injection via libinjection', description: 'Detects SQLi',
  category: 'SQL Injection', severity: 'Critical', enabled: true, hit_count: 12,
  paranoia_level: 1, syntax: 'SecRule ARGS "..."', file_path: 'REQUEST-942.conf',
  last_triggered: null,
};

function renderPage(props = {}) {
  return render(
    <ConfirmProvider>
      <Rules userRole="admin" {...props} />
    </ConfirmProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getRules.mockResolvedValue({ data: [RULE], total: 1 });
  api.getRulesStats.mockResolvedValue(STATS);
  api.getRulesHistory.mockResolvedValue([]);
});

describe('Rules — list and metrics', () => {
  it('renders the metrics summary and the rule card', async () => {
    renderPage();
    expect(await screen.findByText('942100')).toBeInTheDocument();
    expect(screen.getByText('SQL Injection via libinjection')).toBeInTheDocument();
    expect(screen.getByText('PL 1')).toBeInTheDocument();
  });

  it('shows a persistent error state (not just a fading toast) on fetch failure', async () => {
    api.getRules.mockRejectedValue(new Error('db unreachable'));
    api.getRulesStats.mockRejectedValue(new Error('db unreachable'));
    renderPage();
    expect(await screen.findByText(/db unreachable/)).toBeInTheDocument();
  });
});

describe('Rules — enable / disable', () => {
  it('enabling a disabled rule calls the API immediately, no confirmation', async () => {
    api.getRules.mockResolvedValue({ data: [{ ...RULE, enabled: false }], total: 1 });
    api.enableRule.mockResolvedValue({ message: 'enabled' });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('switch'));
    await waitFor(() => expect(api.enableRule).toHaveBeenCalledWith('942100'));
  });

  it('disabling requires a justification of at least 3 characters', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('switch'));
    await user.click(await screen.findByRole('button', { name: 'Confirm Override' }));

    expect(await screen.findByText(/A valid justification reason is required/)).toBeInTheDocument();
    expect(api.disableRule).not.toHaveBeenCalled();
  });

  it('disabling with a valid reason calls disableRule with it', async () => {
    api.disableRule.mockResolvedValue({ message: 'disabled' });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('switch'));
    await user.type(screen.getByLabelText(/Tuning Override Justification/), 'False positive on partner API');
    await user.click(screen.getByRole('button', { name: 'Confirm Override' }));

    await waitFor(() => expect(api.disableRule).toHaveBeenCalledWith('942100', 'False positive on partner API'));
  });

  it('cancelling the disable warning does not call the API', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('switch'));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(api.disableRule).not.toHaveBeenCalled();
  });

  it('non-admins see a disabled, non-interactive toggle', async () => {
    renderPage({ userRole: 'analyst' });
    await screen.findByText('942100');
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(screen.getByTitle('Only administrators can enable or disable rules')).toBeInTheDocument();
  });
});

describe('Rules — paranoia level', () => {
  it('changing paranoia level calls the API with the new level', async () => {
    api.setParanoiaLevel.mockResolvedValue({ message: 'updated' });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('942100');
    await user.click(screen.getByRole('button', { name: /PL 2: Strict/ }));
    await waitFor(() => expect(api.setParanoiaLevel).toHaveBeenCalledWith(2));
  });

  it('non-admins cannot change the paranoia level', async () => {
    renderPage({ userRole: 'analyst' });
    await screen.findByText('942100');
    expect(screen.getByRole('button', { name: /PL 2: Strict/ })).toBeDisabled();
  });
});

describe('Rules — restore defaults', () => {
  it('confirms first, and does not reset if cancelled', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Reset Overrides' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(api.resetRules).not.toHaveBeenCalled();
  });

  it('resets all rules once confirmed', async () => {
    api.resetRules.mockResolvedValue({ message: 'Restored to defaults.' });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Reset Overrides' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Restore' }));
    await waitFor(() => expect(api.resetRules).toHaveBeenCalled());
    expect(await screen.findByText('Restored to defaults.')).toBeInTheDocument();
  });
});

describe('Rules — inspect drawer and canary review', () => {
  it('opens the drawer and loads rule detail', async () => {
    api.getRuleDetails.mockResolvedValue({ ...RULE, syntax: 'SecRule detailed syntax' });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Inspect' }));
    expect(await screen.findByText('SecRule detailed syntax')).toBeInTheDocument();
  });

  it('flagging a rule for canary review calls the API and updates the badge', async () => {
    api.getRuleDetails.mockResolvedValue({ ...RULE });
    api.setRuleCanary.mockResolvedValue({});
    api.getRuleCanaryStatus.mockResolvedValue({ started_at: '2026-09-01T00:00:00', window_hours: 168, elapsed_hours: 10, needs_review: false });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Inspect' }));
    await user.click(await screen.findByRole('button', { name: 'Flag for Canary Review' }));

    await waitFor(() => expect(api.setRuleCanary).toHaveBeenCalledWith('942100', true));
    expect(await screen.findByRole('button', { name: 'Flagged for Review' })).toBeInTheDocument();
  });
});

describe('Rules — canary auto-rollout settings', () => {
  it('loads settings when expanded, and saves edits', async () => {
    api.getCanaryRolloutSettings.mockResolvedValue({
      auto_promote_enabled: false, auto_rollback_enabled: true,
      window_hours: 168, min_sample_size: 50,
      promote_max_sole_match_rate: 0.1, rollback_min_sole_match_rate: 0.5,
    });
    api.saveCanaryRolloutSettings.mockResolvedValue({
      auto_promote_enabled: true, auto_rollback_enabled: true,
      window_hours: 168, min_sample_size: 50,
      promote_max_sole_match_rate: 0.1, rollback_min_sole_match_rate: 0.5,
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('942100');
    await user.click(screen.getByText('Canary Auto-Rollout'));

    const autoPromote = await screen.findByLabelText('Auto-promote low-risk canary rules');
    await user.click(autoPromote);
    await user.click(screen.getByRole('button', { name: 'Save Settings' }));

    await waitFor(() => expect(api.saveCanaryRolloutSettings).toHaveBeenCalledWith(
      expect.objectContaining({ auto_promote_enabled: true })
    ));
  });

  it('"Run Rollout Now" summarizes the outcome', async () => {
    api.getCanaryRolloutSettings.mockResolvedValue({
      auto_promote_enabled: false, auto_rollback_enabled: true,
      window_hours: 168, min_sample_size: 50,
      promote_max_sole_match_rate: 0.1, rollback_min_sole_match_rate: 0.5,
    });
    api.runCanaryRolloutNow.mockResolvedValue({
      promoted: ['1'], rolled_back: [], needs_review: [], still_monitoring: [],
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('942100');
    await user.click(screen.getByText('Canary Auto-Rollout'));
    await user.click(await screen.findByRole('button', { name: 'Run Rollout Now' }));

    expect(await screen.findByText(/1 promoted/)).toBeInTheDocument();
  });
});
