import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DdosBotMitigation from './DdosBotMitigation';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// handleDeleteRule now confirms first (audit finding P3-02), via the same
// useConfirm() hook Settings.jsx already uses — needs its provider in
// scope, same as any other component under it in the real app (see
// main.jsx), or the hook throws on mount.
function renderWithConfirm(ui) {
  return render(<ConfirmProvider>{ui}</ConfirmProvider>);
}

// Covers just the Traffic Composition section (P1 item 5) — the rest of
// this page (rate-limit settings, advanced rules, DDoS analytics) predates
// this change and isn't the target here.
vi.mock('../services/api', () => ({
  getDdosBotSettings: vi.fn().mockResolvedValue(null),
  saveDdosBotSettings: vi.fn(),
  getDdosAnalytics: vi.fn().mockResolvedValue({ timeline: [], top_ips: [], total_blocks: 0, total_unique_ips: 0 }),
  getBotTrafficBreakdown: vi.fn(),
  getTopBotIdentities: vi.fn(),
  getAutoBlockedIps: vi.fn().mockResolvedValue([]),
  releaseAutoBlockedIp: vi.fn().mockResolvedValue({}),
  manualJailIp: vi.fn().mockResolvedValue({}),
}));

describe('DdosBotMitigation — Traffic Composition', () => {
  it('renders each category with its share, and blocked-count only when non-zero', async () => {
    api.getBotTrafficBreakdown.mockResolvedValue([
      { category: 'Browser (Human)', count: 800, blocked_count: 4 },
      { category: 'AI Crawler', count: 200, blocked_count: 0 },
    ]);
    api.getTopBotIdentities.mockResolvedValue([
      { user_agent: 'GPTBot/1.0', category: 'AI Crawler', count: 200 },
    ]);

    renderWithConfirm(<DdosBotMitigation />);

    expect(await screen.findByText('Browser (Human)')).toBeInTheDocument();
    // "AI Crawler" appears twice — once in the breakdown bars, once as the
    // identity table's category tag for GPTBot.
    expect(screen.getAllByText('AI Crawler')).toHaveLength(2);
    expect(screen.getByText('800 (80.0%)')).toBeInTheDocument();
    expect(screen.getByText('200 (20.0%)')).toBeInTheDocument();
    // Only the category with real blocks shows a blocked-count line.
    expect(screen.getByText('4 blocked (0.5%)')).toBeInTheDocument();
    expect(screen.queryByText(/0 blocked/)).not.toBeInTheDocument();

    expect(screen.getByText('GPTBot/1.0')).toBeInTheDocument();
  });

  it('shows an empty state instead of a blank card when there is no traffic yet', async () => {
    api.getBotTrafficBreakdown.mockResolvedValue([]);
    api.getTopBotIdentities.mockResolvedValue([]);

    renderWithConfirm(<DdosBotMitigation />);

    await waitFor(() => expect(screen.getByText('No traffic recorded yet.')).toBeInTheDocument());
    expect(screen.getByText('No non-browser traffic identified yet.')).toBeInTheDocument();
  });

  it('labels a request with no User-Agent instead of rendering an empty cell', async () => {
    api.getBotTrafficBreakdown.mockResolvedValue([{ category: 'No User-Agent', count: 5, blocked_count: 3 }]);
    api.getTopBotIdentities.mockResolvedValue([{ user_agent: '', category: 'Scripted Client', count: 1 }]);

    renderWithConfirm(<DdosBotMitigation />);

    expect(await screen.findByText('(empty)')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// P3-02: deleting an advanced rate-limit rule used to save immediately with
// no confirmation and no undo. It now confirms first, like every other
// destructive action in the dashboard.
// ---------------------------------------------------------------------------

describe('DdosBotMitigation — advanced rule deletion', () => {
  const RULE = {
    id: 'rule-1', name: 'Throttle login endpoint', enabled: true,
    parameter_type: 'URI', parameter_value: '/api/auth/login',
    rate_limit_rps: 5, rate_limit_unit: 'r/s', burst_tolerance: 10,
  };

  function mockSettingsWithOneRule() {
    api.getDdosBotSettings.mockResolvedValue({ advanced_rules: [RULE] });
    api.getBotTrafficBreakdown.mockResolvedValue([]);
    api.getTopBotIdentities.mockResolvedValue([]);
  }

  it('asks for confirmation naming the rule, and does not save if cancelled', async () => {
    mockSettingsWithOneRule();
    const user = userEvent.setup();
    renderWithConfirm(<DdosBotMitigation />);

    await user.click(await screen.findByRole('button', { name: 'Delete' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Throttle login endpoint/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    // framer-motion's exit animation keeps the dialog mounted briefly —
    // wait it out rather than assert on a mid-animation DOM snapshot.
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(api.saveDdosBotSettings).not.toHaveBeenCalled();
    // The rule itself is still there — nothing was removed client-side either.
    expect(screen.getByText('Throttle login endpoint')).toBeInTheDocument();
  });

  it('deletes and saves once the confirmation is accepted', async () => {
    mockSettingsWithOneRule();
    const user = userEvent.setup();
    renderWithConfirm(<DdosBotMitigation />);

    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));

    await waitFor(() => expect(api.saveDdosBotSettings).toHaveBeenCalled());
    const savedArg = api.saveDdosBotSettings.mock.calls.at(-1)[0];
    expect(savedArg.advanced_rules).toEqual([]);
  });
});

describe('DdosBotMitigation — Challenge Provider (Step 2.2)', () => {
  it('renders challenge provider options and saves Turnstile keys', async () => {
    api.getDdosBotSettings.mockResolvedValue({
      rate_limit_rps: 50,
      burst_tolerance: 100,
      trusted_ips: [],
      bot_mitigation_action: 'CAPTCHA Challenge',
      challenge_provider: 'turnstile',
      turnstile_site_key: '0x4AAAAAA_test',
      turnstile_secret_key: '0x4AAAAAA_secret',
    });
    api.getBotTrafficBreakdown.mockResolvedValue([]);
    api.getTopBotIdentities.mockResolvedValue([]);
    api.getAutoBlockedIps.mockResolvedValue([]);

    const user = userEvent.setup();
    renderWithConfirm(<DdosBotMitigation />);

    const siteKeyInput = await screen.findByLabelText(/Turnstile Site Key/i);
    expect(siteKeyInput).toHaveValue('0x4AAAAAA_test');

    const enforceBtn = screen.getByRole('button', { name: /Enforce Policy/i });
    await user.click(enforceBtn);

    await waitFor(() => {
      expect(api.saveDdosBotSettings).toHaveBeenCalledWith(
        expect.objectContaining({
          bot_mitigation_action: 'CAPTCHA Challenge',
          challenge_provider: 'turnstile',
          turnstile_site_key: '0x4AAAAAA_test',
        })
      );
    });
  });
});

describe('DdosBotMitigation — Threat Quarantine & Auto-Jail (Step 2.3)', () => {
  it('renders quarantined attackers with remaining countdown and releases on pardon', async () => {
    api.getDdosBotSettings.mockResolvedValue(null);
    api.getBotTrafficBreakdown.mockResolvedValue([]);
    api.getTopBotIdentities.mockResolvedValue([]);
    api.getAutoBlockedIps.mockResolvedValue([
      { ip: '203.0.113.50', ttl_seconds: 3600 },
    ]);
    api.releaseAutoBlockedIp.mockResolvedValue({ message: 'Released' });

    const user = userEvent.setup();
    renderWithConfirm(<DdosBotMitigation />);

    expect(await screen.findByText('203.0.113.50')).toBeInTheDocument();
    expect(screen.getByText(/1h 0m/)).toBeInTheDocument();
    expect(screen.getByText('1 JAILED')).toBeInTheDocument();

    const pardonBtn = screen.getByRole('button', { name: /Pardon \/ Release/i });
    await user.click(pardonBtn);

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Pardon and release IP "203.0.113.50"/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => {
      expect(api.releaseAutoBlockedIp).toHaveBeenCalledWith('203.0.113.50');
    });
  }, 15000);

  it('allows manual quarantining of an attacker IP', async () => {
    api.getDdosBotSettings.mockResolvedValue(null);
    api.getBotTrafficBreakdown.mockResolvedValue([]);
    api.getTopBotIdentities.mockResolvedValue([]);
    api.getAutoBlockedIps.mockResolvedValue([]);
    api.manualJailIp.mockResolvedValue({ message: 'Jailed' });

    const user = userEvent.setup();
    renderWithConfirm(<DdosBotMitigation />);

    const openQuarantineBtn = await screen.findByRole('button', { name: /\+ Quarantine Attacker IP/i });
    await user.click(openQuarantineBtn);

    const ipInput = await screen.findByLabelText(/Attacker IP Address/i);
    await user.type(ipInput, '198.51.100.99');

    const submitBtn = screen.getByRole('button', { name: /Quarantine Immediately/i });
    await user.click(submitBtn);

    await waitFor(() => {
      expect(api.manualJailIp).toHaveBeenCalledWith('198.51.100.99', 24);
    });
  }, 15000);
});
