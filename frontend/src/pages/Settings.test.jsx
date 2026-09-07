import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Settings from './Settings';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// Audit finding P3-05: this is the single largest, highest-privilege
// screen in the product (~20 independently-saved sections, credential
// changes, API-key issuance, full-system backup/restore, and irreversible
// "Danger Zone" actions) and had zero coverage. Covers the
// highest-risk paths rather than all ~20 sections — see the report's own
// framing of full coverage here as separate, open-ended follow-up work.

vi.mock('../services/api', () => ({
  getGeneralSettings: vi.fn(), saveGeneralSettings: vi.fn(),
  getLogSettings: vi.fn(), saveLogSettings: vi.fn(),
  getWafSettings: vi.fn(), saveWafSettings: vi.fn(),
  changeAdminPassword: vi.fn(), restartWafEngine: vi.fn(), reloadNginxProxy: vi.fn(),
  purgeStatsCache: vi.fn(), syncSignatures: vi.fn(),
  getHardeningSettings: vi.fn(), saveHardeningSettings: vi.fn(),
  getGeoBlockSettings: vi.fn(), saveGeoBlockSettings: vi.fn(),
  getThreatIntelSettings: vi.fn(), saveThreatIntelSettings: vi.fn(), syncThreatIntelNow: vi.fn(),
  getGoodBotSettings: vi.fn(), saveGoodBotSettings: vi.fn(), syncGoodBotsNow: vi.fn(),
  getAutoReputationSettings: vi.fn(), saveAutoReputationSettings: vi.fn(), syncAutoReputationNow: vi.fn(),
  getAutoBlockedIps: vi.fn(), releaseAutoBlockedIp: vi.fn(),
  getAdminLoginAllowlistSettings: vi.fn(), saveAdminLoginAllowlistSettings: vi.fn(),
  getMalwareScanningSettings: vi.fn(), saveMalwareScanningSettings: vi.fn(), checkMalwareScanningNow: vi.fn(),
  getApiKeys: vi.fn(), createApiKey: vi.fn(), revokeApiKey: vi.fn(),
  getAntiDefacementSettings: vi.fn(), saveAntiDefacementSettings: vi.fn(),
  getPositiveSecurity: vi.fn(), savePositiveSecurity: vi.fn(),
  getCustomResponse: vi.fn(), saveCustomResponse: vi.fn(),
  getAutoLearning: vi.fn(), saveAutoLearning: vi.fn(),
  getAutoLearningSuggestions: vi.fn(), runAutoLearningNow: vi.fn(),
  approveAutoLearningSuggestion: vi.fn(), rejectAutoLearningSuggestion: vi.fn(),
  getAuditLog: vi.fn(),
  getBackups: vi.fn(), createBackup: vi.fn(), restoreBackup: vi.fn(), deleteBackup: vi.fn(), downloadBackup: vi.fn(),
}));

function renderPage(props = {}) {
  return render(
    <ConfirmProvider>
      <Settings onLogout={vi.fn()} {...props} />
    </ConfirmProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  // The 14 calls fetchSettings() fires unconditionally on mount — resolve
  // all of them so the effect completes cleanly regardless of which tab a
  // given test actually exercises.
  api.getGeneralSettings.mockResolvedValue({});
  api.getLogSettings.mockResolvedValue({});
  api.getWafSettings.mockResolvedValue({});
  api.getHardeningSettings.mockResolvedValue({});
  api.getGeoBlockSettings.mockResolvedValue({});
  api.getThreatIntelSettings.mockResolvedValue({});
  api.getGoodBotSettings.mockResolvedValue({});
  api.getAutoReputationSettings.mockResolvedValue({});
  api.getAdminLoginAllowlistSettings.mockResolvedValue({});
  api.getMalwareScanningSettings.mockResolvedValue({});
  api.getAntiDefacementSettings.mockResolvedValue({});
  api.getPositiveSecurity.mockResolvedValue({});
  api.getCustomResponse.mockResolvedValue({});
  api.getAutoLearning.mockResolvedValue({});
  // Lazily fetched per-tab.
  api.getApiKeys.mockResolvedValue([]);
  api.getBackups.mockResolvedValue([]);
  api.getAutoBlockedIps.mockResolvedValue([]);
  api.getAuditLog.mockResolvedValue({ data: [], total: 0 });
});

describe('Settings — load failure', () => {
  it('shows a persistent error rather than silently leaving stale form fields', async () => {
    api.getGeneralSettings.mockRejectedValue(new Error('backend unreachable'));
    renderPage();
    expect(await screen.findByText(/backend unreachable/)).toBeInTheDocument();
  });
});

describe('Settings — General tab', () => {
  it('saves the selected refresh interval and logs-per-page', async () => {
    api.saveGeneralSettings.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.selectOptions(await screen.findByLabelText('Dashboard Refresh Interval'), '10s');
    await user.click(screen.getByRole('button', { name: 'Save General Preferences' }));
    await waitFor(() => expect(api.saveGeneralSettings).toHaveBeenCalledWith(
      expect.objectContaining({ refreshInterval: '10s' })
    ));
  });
});

describe('Settings — Security & Danger Zone', () => {
  async function openSecurityTab(user) {
    await user.click(await screen.findByRole('button', { name: /Security & Danger Zone/ }));
  }

  it('rejects a mismatched password confirmation client-side', async () => {
    const user = userEvent.setup();
    renderPage();
    await openSecurityTab(user);
    // AnimatePresence's mode="wait" means the previous tab's exit
    // transition must finish before this one mounts — findBy* (which
    // retries) rather than getBy* for the first query after a tab switch.
    await user.type(await screen.findByLabelText('Current Admin Password'), 'old-pass');
    await user.type(screen.getByLabelText('New Security Password'), 'new-password-1');
    await user.type(screen.getByLabelText('Confirm New Password'), 'new-password-2');
    await user.click(screen.getByRole('button', { name: 'Update Credentials' }));

    expect(await screen.findByText(/Passwords do not match/)).toBeInTheDocument();
    expect(api.changeAdminPassword).not.toHaveBeenCalled();
  });

  it('changes the password and clears the form on success', async () => {
    api.changeAdminPassword.mockResolvedValue({ message: 'Password updated.' });
    const user = userEvent.setup();
    renderPage();
    await openSecurityTab(user);
    await user.type(await screen.findByLabelText('Current Admin Password'), 'old-pass');
    await user.type(screen.getByLabelText('New Security Password'), 'new-password-1');
    await user.type(screen.getByLabelText('Confirm New Password'), 'new-password-1');
    await user.click(screen.getByRole('button', { name: 'Update Credentials' }));

    await waitFor(() => expect(api.changeAdminPassword).toHaveBeenCalledWith('old-pass', 'new-password-1'));
    expect(await screen.findByText('Password updated.')).toBeInTheDocument();
    expect(screen.getByLabelText('Current Admin Password')).toHaveValue('');
  });

  it('creates an API key and reveals it once, with a Copy/Dismiss control', async () => {
    api.createApiKey.mockResolvedValue({ name: 'CI key', api_key: 'waf_mock_key_abcdef123456' });
    const user = userEvent.setup();
    renderPage();
    await openSecurityTab(user);
    await user.type(await screen.findByLabelText('Key Name'), 'CI key');
    await user.click(screen.getByRole('button', { name: 'Create Key' }));

    await waitFor(() => expect(api.createApiKey).toHaveBeenCalledWith({ name: 'CI key', role: 'analyst' }));
    expect(await screen.findByText('waf_mock_key_abcdef123456')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText('waf_mock_key_abcdef123456')).not.toBeInTheDocument();
  });

  it('revokes an existing API key', async () => {
    api.getApiKeys.mockResolvedValue([
      { id: 9, name: 'Old key', role: 'admin', enabled: true, key_prefix: 'sk_9ab', expires_at: null, last_used_at: null },
    ]);
    api.revokeApiKey.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await openSecurityTab(user);
    await user.click(await screen.findByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(api.revokeApiKey).toHaveBeenCalledWith(9));
  });

  it('Danger Zone actions confirm first, using their own dialog', async () => {
    api.restartWafEngine.mockResolvedValue({ message: 'Engine restarted.' });
    const user = userEvent.setup();
    renderPage();
    await openSecurityTab(user);
    await user.click(await screen.findByRole('button', { name: 'Restart Engine' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/restart the CyberSentinel WAF protection engine/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Confirm Action' }));

    await waitFor(() => expect(api.restartWafEngine).toHaveBeenCalled());
    expect(await screen.findByText('Engine restarted.')).toBeInTheDocument();
  });

  it('cancelling a Danger Zone action does not call the API', async () => {
    const user = userEvent.setup();
    renderPage();
    await openSecurityTab(user);
    await user.click(await screen.findByRole('button', { name: 'Reload NGINX' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(api.reloadNginxProxy).not.toHaveBeenCalled();
  });
});

describe('Settings — Backups', () => {
  async function openBackupsTab(user) {
    await user.click(await screen.findByRole('button', { name: /Backups/ }));
  }

  it('creates a backup and refreshes the list', async () => {
    api.createBackup.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await openBackupsTab(user);
    await user.click(await screen.findByRole('button', { name: /Create Backup Now/ }));
    await waitFor(() => expect(api.createBackup).toHaveBeenCalled());
    await waitFor(() => expect(api.getBackups).toHaveBeenCalledTimes(2));
  });

  it('restoring confirms first, naming the exact overwrite risk', async () => {
    api.getBackups.mockResolvedValue([
      { id: 'bk1', filename: 'backup-2026-09-01.tar.gz.enc', created_at: '2026-09-01T00:00:00', size_bytes: 1024, triggered_by: 'admin', trigger_type: 'manual' },
    ]);
    api.restoreBackup.mockResolvedValue({ message: 'Restore complete.' });
    const user = userEvent.setup();
    renderPage();
    await openBackupsTab(user);
    await user.click(await screen.findByTitle('Restore'));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/overwrites the live nginx configuration/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));

    await waitFor(() => expect(api.restoreBackup).toHaveBeenCalledWith('bk1'));
    expect(await screen.findByText('Restore complete.')).toBeInTheDocument();
  });

  it('does not restore when cancelled', async () => {
    api.getBackups.mockResolvedValue([
      { id: 'bk1', filename: 'backup.tar.gz.enc', created_at: '2026-09-01T00:00:00', size_bytes: 1024, triggered_by: 'admin', trigger_type: 'manual' },
    ]);
    const user = userEvent.setup();
    renderPage();
    await openBackupsTab(user);
    await user.click(await screen.findByTitle('Restore'));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(api.restoreBackup).not.toHaveBeenCalled();
  });

  it('deletes a backup once confirmed', async () => {
    api.getBackups.mockResolvedValue([
      { id: 'bk1', filename: 'backup.tar.gz.enc', created_at: '2026-09-01T00:00:00', size_bytes: 1024, triggered_by: 'admin', trigger_type: 'manual' },
    ]);
    api.deleteBackup.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await openBackupsTab(user);
    await user.click(await screen.findByTitle('Delete'));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/This cannot be undone/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(api.deleteBackup).toHaveBeenCalledWith('bk1'));
  });

  it('downloading calls the API with id and filename', async () => {
    api.getBackups.mockResolvedValue([
      { id: 'bk1', filename: 'backup.tar.gz.enc', created_at: '2026-09-01T00:00:00', size_bytes: 1024, triggered_by: 'admin', trigger_type: 'manual' },
    ]);
    api.downloadBackup.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await openBackupsTab(user);
    await user.click(await screen.findByTitle('Download'));
    await waitFor(() => expect(api.downloadBackup).toHaveBeenCalledWith('bk1', 'backup.tar.gz.enc'));
  });
});
