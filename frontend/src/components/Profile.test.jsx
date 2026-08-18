import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Profile from './Profile';
import * as api from '../services/api';

vi.mock('../services/api');

const BASE_PROFILE = {
  id: 1, username: 'admin', role: 'admin', display_name: '', email: '',
  enabled: true, created_at: null, updated_at: null, last_login_at: null,
};
const BASE_PREFS = { muted_severities: [], muted_event_types: [] };
const BASE_MFA_STATUS = { enabled: false };

beforeEach(() => {
  vi.resetAllMocks();
  api.getMyProfile.mockResolvedValue(BASE_PROFILE);
  api.getMyNotificationPreferences.mockResolvedValue(BASE_PREFS);
  api.getMyMfaStatus.mockResolvedValue(BASE_MFA_STATUS);
});

describe('Profile', () => {
  it('loads and displays the current username and role', async () => {
    render(<Profile onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByText('admin')).toBeInTheDocument();
    });
    expect(screen.getByText(/admin/i, { selector: 'span' })).toBeInTheDocument();
  });

  it('toggling a severity chip mutes it and persists the change', async () => {
    api.updateMyNotificationPreferences.mockResolvedValue({
      muted_severities: ['critical'], muted_event_types: [],
    });
    const user = userEvent.setup();
    render(<Profile onClose={() => {}} />);

    const criticalChip = await screen.findByRole('button', { name: 'critical' });
    expect(criticalChip).not.toHaveStyle({ textDecoration: 'line-through' });

    await user.click(criticalChip);

    await waitFor(() => {
      expect(api.updateMyNotificationPreferences).toHaveBeenCalledWith({
        muted_severities: ['critical'],
        muted_event_types: [],
      });
    });
    await waitFor(() => {
      expect(criticalChip).toHaveStyle({ textDecoration: 'line-through' });
    });
  });

  it('reverts the optimistic toggle if saving preferences fails', async () => {
    api.updateMyNotificationPreferences.mockRejectedValue(new Error('network down'));
    const user = userEvent.setup();
    render(<Profile onClose={() => {}} />);

    const infoChip = await screen.findByRole('button', { name: 'info' });
    await user.click(infoChip);

    await waitFor(() => {
      expect(screen.getByText(/failed to update notification preferences/i)).toBeInTheDocument();
    });
    expect(infoChip).not.toHaveStyle({ textDecoration: 'line-through' });
  });

  it('rejects a new password shorter than 12 characters without calling the API', async () => {
    const user = userEvent.setup();
    render(<Profile onClose={() => {}} />);
    await screen.findByText('admin');

    await user.type(screen.getByPlaceholderText('Current password'), 'whatever');
    await user.type(screen.getByPlaceholderText(/new password/i), 'short');
    await user.click(screen.getByRole('button', { name: /update password/i }));

    expect(await screen.findByText(/at least 12 characters/i)).toBeInTheDocument();
    expect(api.changeMyPassword).not.toHaveBeenCalled();
  });

  it('walks through enabling MFA: setup shows QR code, confirm enables it', async () => {
    api.setupMyMfa.mockResolvedValue({
      secret: 'JBSWY3DPEHPK3PXP',
      otpauth_uri: 'otpauth://totp/CyberSentinel%20WAF:admin?secret=JBSWY3DPEHPK3PXP&issuer=CyberSentinel%20WAF',
      qr_code_png_base64: 'ZmFrZS1wbmc=',
    });
    api.confirmMyMfa.mockResolvedValue({ enabled: true });

    const user = userEvent.setup();
    render(<Profile onClose={() => {}} />);

    await user.click(await screen.findByRole('button', { name: /enable 2fa/i }));
    expect(await screen.findByAltText(/mfa qr code/i)).toBeInTheDocument();
    expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText(/enter 6-digit code to confirm/i), '123456');
    await user.click(screen.getByRole('button', { name: /confirm & enable/i }));

    await waitFor(() => {
      expect(api.confirmMyMfa).toHaveBeenCalledWith('123456');
    });
    expect(await screen.findByText(/two-factor authentication enabled/i)).toBeInTheDocument();
    expect(screen.queryByAltText(/mfa qr code/i)).not.toBeInTheDocument();
  });

  it('disabling MFA requires both password and code before submitting', async () => {
    // The confirm button is intentionally always clickable (not disabled
    // based on React input state) — a password-manager autofill can fill
    // the DOM without firing React's onChange, which previously left the
    // button silently, permanently disabled with zero feedback. Validation
    // now happens on click instead, so an incomplete form always produces a
    // visible error rather than doing nothing.
    api.getMyMfaStatus.mockResolvedValue({ enabled: true });
    api.disableMyMfa.mockResolvedValue({ enabled: false });

    const user = userEvent.setup();
    render(<Profile onClose={() => {}} />);

    await user.click(await screen.findByRole('button', { name: /^disable$/i }));
    const confirmBtn = await screen.findByRole('button', { name: /confirm disable/i });
    expect(confirmBtn).not.toBeDisabled();

    await user.click(confirmBtn);
    expect(await screen.findByText(/enter your current password and the 6-digit code/i)).toBeInTheDocument();
    expect(api.disableMyMfa).not.toHaveBeenCalled();

    await user.type(screen.getByPlaceholderText(/current password to confirm/i), 'MyPassword123!');
    await user.type(screen.getByPlaceholderText(/6-digit code/i), '654321');
    await user.click(confirmBtn);
    await waitFor(() => {
      expect(api.disableMyMfa).toHaveBeenCalledWith('MyPassword123!', '654321');
    });
  });
});
