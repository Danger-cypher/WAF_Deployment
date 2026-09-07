import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UserManagement from './UserManagement';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// Audit finding P3-05: this screen — the one that creates, deletes and
// changes the role of every account in the product, including the one
// running these tests' own — had zero coverage.

vi.mock('../services/api', () => ({
  listUsers: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  resetUserPassword: vi.fn(),
  deleteUser: vi.fn(),
  adminDisableUserMfa: vi.fn(),
  getProtectedApps: vi.fn().mockResolvedValue([]),
  getUserSessions: vi.fn(),
  revokeUserSession: vi.fn(),
}));

function renderPage(props = {}) {
  return render(
    <ConfirmProvider>
      <UserManagement currentUsername="admin" {...props} />
    </ConfirmProvider>
  );
}

const USERS = [
  { id: 1, username: 'admin', role: 'admin', enabled: true, mfa_enabled: true, last_login_at: '2026-09-01T10:00:00', app_ids: [] },
  { id: 2, username: 'jdoe', role: 'analyst', enabled: true, mfa_enabled: false, last_login_at: null, app_ids: [] },
  { id: 3, username: 'disabled-guy', role: 'app_admin', enabled: false, mfa_enabled: false, last_login_at: null, app_ids: [7] },
];

beforeEach(() => {
  vi.clearAllMocks();
  api.getProtectedApps.mockResolvedValue([]);
  api.listUsers.mockResolvedValue(USERS);
});

describe('UserManagement — list rendering', () => {
  it('renders every user with role, status and 2FA state', async () => {
    renderPage();
    expect(await screen.findByText('jdoe')).toBeInTheDocument();
    expect(screen.getAllByText('Active')).toHaveLength(2);
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    // The "(you)" tag only appears on the row matching currentUsername.
    expect(screen.getByText('(you)')).toBeInTheDocument();
  });

  it("disables self-role-change and self-delete, but not for other users", async () => {
    renderPage();
    await screen.findByText('jdoe');

    const adminRow = screen.getByText('admin').closest('tr');
    const jdoeRow = screen.getByText('jdoe').closest('tr');

    expect(within(adminRow).getByRole('combobox')).toBeDisabled();
    expect(within(adminRow).getByTitle('Delete user')).toBeDisabled();
    expect(within(jdoeRow).getByRole('combobox')).not.toBeDisabled();
    expect(within(jdoeRow).getByTitle('Delete user')).not.toBeDisabled();
  });

  it('surfaces a load failure as a toast instead of an infinite spinner', async () => {
    api.listUsers.mockRejectedValue(new Error('db is down'));
    renderPage();
    expect(await screen.findByText(/Failed to load users: db is down/)).toBeInTheDocument();
  });
});

describe('UserManagement — create user', () => {
  it('rejects a short password client-side without calling the API', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Add User/ }));

    await user.type(screen.getByLabelText(/Username/), 'newperson');
    await user.type(screen.getByLabelText(/Temporary Password/), 'short');
    await user.click(screen.getByRole('button', { name: /Create User/ }));

    expect(await screen.findByText(/password must be at least 12 characters/)).toBeInTheDocument();
    expect(api.createUser).not.toHaveBeenCalled();
  });

  it('creates a user and refreshes the list on success', async () => {
    api.createUser.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Add User/ }));

    await user.type(screen.getByLabelText(/Username/), 'newperson');
    await user.type(screen.getByLabelText(/Temporary Password/), 'correct-horse-battery');
    await user.click(screen.getByRole('button', { name: /Create User/ }));

    await waitFor(() => expect(api.createUser).toHaveBeenCalledWith(expect.objectContaining({
      username: 'newperson',
      password: 'correct-horse-battery',
      role: 'analyst',
      app_ids: [],
    })));
    // The modal closes and the list is re-fetched (2 calls: initial + refresh).
    await waitFor(() => expect(api.listUsers).toHaveBeenCalledTimes(2));
  });

  it('shows the app checklist only when role is switched to app_admin', async () => {
    api.getProtectedApps.mockResolvedValue([{ id: 7, name: 'Shop', domain: 'shop.example.com' }]);
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Add User/ }));

    expect(screen.queryByText('Protected Applications')).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Role'), 'app_admin');
    expect(await screen.findByText('Protected Applications')).toBeInTheDocument();
    expect(await screen.findByText(/Shop/)).toBeInTheDocument();
  });
});

describe('UserManagement — destructive actions confirm first', () => {
  it('does not delete when the confirmation is cancelled', async () => {
    const user = userEvent.setup();
    renderPage();
    const jdoeRow = (await screen.findByText('jdoe')).closest('tr');

    await user.click(within(jdoeRow).getByTitle('Delete user'));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Delete user "jdoe"/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(api.deleteUser).not.toHaveBeenCalled();
  });

  it('deletes once confirmed', async () => {
    api.deleteUser.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    const jdoeRow = (await screen.findByText('jdoe')).closest('tr');

    await user.click(within(jdoeRow).getByTitle('Delete user'));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => expect(api.deleteUser).toHaveBeenCalledWith(2));
  });

  it('force-disabling 2FA also confirms first', async () => {
    api.adminDisableUserMfa.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    // Only the admin row has mfa_enabled: true.
    const adminRow = (await screen.findByText('admin')).closest('tr');

    await user.click(within(adminRow).getByTitle('Force-disable 2FA (account recovery)'));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Disable 2FA' }));

    await waitFor(() => expect(api.adminDisableUserMfa).toHaveBeenCalledWith(1));
  });
});

describe('UserManagement — toggle enabled and role change', () => {
  it('enabling/disabling a user calls updateUser with the flipped flag', async () => {
    api.updateUser.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    const jdoeRow = (await screen.findByText('jdoe')).closest('tr');

    await user.click(within(jdoeRow).getByTitle('Disable user'));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(2, { enabled: false }));
  });

  it('changing role calls updateUser with the new role', async () => {
    api.updateUser.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    const jdoeRow = (await screen.findByText('jdoe')).closest('tr');

    await user.selectOptions(within(jdoeRow).getByRole('combobox'), 'admin');
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(2, { role: 'admin' }));
  });
});

describe('UserManagement — sessions modal', () => {
  it('lists sessions and marks the current one', async () => {
    api.getUserSessions.mockResolvedValue([
      { session_id: 's1', ip: '10.0.0.5', user_agent: 'Chrome', last_seen_at: '2026-09-05T10:00:00', is_current: true },
      { session_id: 's2', ip: '10.0.0.9', user_agent: 'Firefox', last_seen_at: '2026-09-04T09:00:00', is_current: false },
    ]);
    const user = userEvent.setup();
    renderPage();
    const jdoeRow = (await screen.findByText('jdoe')).closest('tr');
    await user.click(within(jdoeRow).getByTitle('View / revoke active sessions'));

    expect(await screen.findByText(/you, right now/)).toBeInTheDocument();
    expect(screen.getByText('10.0.0.9')).toBeInTheDocument();
  });

  it('revokes a session and reloads the list', async () => {
    api.getUserSessions
      .mockResolvedValueOnce([{ session_id: 's1', ip: '10.0.0.5', user_agent: 'Chrome', last_seen_at: null, is_current: false }])
      .mockResolvedValueOnce([]);
    api.revokeUserSession.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    const jdoeRow = (await screen.findByText('jdoe')).closest('tr');
    await user.click(within(jdoeRow).getByTitle('View / revoke active sessions'));

    await user.click(await screen.findByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(api.revokeUserSession).toHaveBeenCalledWith(2, 's1'));
    expect(await screen.findByText('No active sessions.')).toBeInTheDocument();
  });
});
