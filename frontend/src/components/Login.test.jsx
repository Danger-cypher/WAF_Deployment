import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Login from './Login';

// jsdom doesn't implement canvas 2D contexts; the login screen's animated
// particle background just needs enough of a stub to not throw.
beforeEach(() => {
  HTMLCanvasElement.prototype.getContext = () => ({
    clearRect: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    arc: () => {},
    fill: () => {},
    stroke: () => {},
  });
  vi.stubGlobal('fetch', vi.fn());
});

function fillAndSubmit(user, { username = 'admin', password = 'wrongpass' } = {}) {
  return (async () => {
    await user.type(screen.getByPlaceholderText(/username/i), username);
    await user.type(screen.getByPlaceholderText(/password/i), password);
    await user.click(screen.getByRole('button', { name: /initialize session/i }));
  })();
}

describe('Login', () => {
  it('renders username and password fields', () => {
    render(<Login setAuth={() => {}} onLoginSuccess={() => {}} />);
    expect(screen.getByPlaceholderText(/username/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument();
  });

  it('toggles password visibility', async () => {
    const user = userEvent.setup();
    render(<Login setAuth={() => {}} onLoginSuccess={() => {}} />);

    const passwordInput = screen.getByPlaceholderText(/password/i);
    expect(passwordInput).toHaveAttribute('type', 'password');

    await user.click(screen.getByLabelText(/show password/i));
    expect(passwordInput).toHaveAttribute('type', 'text');

    await user.click(screen.getByLabelText(/hide password/i));
    expect(passwordInput).toHaveAttribute('type', 'password');
  });

  it('shows an error message when the API rejects the credentials', async () => {
    globalThis.fetch.mockResolvedValueOnce({ ok: false });
    const user = userEvent.setup();
    render(<Login setAuth={() => {}} onLoginSuccess={() => {}} />);

    await fillAndSubmit(user);

    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
    });
  });

  it('calls onLoginSuccess and setAuth(true) on a successful login', async () => {
    globalThis.fetch
      .mockResolvedValueOnce({ ok: true, json: async () => ({ message: 'Login successful', role: 'admin', mfa_required: false }) }) // /auth/login
      .mockResolvedValueOnce({ ok: true, json: async () => ({ role: 'admin', username: 'admin' }) }); // /auth/me

    const setAuth = vi.fn();
    const onLoginSuccess = vi.fn();
    const user = userEvent.setup();
    render(<Login setAuth={setAuth} onLoginSuccess={onLoginSuccess} />);

    await fillAndSubmit(user, { username: 'admin', password: 'correct-password' });

    await waitFor(() => {
      expect(onLoginSuccess).toHaveBeenCalledWith({ role: 'admin', username: 'admin' });
      expect(setAuth).toHaveBeenCalledWith(true);
    });
  });

  it('switches to the OTP step when the backend reports mfa_required, then completes login', async () => {
    globalThis.fetch
      .mockResolvedValueOnce({ ok: true, json: async () => ({ message: 'MFA code required', mfa_required: true }) }) // /auth/login
      .mockResolvedValueOnce({ ok: true, json: async () => ({ message: 'Login successful', role: 'admin', mfa_required: false }) }) // /auth/login/mfa
      .mockResolvedValueOnce({ ok: true, json: async () => ({ role: 'admin', username: 'admin' }) }); // /auth/me

    const setAuth = vi.fn();
    const onLoginSuccess = vi.fn();
    const user = userEvent.setup();
    render(<Login setAuth={setAuth} onLoginSuccess={onLoginSuccess} />);

    await fillAndSubmit(user, { username: 'admin', password: 'correct-password' });

    const otpInput = await screen.findByPlaceholderText(/enter 6-digit otp code/i);
    expect(screen.queryByPlaceholderText(/username/i)).not.toBeInTheDocument();

    await user.type(otpInput, '123456');
    await user.click(screen.getByRole('button', { name: /verify otp/i }));

    await waitFor(() => {
      expect(onLoginSuccess).toHaveBeenCalledWith({ role: 'admin', username: 'admin' });
      expect(setAuth).toHaveBeenCalledWith(true);
    });
  });

  it('shows an error and stays on the OTP step for an invalid code', async () => {
    globalThis.fetch
      .mockResolvedValueOnce({ ok: true, json: async () => ({ message: 'MFA code required', mfa_required: true }) })
      .mockResolvedValueOnce({ ok: false });

    const user = userEvent.setup();
    render(<Login setAuth={() => {}} onLoginSuccess={() => {}} />);

    await fillAndSubmit(user, { username: 'admin', password: 'correct-password' });
    const otpInput = await screen.findByPlaceholderText(/enter 6-digit otp code/i);
    await user.type(otpInput, '000000');
    await user.click(screen.getByRole('button', { name: /verify otp/i }));

    expect(await screen.findByText(/invalid or expired otp code/i)).toBeInTheDocument();
    // Still on the OTP step, not bounced back to the username/password form.
    expect(screen.getByPlaceholderText(/enter 6-digit otp code/i)).toBeInTheDocument();
  });
});
