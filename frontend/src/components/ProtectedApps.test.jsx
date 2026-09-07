import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ProtectedApps from './ProtectedApps';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// Audit finding P3-05: this screen owns the entire proxy/routing config —
// add, edit, delete, enable/disable an app, plus its login-protection,
// API-schema and mTLS sub-features — and had zero coverage.

vi.mock('../services/api', () => ({
  getProtectedApps: vi.fn(),
  deleteProtectedApp: vi.fn(),
  toggleProtectedApp: vi.fn(),
  getDdosBotSettings: vi.fn(),
  saveDdosBotSettings: vi.fn(),
  getAppSchema: vi.fn(),
  saveAppSchema: vi.fn(),
  importAppSchemaFromOpenApi: vi.fn(),
  getAppMtls: vi.fn(),
  saveAppMtls: vi.fn(),
  uploadMtlsCaCert: vi.fn(),
  removeMtlsCaCert: vi.fn(),
}));

function renderPage(props = {}) {
  return render(
    <ConfirmProvider>
      <ProtectedApps onOpenWizard={vi.fn()} {...props} />
    </ConfirmProvider>
  );
}

const APP = {
  id: 5, name: 'Shop', domain: 'shop.example.com', protocol: 'http',
  upstream_host: '10.0.0.20', upstream_port: 8080, is_active: true,
  rate_limit_rps: 20, burst_tolerance: 10,
};

beforeEach(() => {
  vi.clearAllMocks();
  api.getProtectedApps.mockResolvedValue([APP]);
  api.getDdosBotSettings.mockResolvedValue({ advanced_rules: [] });
});

describe('ProtectedApps — list rendering', () => {
  it('renders an app card with domain, upstream and rate limit', async () => {
    renderPage();
    expect(await screen.findByText('Shop')).toBeInTheDocument();
    expect(screen.getByText('shop.example.com')).toBeInTheDocument();
    expect(screen.getByText('http://10.0.0.20:8080')).toBeInTheDocument();
    expect(screen.getByText('20 RPS (Burst: 10)')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('shows an empty state with no apps configured', async () => {
    api.getProtectedApps.mockResolvedValue([]);
    renderPage();
    expect(await screen.findByText('No Applications Configured')).toBeInTheDocument();
  });

  it('a load failure surfaces a toast rather than an infinite spinner', async () => {
    api.getProtectedApps.mockRejectedValue(new Error('boom'));
    renderPage();
    expect(await screen.findByText('Failed to fetch applications list.')).toBeInTheDocument();
  });
});

describe('ProtectedApps — enable/disable and delete', () => {
  it('toggles active state', async () => {
    api.toggleProtectedApp.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByTitle('Disable Application'));
    await waitFor(() => expect(api.toggleProtectedApp).toHaveBeenCalledWith(5));
  });

  it('does not delete when confirmation is cancelled', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(api.deleteProtectedApp).not.toHaveBeenCalled();
  });

  it('deletes once confirmed and refreshes the list', async () => {
    api.deleteProtectedApp.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(api.deleteProtectedApp).toHaveBeenCalledWith(5));
    await waitFor(() => expect(api.getProtectedApps).toHaveBeenCalledTimes(2));
  });
});

describe('ProtectedApps — login protection', () => {
  it('rejects a path that does not start with / and never saves', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Protect Login/ }));
    const pathInput = await screen.findByLabelText('Login Path');
    await user.clear(pathInput);
    await user.type(pathInput, 'login');
    await user.click(screen.getByRole('button', { name: 'Apply Protection' }));

    expect(await screen.findByText("Login path must start with '/'.")).toBeInTheDocument();
    expect(api.saveDdosBotSettings).not.toHaveBeenCalled();
  });

  it('saves a new login-protection rule scoped to this app only', async () => {
    api.getDdosBotSettings.mockResolvedValue({ advanced_rules: [] });
    api.saveDdosBotSettings.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Protect Login/ }));
    await user.click(await screen.findByRole('button', { name: 'Apply Protection' }));

    await waitFor(() => expect(api.saveDdosBotSettings).toHaveBeenCalled());
    const saved = api.saveDdosBotSettings.mock.calls.at(-1)[0];
    expect(saved.advanced_rules).toHaveLength(1);
    expect(saved.advanced_rules[0]).toMatchObject({
      id: 'login_protect_app_5',
      parameter_type: 'Host+URI',
      parameter_value: 'shop.example.com/login',
    });
  });

  it('is unavailable for the wildcard/catch-all app (domain "_")', async () => {
    api.getProtectedApps.mockResolvedValue([{ ...APP, domain: '_' }]);
    renderPage();
    expect(await screen.findByRole('button', { name: /Protect Login/ })).toBeDisabled();
  });
});

describe('ProtectedApps — API schema modal', () => {
  it('shows an invalid-JSON error and never saves', async () => {
    api.getAppSchema.mockResolvedValue({ mode: 'log', endpoints: [] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /API Schema/ }));
    const textarea = await screen.findByLabelText('Endpoints (JSON array)');
    await user.clear(textarea);
    await user.type(textarea, '{{not valid json');
    await user.click(screen.getByRole('button', { name: 'Save Schema' }));

    expect(await screen.findByText(/Invalid JSON|Unexpected/i)).toBeInTheDocument();
    expect(api.saveAppSchema).not.toHaveBeenCalled();
  });

  it('loads existing schema and saves edits', async () => {
    api.getAppSchema.mockResolvedValue({ mode: 'log', endpoints: [{ method: 'GET', path: '/x' }] });
    api.saveAppSchema.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /API Schema/ }));
    await user.selectOptions(await screen.findByLabelText('Mode'), 'enforce');
    await user.click(screen.getByRole('button', { name: 'Save Schema' }));

    await waitFor(() => expect(api.saveAppSchema).toHaveBeenCalledWith(5, {
      mode: 'enforce',
      endpoints: [{ method: 'GET', path: '/x' }],
    }));
  });
});

describe('ProtectedApps — mTLS modal', () => {
  it('keeps Enable mTLS disabled until a CA certificate is uploaded', async () => {
    api.getAppMtls.mockResolvedValue({ enabled: false, mode: 'log', ca_cert_uploaded: false });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /mTLS/ }));
    expect(await screen.findByRole('switch', { name: 'Enable mTLS' })).toBeDisabled();
  });

  it('refuses to save enabled=true without a CA cert client-side', async () => {
    // Simulated impossible-but-defensive state: enabled somehow true, no CA.
    api.getAppMtls.mockResolvedValue({ enabled: true, mode: 'log', ca_cert_uploaded: false });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /mTLS/ }));
    await user.click(await screen.findByRole('button', { name: /Save mTLS Settings/ }));
    expect(await screen.findByText('Upload a CA certificate before enabling mTLS.')).toBeInTheDocument();
    expect(api.saveAppMtls).not.toHaveBeenCalled();
  });

  it('uploads a CA cert, then removing it disables mTLS client-side too', async () => {
    api.getAppMtls.mockResolvedValue({ enabled: false, mode: 'log', ca_cert_uploaded: false });
    api.uploadMtlsCaCert.mockResolvedValue({});
    api.removeMtlsCaCert.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /mTLS/ }));

    const file = new File(['cert'], 'ca.pem', { type: 'application/x-pem-file' });
    const fileInput = document.querySelector('input[type="file"][accept=".crt,.pem,.cer"]');
    await user.upload(fileInput, file);

    expect(await screen.findByText('Uploaded')).toBeInTheDocument();
    expect(api.uploadMtlsCaCert).toHaveBeenCalledWith(5, file);

    await user.click(screen.getByRole('button', { name: 'Remove CA certificate' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));

    await waitFor(() => expect(api.removeMtlsCaCert).toHaveBeenCalledWith(5));
    expect(screen.queryByText('Uploaded')).not.toBeInTheDocument();
  });
});
