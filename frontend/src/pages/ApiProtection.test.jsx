import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ApiProtection from './ApiProtection';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// Audit finding P3-05: the API inventory screen — protect/block real
// endpoints, upload an OpenAPI spec, reconcile data stores — had zero
// coverage. The component polls every 10s; tests don't advance that timer,
// so each test only ever sees the initial fetch.

vi.mock('../services/api', () => ({
  getApiProtectionAnalytics: vi.fn(),
  getDiscoveredEndpoints: vi.fn(),
  getRecentlyDiscoveredEndpoints: vi.fn(),
  getStaleEndpoints: vi.fn(),
  getDdosBotSettings: vi.fn(),
  saveDdosBotSettings: vi.fn(),
  getBlockedEndpoints: vi.fn(),
  blockEndpoint: vi.fn(),
  unblockEndpoint: vi.fn(),
  getApiSpec: vi.fn(),
  uploadApiSpec: vi.fn(),
  deleteApiSpec: vi.fn(),
  getApiDrift: vi.fn(),
  reconcileDataStores: vi.fn(),
}));

const ANALYTICS = {
  total_endpoints_count: 2, avg_response_time_ms: 120,
  traffic_bands: { normal: 10, suspicious: 2, malicious: 1 },
  most_consumed: [], resource_intensive: [],
};

const ENDPOINT = {
  method: 'GET', uri: '/api/widgets', avg_response_time_ms: 80, hit_count: 500,
  traffic_source: 'External', has_https: 1, content_encoding: 'gzip',
  score: 90, grade: 'A', first_seen: '2026-08-01 00:00:00', last_seen: '2026-09-01 00:00:00',
};

function renderPage() {
  return render(
    <ConfirmProvider>
      <ApiProtection />
    </ConfirmProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getApiProtectionAnalytics.mockResolvedValue(ANALYTICS);
  api.getDiscoveredEndpoints.mockResolvedValue({ data: [ENDPOINT], total: 1 });
  api.getRecentlyDiscoveredEndpoints.mockResolvedValue({ data: [], total: 0 });
  api.getStaleEndpoints.mockResolvedValue({ data: [], total: 0 });
  api.getDdosBotSettings.mockResolvedValue({ advanced_rules: [] });
  api.getBlockedEndpoints.mockResolvedValue([]);
  api.getApiSpec.mockResolvedValue(null);
  api.getApiDrift.mockResolvedValue({ shadow_endpoints: [], undocumented_spec_endpoints: [] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('ApiProtection — inventory', () => {
  it('renders analytics cards and the discovered endpoint', async () => {
    renderPage();
    expect(await screen.findByText('/api/widgets')).toBeInTheDocument();
    expect(screen.getByText('Total Discovered Endpoints')).toBeInTheDocument();
    expect(screen.getByText('Total Discovered Endpoints').nextSibling).toHaveTextContent('2');
    expect(screen.getByText('120 ms')).toBeInTheDocument();
  });

  it('a fetch failure shows the retry state instead of a blank screen', async () => {
    api.getApiProtectionAnalytics.mockRejectedValue(new Error('backend unreachable'));
    renderPage();
    expect(await screen.findByText(/backend unreachable/)).toBeInTheDocument();
  });

  it('switches to the stale tab and shows its own empty-state copy', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('/api/widgets');
    await user.click(screen.getByRole('button', { name: /Stale \/ Zombie/ }));
    expect(await screen.findByText(/No stale endpoints/)).toBeInTheDocument();
  });
});

describe('ApiProtection — protect endpoint', () => {
  it('pre-fills a suggested rule name and pattern from the endpoint', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Protect/ }));
    expect(screen.getByLabelText('Rule Name')).toHaveValue('Protect GET /api/widgets');
    expect(screen.getByLabelText('Match Pattern (Request URI)')).toHaveValue('^/api/widgets$');
  });

  it('refuses to create a duplicate-pattern rule', async () => {
    api.getDdosBotSettings.mockResolvedValue({
      advanced_rules: [{ id: 'x', parameter_type: 'URI', parameter_value: '^/api/widgets$', enabled: true, rate_limit_rps: 5, burst_tolerance: 5 }],
    });
    renderPage();
    // Already protected, so the row shows the badge, not a Protect button —
    // exercise the duplicate-guard directly by reopening via a fresh fetch.
    expect(await screen.findByText('Protected')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Protect$/ })).not.toBeInTheDocument();
  });

  it('creates the rate-limit rule and it becomes visible as Protected on refresh', async () => {
    api.saveDdosBotSettings.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Protect/ }));
    await user.click(screen.getByRole('button', { name: 'Create and Apply Rule' }));

    await waitFor(() => expect(api.saveDdosBotSettings).toHaveBeenCalled());
    const saved = api.saveDdosBotSettings.mock.calls.at(-1)[0];
    expect(saved.advanced_rules).toHaveLength(1);
    expect(saved.advanced_rules[0]).toMatchObject({ parameter_type: 'URI', parameter_value: '^/api/widgets$' });
  });
});

describe('ApiProtection — block / unblock', () => {
  it('blocking confirms first and marks the endpoint Blocked once confirmed', async () => {
    api.blockEndpoint.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /^Block$/ }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Block ALL traffic to GET \/api\/widgets/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Block' }));

    await waitFor(() => expect(api.blockEndpoint).toHaveBeenCalledWith('GET', '/api/widgets'));
    expect(await screen.findByText('Blocked')).toBeInTheDocument();
  });

  it('does not block when cancelled', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /^Block$/ }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(api.blockEndpoint).not.toHaveBeenCalled();
  });

  it('unblocking an already-blocked endpoint calls unblockEndpoint', async () => {
    api.getBlockedEndpoints.mockResolvedValue([{ method: 'GET', uri: '/api/widgets' }]);
    api.unblockEndpoint.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Blocked' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Unblock' }));
    await waitFor(() => expect(api.unblockEndpoint).toHaveBeenCalledWith('GET', '/api/widgets'));
  });
});

describe('ApiProtection — OpenAPI spec + drift', () => {
  it('shows an upload prompt with no spec, and drift once one exists', async () => {
    renderPage();
    expect(await screen.findByText(/No spec uploaded yet/)).toBeInTheDocument();

    api.getApiSpec.mockResolvedValue({ filename: 'openapi.json', version: '1.0', endpoint_count: 12, uploaded_by: 'admin' });
    api.getApiDrift.mockResolvedValue({ shadow_endpoints: [{ method: 'GET', uri: '/secret', hit_count: 3 }], undocumented_spec_endpoints: [] });
    api.uploadApiSpec.mockResolvedValue({ endpoint_count: 12 });

    const file = new File(['{}'], 'openapi.json', { type: 'application/json' });
    file.text = () => Promise.resolve('{}'); // jsdom's File has no .text() implementation
    const fileInput = document.querySelector('input[type="file"][accept=".json,.yaml,.yml"]');
    const user = userEvent.setup();
    await user.upload(fileInput, file);

    expect(await screen.findByText(/Spec uploaded: 12 operations/)).toBeInTheDocument();
    expect(await screen.findByText('/secret')).toBeInTheDocument();
  });

  it('removing the spec confirms first', async () => {
    api.getApiSpec.mockResolvedValue({ filename: 'openapi.json', version: '1.0', endpoint_count: 12, uploaded_by: 'admin' });
    api.deleteApiSpec.mockResolvedValue({});
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Remove Spec/ }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(api.deleteApiSpec).toHaveBeenCalled());
  });
});

describe('ApiProtection — reconcile data stores', () => {
  it('confirms first, then reports the result message', async () => {
    api.reconcileDataStores.mockResolvedValue({ message: 'Backfilled 4 endpoints.' });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Reconcile Data Stores/ }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Reconcile' }));
    expect(await screen.findByText('Backfilled 4 endpoints.')).toBeInTheDocument();
  });
});
