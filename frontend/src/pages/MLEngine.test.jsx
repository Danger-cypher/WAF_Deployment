import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MLEngine from './MLEngine';
import { ConfirmProvider } from '../context/ConfirmContext.jsx';
import * as api from '../services/api';

// Audit finding P3-05: the ML analytics + model-management screen —
// including retrain and rollback, both irreversible-ish operational
// actions — had zero coverage.

vi.mock('../services/api', () => ({
  getMLBackups: vi.fn(),
  getMLDriftHistory: vi.fn(),
  getMLFeatureImportance: vi.fn(),
  getMLLogs: vi.fn(),
  getMLModelInfo: vi.fn(),
  getMLRetrainStatus: vi.fn(),
  getMLStats: vi.fn(),
  getMLTimeline: vi.fn(),
  rollbackMLModel: vi.fn(),
  triggerMLRetrain: vi.fn(),
}));

const STATS = {
  total_evaluations: 1000,
  decision_breakdown: { allow: 800, block: 150, rate_limit: 30, log: 20 },
  avg_threat_score: 0.35,
  top_anomalous_uris: [{ uri: '/api/login', count: 40, avg_score: 0.8 }],
  top_anomalous_ips: [{ ip: '10.0.0.9', count: 12, avg_score: 0.9 }],
};

const LOG = {
  id: 'ml1', timestamp: '2026-09-05T10:00:00', remote_addr: '10.0.0.42',
  method: 'POST', uri: '/api/checkout', xgb_prob: 0.9, iso_score: -0.4,
  threat_score: 0.9, decision: 'block',
};

function renderPage() {
  return render(
    <ConfirmProvider>
      <MLEngine />
    </ConfirmProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getMLStats.mockResolvedValue(STATS);
  api.getMLLogs.mockResolvedValue({ data: [LOG], total: 1 });
  api.getMLTimeline.mockResolvedValue({ data: [] });
  api.getMLModelInfo.mockResolvedValue({ model_metadata: {} });
  api.getMLRetrainStatus.mockResolvedValue({ status: 'idle', logs: '' });
  api.getMLBackups.mockResolvedValue({ data: [] });
  api.getMLFeatureImportance.mockResolvedValue({ data: [] });
  api.getMLDriftHistory.mockResolvedValue({ data: [] });
});

describe('MLEngine — analytics tab', () => {
  it('renders metric cards and the anomalous URI/IP leaderboards', async () => {
    renderPage();
    expect(await screen.findByText('1,000')).toBeInTheDocument();
    expect(screen.getByText('/api/login')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.9')).toBeInTheDocument();
  });

  it('renders the inference log row', async () => {
    renderPage();
    expect(await screen.findByText('block')).toBeInTheDocument();
  });

  it('typing a search term re-fetches logs with that filter', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('block');
    await user.type(screen.getByPlaceholderText(/Search by URI, IP, variables/), '10.0.0.42');
    await waitFor(() => expect(api.getMLLogs).toHaveBeenCalledWith(
      1, 10, expect.objectContaining({ search: '10.0.0.42' })
    ));
  });

  it('filtering by decision re-fetches with that filter', async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText('block');
    await user.selectOptions(screen.getByDisplayValue('All Actions'), 'block');
    await waitFor(() => expect(api.getMLLogs).toHaveBeenCalledWith(
      1, 10, expect.objectContaining({ decision: 'block' })
    ));
  });

  it('clicking a log row opens its detail drawer', async () => {
    const user = userEvent.setup();
    renderPage();
    const row = (await screen.findByText('block')).closest('tr');
    await user.click(row);
    expect(await screen.findByText('Threat Evaluation')).toBeInTheDocument();
  });
});

describe('MLEngine — model management tab', () => {
  it('fetches and renders model info, backups and drift history', async () => {
    api.getMLModelInfo.mockResolvedValue({
      model_metadata: { xgboost: { accuracy: 0.97, sample_count: 5000, version: '3', training_date: '2026-09-01T00:00:00' } },
    });
    api.getMLBackups.mockResolvedValue({ data: [{ timestamp: 'bk1', formatted_date: '2026-09-01', xgboost: true, isolation_forest: true }] });
    api.getMLDriftHistory.mockResolvedValue({ data: [{ id: 1, timestamp: '2026-09-01T00:00:00', total_requests: 500, avg_threat_score: 0.4, drift_detected: false }] });
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: /Model Control & Retraining/ }));

    expect(await screen.findByText('97.0%')).toBeInTheDocument();
    expect(screen.getByText('2026-09-01')).toBeInTheDocument();
    expect(screen.getByText('Stable')).toBeInTheDocument();
  });

  it('triggering retrain confirms first, then disables the button while running', async () => {
    api.triggerMLRetrain.mockResolvedValue({ status: 'success' });
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: /Model Control & Retraining/ }));
    await user.click(await screen.findByRole('button', { name: /Retrain ML Models/ }));

    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Retrain' }));

    await waitFor(() => expect(api.triggerMLRetrain).toHaveBeenCalled());
    expect(await screen.findByRole('button', { name: /Training/ })).toBeDisabled();
  });

  it('does not retrain when cancelled', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: /Model Control & Retraining/ }));
    await user.click(await screen.findByRole('button', { name: /Retrain ML Models/ }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(api.triggerMLRetrain).not.toHaveBeenCalled();
  });

  it('rolling back confirms first and calls the API with the backup timestamp', async () => {
    api.getMLBackups.mockResolvedValue({ data: [{ timestamp: 'bk-2026-09-01', formatted_date: '2026-09-01', xgboost: true, isolation_forest: true }] });
    api.rollbackMLModel.mockResolvedValue({ status: 'success', message: 'Rolled back.' });
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole('button', { name: /Model Control & Retraining/ }));
    await user.click(await screen.findByRole('button', { name: 'Rollback' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/bk-2026-09-01/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Roll back' }));

    await waitFor(() => expect(api.rollbackMLModel).toHaveBeenCalledWith('bk-2026-09-01'));
    expect(await screen.findByText('Rolled back.')).toBeInTheDocument();
  });
});
