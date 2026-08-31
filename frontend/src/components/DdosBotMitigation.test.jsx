import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import DdosBotMitigation from './DdosBotMitigation';
import * as api from '../services/api';

// Covers just the Traffic Composition section (P1 item 5) — the rest of
// this page (rate-limit settings, advanced rules, DDoS analytics) predates
// this change and isn't the target here.
vi.mock('../services/api', () => ({
  getDdosBotSettings: vi.fn().mockResolvedValue(null),
  saveDdosBotSettings: vi.fn(),
  getDdosAnalytics: vi.fn().mockResolvedValue({ timeline: [], top_ips: [], total_blocks: 0, total_unique_ips: 0 }),
  getBotTrafficBreakdown: vi.fn(),
  getTopBotIdentities: vi.fn(),
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

    render(<DdosBotMitigation />);

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

    render(<DdosBotMitigation />);

    await waitFor(() => expect(screen.getByText('No traffic recorded yet.')).toBeInTheDocument());
    expect(screen.getByText('No non-browser traffic identified yet.')).toBeInTheDocument();
  });

  it('labels a request with no User-Agent instead of rendering an empty cell', async () => {
    api.getBotTrafficBreakdown.mockResolvedValue([{ category: 'No User-Agent', count: 5, blocked_count: 3 }]);
    api.getTopBotIdentities.mockResolvedValue([{ user_agent: '', category: 'Scripted Client', count: 1 }]);

    render(<DdosBotMitigation />);

    expect(await screen.findByText('(empty)')).toBeInTheDocument();
  });
});
