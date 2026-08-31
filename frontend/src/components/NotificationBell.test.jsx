import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import NotificationBell from './NotificationBell';
import * as api from '../services/api';

// Covers the WS-vs-REST duplicate-count race this session's notification
// review flagged: the initial REST fetch and the WebSocket connection both
// fire on mount, so an alert created in that window (or redelivered on a
// reconnect) could previously be counted once by each.
vi.mock('../services/api', () => ({
  getAlertHistory: vi.fn(),
  acknowledgeAlert: vi.fn(),
  getMyNotificationPreferences: vi.fn().mockResolvedValue({ muted_severities: [], muted_event_types: [] }),
  getLiveStreamWsUrl: vi.fn().mockReturnValue('ws://localhost/ws/logs/stream'),
}));

class FakeWebSocket {
  constructor(url) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  close() {}
}
FakeWebSocket.instances = [];

const alert = (id) => ({
  id, rule_id: 1, rule_name: 'test-rule', event_type: 'attack_detected', severity: 'high',
  message: `alert ${id}`, status: 'sent', created_at: '2026-08-31T12:00:00Z',
});

beforeEach(() => {
  FakeWebSocket.instances = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
});

function badgeCount() {
  // The badge <span> only renders at all once unreadCount > 0.
  const bell = screen.getByRole('button');
  const badge = bell.querySelector('span');
  return badge ? Number(badge.textContent) : 0;
}

describe('NotificationBell — WS/REST duplicate-count race', () => {
  it('does not double-count a WS push for an alert the initial REST fetch already included', async () => {
    api.getAlertHistory.mockResolvedValue([alert(1)]);
    render(<NotificationBell onOpenHistory={() => {}} onOpenSettings={() => {}} />);

    await waitFor(() => expect(badgeCount()).toBe(1));

    const ws = FakeWebSocket.instances[0];
    act(() => {
      ws.onmessage({ data: JSON.stringify({ type: 'alert', data: alert(1) }) });
    });

    // Same id redelivered over WS — count must stay at 1, not jump to 2.
    expect(badgeCount()).toBe(1);
  });

  it('still counts a genuinely new alert pushed over WS', async () => {
    api.getAlertHistory.mockResolvedValue([alert(1)]);
    render(<NotificationBell onOpenHistory={() => {}} onOpenSettings={() => {}} />);

    await waitFor(() => expect(badgeCount()).toBe(1));

    const ws = FakeWebSocket.instances[0];
    act(() => {
      ws.onmessage({ data: JSON.stringify({ type: 'alert', data: alert(2) }) });
    });

    expect(badgeCount()).toBe(2);
  });

  it('a duplicate WS push replaces the row in the visible list instead of adding a second copy', async () => {
    api.getAlertHistory.mockResolvedValue([alert(1)]);
    render(<NotificationBell onOpenHistory={() => {}} onOpenSettings={() => {}} />);
    await waitFor(() => expect(badgeCount()).toBe(1));

    const ws = FakeWebSocket.instances[0];
    act(() => {
      ws.onmessage({ data: JSON.stringify({ type: 'alert', data: alert(1) }) });
    });

    // Open the dropdown to render the list, then confirm exactly one row
    // for id 1, not two.
    await act(async () => { screen.getByRole('button').click(); });
    expect(screen.getAllByText('alert 1')).toHaveLength(1);
  });
});
