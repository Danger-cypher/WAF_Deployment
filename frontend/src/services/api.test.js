import { describe, it, expect, afterEach, vi } from 'vitest';
import { getLiveStreamWsUrl } from './api';

describe('getLiveStreamWsUrl', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('builds a ws:// URL for http pages', () => {
    vi.stubGlobal('location', { protocol: 'http:', host: 'dashboard.local:8080' });
    expect(getLiveStreamWsUrl()).toBe('ws://dashboard.local:8080/ws/logs/stream');
  });

  it('builds a wss:// URL for https pages (never mixed content)', () => {
    vi.stubGlobal('location', { protocol: 'https:', host: 'dashboard.example.com' });
    expect(getLiveStreamWsUrl()).toBe('wss://dashboard.example.com/ws/logs/stream');
  });
});
