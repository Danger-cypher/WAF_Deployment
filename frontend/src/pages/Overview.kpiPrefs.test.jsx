import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DEFAULT_KPI_ORDER, KPI_LABELS, loadKpiPrefs, saveKpiPrefs } from '../utils/kpiPrefs';
import { KpiCustomizePanel } from './Overview';

// Covers just the configurable-KPI-cards feature (P1 item 6) in isolation —
// mounting the full Overview page would mean mocking a dozen unrelated API
// calls for a purely client-side, localStorage-backed preference.
describe('KPI card preferences (load/save)', () => {
  beforeEach(() => localStorage.clear());

  it('defaults to every card visible, in the standard order, when nothing is saved', () => {
    expect(loadKpiPrefs('admin')).toEqual({ order: DEFAULT_KPI_ORDER, hidden: [] });
  });

  it('round-trips a saved order and hidden set', () => {
    const prefs = { order: ['xss', 'sqli', 'total_requests', 'blocked_threats', 'block_rate', 'unique_attackers'], hidden: ['sqli'] };
    saveKpiPrefs('admin', prefs);
    expect(loadKpiPrefs('admin')).toEqual(prefs);
  });

  it('scopes preferences per username — one admin\'s layout never leaks into another\'s', () => {
    saveKpiPrefs('admin', { order: DEFAULT_KPI_ORDER, hidden: ['xss'] });
    expect(loadKpiPrefs('analyst')).toEqual({ order: DEFAULT_KPI_ORDER, hidden: [] });
  });

  it('drops a stale/unknown card id and re-appends any card missing from a saved order, instead of crashing', () => {
    localStorage.setItem(
      'waf_kpi_layout_v1:admin',
      JSON.stringify({ order: ['sqli', 'a_removed_card', 'xss'], hidden: ['a_removed_card'] })
    );
    const result = loadKpiPrefs('admin');
    expect(result.hidden).toEqual([]); // the stale hidden id is dropped too
    expect(result.order).toEqual(expect.arrayContaining(DEFAULT_KPI_ORDER));
    expect(result.order).toHaveLength(DEFAULT_KPI_ORDER.length);
    expect(result.order.slice(0, 2)).toEqual(['sqli', 'xss']); // valid ids keep their relative order
  });

  it('falls back to defaults on corrupt JSON rather than throwing', () => {
    localStorage.setItem('waf_kpi_layout_v1:admin', 'not json');
    expect(loadKpiPrefs('admin')).toEqual({ order: DEFAULT_KPI_ORDER, hidden: [] });
  });
});

describe('KpiCustomizePanel', () => {
  it('lists every card with its label, in the given order', () => {
    render(<KpiCustomizePanel order={DEFAULT_KPI_ORDER} hidden={[]} onChange={() => {}} onClose={() => {}} />);
    for (const label of Object.values(KPI_LABELS)) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it('unchecking a card calls onChange with it added to hidden', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<KpiCustomizePanel order={DEFAULT_KPI_ORDER} hidden={[]} onChange={onChange} onClose={() => {}} />);
    await user.click(screen.getByLabelText(KPI_LABELS.sqli));
    expect(onChange).toHaveBeenCalledWith({ order: DEFAULT_KPI_ORDER, hidden: ['sqli'] });
  });

  it('refuses to hide the last visible card', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const allButOneHidden = DEFAULT_KPI_ORDER.slice(1);
    render(<KpiCustomizePanel order={DEFAULT_KPI_ORDER} hidden={allButOneHidden} onChange={onChange} onClose={() => {}} />);
    const lastVisibleCheckbox = screen.getByLabelText(KPI_LABELS[DEFAULT_KPI_ORDER[0]]);
    expect(lastVisibleCheckbox).toBeDisabled();
    await user.click(lastVisibleCheckbox);
    expect(onChange).not.toHaveBeenCalled();
  });

  it('moving a card down swaps it with its neighbor', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<KpiCustomizePanel order={DEFAULT_KPI_ORDER} hidden={[]} onChange={onChange} onClose={() => {}} />);
    await user.click(screen.getByLabelText(`Move ${KPI_LABELS[DEFAULT_KPI_ORDER[0]]} down`));
    const expected = [...DEFAULT_KPI_ORDER];
    [expected[0], expected[1]] = [expected[1], expected[0]];
    expect(onChange).toHaveBeenCalledWith({ order: expected, hidden: [] });
  });

  it('the first card cannot move up and the last cannot move down', () => {
    render(<KpiCustomizePanel order={DEFAULT_KPI_ORDER} hidden={[]} onChange={() => {}} onClose={() => {}} />);
    expect(screen.getByLabelText(`Move ${KPI_LABELS[DEFAULT_KPI_ORDER[0]]} up`)).toBeDisabled();
    expect(screen.getByLabelText(`Move ${KPI_LABELS[DEFAULT_KPI_ORDER[DEFAULT_KPI_ORDER.length - 1]]} down`)).toBeDisabled();
  });

  it('"Reset to default" restores the standard order with nothing hidden', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<KpiCustomizePanel order={['xss', 'sqli']} hidden={['sqli']} onChange={onChange} onClose={() => {}} />);
    await user.click(screen.getByRole('button', { name: /reset to default/i }));
    expect(onChange).toHaveBeenCalledWith({ order: DEFAULT_KPI_ORDER, hidden: [] });
  });
});
