import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ChartTooltip from './ChartTooltip';
import { defaultTooltipProps } from './chartTooltipProps';

describe('ChartTooltip', () => {
  it('renders nothing when active is false or payload is empty', () => {
    const { container: c1 } = render(<ChartTooltip active={false} payload={[{ name: 'A', value: 10 }]} />);
    expect(c1.firstChild).toBeNull();

    const { container: c2 } = render(<ChartTooltip active={true} payload={[]} />);
    expect(c2.firstChild).toBeNull();

    const { container: c3 } = render(<ChartTooltip active={true} payload={null} />);
    expect(c3.firstChild).toBeNull();
  });

  it('renders label and payload items correctly', () => {
    const payload = [
      { name: 'Blocked Attacks', value: 1420, color: '#ff3b5c' },
      { name: 'Allowed Requests', value: 58000, color: '#00d4ff' }
    ];

    render(<ChartTooltip active={true} label="14:00" payload={payload} />);

    expect(screen.getByText(/14:00/)).toBeInTheDocument();
    expect(screen.getByText(/Blocked Attacks/)).toBeInTheDocument();
    expect(screen.getByText('1,420')).toBeInTheDocument();
    expect(screen.getByText(/Allowed Requests/)).toBeInTheDocument();
    expect(screen.getByText('58,000')).toBeInTheDocument();
  });

  it('supports custom labelFormatter and valueFormatter', () => {
    const payload = [
      { name: 'Avg Threat', value: 0.854, color: '#ff3b5c' }
    ];

    render(
      <ChartTooltip
        active={true}
        label="2026-11-06"
        labelFormatter={(l) => `Date: ${l}`}
        valueFormatter={(v) => `${(v * 100).toFixed(1)}%`}
        payload={payload}
      />
    );

    expect(screen.getByText('Date: 2026-11-06')).toBeInTheDocument();
    expect(screen.getByText(/Avg Threat/)).toBeInTheDocument();
    expect(screen.getByText('85.4%')).toBeInTheDocument();
  });

  it('exports valid defaultTooltipProps', () => {
    expect(defaultTooltipProps).toBeDefined();
    expect(defaultTooltipProps.contentStyle.background).toBe('var(--chart-tooltip-bg)');
    expect(defaultTooltipProps.contentStyle.borderRadius).toBe('8px');
    expect(defaultTooltipProps.itemStyle.color).toBe('var(--text-primary)');
    expect(defaultTooltipProps.labelStyle.fontFamily).toBe('var(--font-mono)');
  });
});
