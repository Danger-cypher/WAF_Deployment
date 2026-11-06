/**
 * Standard RechartsTooltip props to apply when not using a custom content component,
 * or as fallback defaults for any direct <RechartsTooltip {...defaultTooltipProps} />
 */
export const defaultTooltipProps = {
  contentStyle: {
    background: 'var(--chart-tooltip-bg)',
    border: '1px solid var(--chart-tooltip-border, var(--border-strong))',
    borderRadius: '8px',
    boxShadow: 'var(--shadow-card)',
    fontSize: '12px',
    color: 'var(--text-primary)'
  },
  itemStyle: {
    color: 'var(--text-primary)',
    fontSize: '12px',
    padding: '2px 0'
  },
  labelStyle: {
    color: 'var(--text-secondary)',
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    marginBottom: '4px'
  }
};
