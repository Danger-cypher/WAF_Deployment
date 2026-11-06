/**
 * Standard enterprise SIEM ChartTooltip component for Recharts.
 * Provides identical executive hover styling across all dashboard and analytics charts,
 * matching both Matte Slate (light) and Cyber Console (dark) themes.
 */
export default function ChartTooltip({
  active,
  payload,
  label,
  valueFormatter,
  labelFormatter,
  showDot = true,
}) {
  if (!active || !payload || !payload.length) return null;

  const displayLabel = labelFormatter ? labelFormatter(label) : label;

  return (
    <div
      className="ui-chart-tooltip"
      style={{
        background: 'var(--chart-tooltip-bg)',
        border: '1px solid var(--chart-tooltip-border, var(--border-strong))',
        borderRadius: '8px',
        padding: '10px 14px',
        fontSize: '12px',
        boxShadow: 'var(--shadow-card)',
        pointerEvents: 'none',
        minWidth: '130px'
      }}
    >
      {displayLabel !== undefined && displayLabel !== null && displayLabel !== '' && (
        <div
          style={{
            color: 'var(--text-secondary)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            marginBottom: '6px',
            borderBottom: payload.length > 1 ? '1px solid var(--surface-hover)' : 'none',
            paddingBottom: payload.length > 1 ? '4px' : '0'
          }}
        >
          {displayLabel}
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {payload.map((p, i) => {
          const itemColor = p.color || p.fill || 'var(--accent-color)';
          const itemName = p.name || p.dataKey;
          let itemValue = p.value;
          if (valueFormatter) {
            itemValue = valueFormatter(p.value, itemName, p);
          } else if (typeof itemValue === 'number') {
            itemValue = itemValue.toLocaleString();
          }

          return (
            <div
              key={i}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                marginBottom: '2px',
                fontSize: '12px'
              }}
            >
              {showDot && (
                <div
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: itemColor,
                    flexShrink: 0
                  }}
                />
              )}
              <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-secondary)', fontWeight: 500, fontFamily: 'var(--font-body)', marginRight: '5px' }}>
                  <span>{itemName}</span>:
                </span>
                {itemValue}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
