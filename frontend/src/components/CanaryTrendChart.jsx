import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';

/**
 * Per-day sole-match vs co-matched trend for a canary report — the 3
 * aggregate stat boxes above this answer "how many, total" but hide
 * whether that's a steady rate or one bad day. Needs at least 2 days of
 * data to mean anything as a trend; below that the caller just keeps
 * showing the aggregate boxes alone.
 */
export default function CanaryTrendChart({ data }) {
  if (!data || data.length < 2) return null;

  // ClickHouse's toDate() gives a plain calendar date ("2026-08-20"), not a
  // UTC instant — parsed as local midnight (no 'Z') so the displayed day
  // never shifts across a timezone boundary the way a real timestamp could.
  const chartData = data.map((d) => ({
    ...d,
    label: new Date(`${d.date}T00:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
  }));

  return (
    <div style={{ marginTop: '12px' }}>
      {/* Red/green alone fails colorblind-safe separation (validated via
          the dataviz skill's palette checker — deuteranopia ΔE 5.6, below
          even its 6-8 conditional floor) — solid-vs-dashed line style is
          the secondary encoding that fixes it, so the legend swatches
          match what's actually drawn rather than just repeating color. */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '6px' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
          <svg width="16" height="8" aria-hidden="true"><line x1="0" y1="4" x2="16" y2="4" stroke="var(--danger-color)" strokeWidth="2" /></svg>
          Sole Match
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
          <svg width="16" height="8" aria-hidden="true"><line x1="0" y1="4" x2="16" y2="4" stroke="var(--success-color)" strokeWidth="2" strokeDasharray="4 2" /></svg>
          Co-Matched
        </span>
      </div>
      <ResponsiveContainer width="100%" height={120}>
        <LineChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
          <CartesianGrid stroke="var(--border-color)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
            axisLine={{ stroke: 'var(--border-color)' }}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
            axisLine={false}
            tickLine={false}
            width={28}
          />
          <Tooltip
            contentStyle={{
              background: 'var(--bg-card)', border: '1px solid var(--border-color)',
              borderRadius: '8px', fontSize: '12px', padding: '8px 10px',
            }}
            labelStyle={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '4px' }}
            formatter={(value, name) => [value, name === 'sole_match_count' ? 'Sole Match' : 'Co-Matched']}
            labelFormatter={(label) => label}
          />
          <Line type="monotone" dataKey="sole_match_count" stroke="var(--danger-color)" strokeWidth={2} dot={{ r: 3 }} activeDot={{ r: 5 }} isAnimationActive={false} />
          <Line type="monotone" dataKey="co_matched_count" stroke="var(--success-color)" strokeWidth={2} strokeDasharray="4 2" dot={{ r: 3 }} activeDot={{ r: 5 }} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
