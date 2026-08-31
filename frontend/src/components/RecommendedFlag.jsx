import { TriangleAlert } from 'lucide-react';

/**
 * Recommended-baseline flag (P2 item 8 of the WAAP console teardown
 * roadmap — Cloudflare's "guidance + flexibility" pattern: show which
 * settings have drifted from the recommended posture, without forcing
 * them). Deliberately scoped to a handful of settings where "more secure"
 * has no real operational downside (HSTS, server cloaking, the WAF engine
 * actually being on and blocking, audit logging) — NOT the settings that
 * are off by design (admin IP allowlist, geo-block, positive security,
 * auto-learning), which need real per-deployment configuration before
 * they're safe to turn on and would be bad advice to blanket-recommend.
 *
 * Only renders when the current value actually differs from the
 * recommendation — matches every existing settings section's own pattern
 * of surfacing only what needs attention, not congratulating every already
 * -correct field.
 */
export default function RecommendedFlag({ current, recommended, label }) {
  if (current === recommended) return null;
  return (
    <span
      title={`Recommended: ${label ?? String(recommended)}`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: '4px', flexShrink: 0,
        fontSize: '10px', fontWeight: 700, padding: '2px 7px', borderRadius: '999px',
        textTransform: 'uppercase', letterSpacing: '0.02em',
        background: 'var(--warning-bg, var(--sev-low-bg))', color: 'var(--warning-color)', whiteSpace: 'nowrap',
      }}
    >
      <TriangleAlert size={10} />
      Recommended: {label ?? String(recommended)}
    </span>
  );
}
