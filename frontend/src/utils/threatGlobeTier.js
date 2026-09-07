/**
 * Classifies a live WAF event into one of three traffic tiers for the
 * Threat Globe: the ModSecurity audit log this stream is sourced from
 * (SecAuditEngine On) captures nearly all traffic, not just attacks —
 * confirmed live: in a 6h sample, ~5% of logged events were genuine
 * blocks, ~73% were CRS-flagged but allowed through (anomaly score under
 * the block threshold), and the rest never matched a rule at all.
 * Painting all three identically as "blocked" is actively misleading, so
 * every event is classified here before it reaches the rendering engine.
 *
 * - 'blocked': a rule matched AND the response was denied (403 — this
 *   deployment's actual block status, confirmed against both its custom
 *   rules and CRS's default blocking response).
 * - 'flagged': a rule matched but the request still went through (any
 *   other status) — real signal, nothing was enforced.
 * - 'normal': no rule matched at all — genuinely clean traffic. Its
 *   severity/attack_type fields are just the model's unclassified
 *   defaults ("Low"/"Unknown"), not a real signal.
 */
export function classifyTier(d) {
  if (!d || !d.rule_id) return 'normal';
  return d.http_code === '403' ? 'blocked' : 'flagged';
}
