/**
 * Which destination point the Threat Globe should use: an admin's
 * manual override (Settings) takes precedence over the startup
 * auto-detection (threat_globe_location.py) whenever the override is
 * both enabled and has real coordinates; falls back to the
 * auto-detected point otherwise, and to null if neither exists yet.
 * Split into its own module (rather than living in ThreatGlobe.jsx)
 * purely so the component file can stay component-only — needed for
 * Fast Refresh, not a functional requirement.
 */
export function resolveDestination(data) {
  if (!data) return null;
  if (data.override_enabled && data.override_lat != null && data.override_lon != null) {
    return { lat: data.override_lat, lon: data.override_lon, label: data.override_label || 'Custom location' };
  }
  if (data.server_lat != null && data.server_lon != null) {
    return { lat: data.server_lat, lon: data.server_lon, label: data.server_label || 'Protected origin' };
  }
  return null;
}
