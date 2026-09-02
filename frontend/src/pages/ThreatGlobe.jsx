import { useEffect, useRef, useState } from 'react';
import { getLiveStreamWsUrl, getThreatGlobeSettings, saveThreatGlobeSettings } from '../services/api';
import { createThreatGlobeEngine } from '../utils/threatGlobeEngine';
import { resolveDestination } from '../utils/threatGlobeDestination';
import worldCountries from '../data/world-countries.json';

/**
 * Threat Globe — live 3D visualization of attack origins (P1 item 4 of
 * the WAAP console teardown roadmap). This component owns the container
 * markup, the live WebSocket feed, and the destination setting; the
 * actual WebGL scene lives in threatGlobeEngine.js (see its docstring
 * for why that's imperative rather than React-driven).
 *
 * Data flow: reuses the existing /ws/logs/stream socket (the same one
 * NotificationBell already opens for the live log feed) rather than a
 * new channel — every blocked request already broadcasts there. Events
 * without a geo fix (geo_lat/geo_lon are null — private IP, City DB
 * unavailable, or no MaxMind record for that address) are skipped
 * rather than plotted at a fabricated point.
 */

const SEV_TOKENS = { critical: '--danger-color', high: '--sev-high', medium: '--sev-medium', low: '--sev-low' };
const SEV_FALLBACK = { critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

function readSevColors() {
  const cs = getComputedStyle(document.documentElement);
  const out = {};
  for (const [key, token] of Object.entries(SEV_TOKENS)) {
    out[key] = cs.getPropertyValue(token).trim() || SEV_FALLBACK[key];
  }
  return out;
}

export default function ThreatGlobe({ userRole }) {
  const rootRef = useRef(null);
  const engineRef = useRef(null);
  const [destination, setDestinationState] = useState(null);
  const [destChecked, setDestChecked] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [overrideForm, setOverrideForm] = useState({ lat: '', lon: '', label: '' });
  const [savingOverride, setSavingOverride] = useState(false);
  const [overrideError, setOverrideError] = useState('');

  // Engine lifecycle — created once on mount, disposed on unmount. Not
  // re-created on destination change; setDestination() updates it in place.
  useEffect(() => {
    if (!rootRef.current) return undefined;
    const engine = createThreatGlobeEngine(rootRef.current, worldCountries, readSevColors());
    engineRef.current = engine;
    return () => {
      engine.dispose();
      engineRef.current = null;
    };
  }, []);

  // Fetch the configured destination once on mount.
  useEffect(() => {
    let cancelled = false;
    getThreatGlobeSettings()
      .then((data) => {
        if (cancelled) return;
        const dest = resolveDestination(data);
        setDestinationState(dest);
      })
      .catch(() => { /* leave destination unset — the empty state below still explains why */ })
      .finally(() => { if (!cancelled) setDestChecked(true); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (destination && engineRef.current) {
      engineRef.current.setDestination(destination);
    }
  }, [destination]);

  // Live event feed — same socket the notification bell uses.
  useEffect(() => {
    const ws = new WebSocket(getLiveStreamWsUrl());
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (evt) => {
      let msg;
      try {
        msg = JSON.parse(evt.data);
      } catch {
        return;
      }
      if (msg.type !== 'log') return;
      const d = msg.data || {};
      // geo_lat/geo_lon are null for private/loopback IPs (no real point
      // to plot for 192.168.x.x) and for public IPs the City DB has no
      // fix for — the engine still counts these toward the HUD, it just
      // can't draw an arc for them. See threatGlobeEngine.js's fireAttack.
      engineRef.current?.fireAttack({
        lat: d.geo_lat,
        lon: d.geo_lon,
        country: d.country || '',
        city: d.geo_city || '',
        severity: (d.severity || 'low').toLowerCase(),
      });
    };
    return () => ws.close();
  }, []);

  async function submitOverride(e) {
    e.preventDefault();
    setOverrideError('');
    const lat = parseFloat(overrideForm.lat);
    const lon = parseFloat(overrideForm.lon);
    if (Number.isNaN(lat) || lat < -90 || lat > 90) {
      setOverrideError('Latitude must be a number between -90 and 90.');
      return;
    }
    if (Number.isNaN(lon) || lon < -180 || lon > 180) {
      setOverrideError('Longitude must be a number between -180 and 180.');
      return;
    }
    setSavingOverride(true);
    try {
      const current = await getThreatGlobeSettings();
      const saved = await saveThreatGlobeSettings({
        ...current,
        override_enabled: true,
        override_lat: lat,
        override_lon: lon,
        override_label: overrideForm.label || 'Custom location',
      });
      setDestinationState(resolveDestination(saved));
    } catch (err) {
      setOverrideError(err?.message || 'Failed to save destination.');
    } finally {
      setSavingOverride(false);
    }
  }

  const showEmptyState = destChecked && !destination;

  return (
    <div className="tg-root" ref={rootRef}>
      <canvas className="tg-canvas" />
      <div className="tg-vignette" aria-hidden="true" />
      <div className="tg-brackets" aria-hidden="true">
        <span className="tl" /><span className="tr" /><span className="bl" /><span className="br" />
      </div>

      <header className="tg-top">
        <div className="tg-wordmark tg-panel">
          <span className="tg-name">CYBER<em>SENTINEL</em></span>
          <span className="tg-live-pill">
            <span className="tg-live-dot" style={{ background: wsConnected ? undefined : 'var(--sev-low)' }} />
            {wsConnected ? 'LIVE' : 'CONNECTING…'}
          </span>
          <span className="tg-clock" data-tg="clock">--:--:-- UTC</span>
        </div>
        <div className="tg-top-right">
          <button className="tg-ctrl-btn" data-tg="btn-rotate" type="button">⟳ AUTO-ROTATE</button>
          <button className="tg-ctrl-btn" data-tg="btn-pause" type="button">❚❚ PAUSE FEED</button>
        </div>
      </header>

      <aside className="tg-rail">
        <div className="tg-rail-section tg-panel">
          <div className="tg-rail-title">Throughput</div>
          <div className="tg-throughput-value">
            <span data-tg="rate">0</span><span className="tg-unit">req/s blocked</span>
          </div>
          <canvas className="tg-spark" data-tg="spark" width="420" height="68" />
          <div className="tg-throughput-total">Session total <b data-tg="total">0</b> blocked</div>
          <div className="tg-throughput-total" data-tg="unmapped-row" hidden>
            <b data-tg="unmapped">0</b> from internal/private IPs — not mappable
          </div>
        </div>
        <div className="tg-rail-section tg-panel">
          <div className="tg-rail-title">Active vectors — by origin</div>
          <div data-tg="vector-list" />
        </div>
        <div className="tg-rail-section tg-panel">
          <div className="tg-rail-title">Severity mix</div>
          <div className="tg-sev-mix" data-tg="sev-mix" />
        </div>
      </aside>

      <section className="tg-feed tg-panel">
        <div className="tg-feed-head">
          <span className="tg-rail-title" style={{ margin: 0 }}>Live event feed</span>
          <span data-tg="feed-count">0 events</span>
        </div>
        <div className="tg-feed-list" data-tg="feed-list" />
      </section>

      <div className="tg-legend tg-panel">
        <span className="tg-legend-item"><span className="tg-legend-dot" style={{ background: 'var(--danger-color)' }} />Critical</span>
        <span className="tg-legend-item"><span className="tg-legend-dot" style={{ background: 'var(--sev-high)' }} />High</span>
        <span className="tg-legend-item"><span className="tg-legend-dot" style={{ background: 'var(--sev-medium)' }} />Medium</span>
        <span className="tg-legend-item"><span className="tg-legend-dot" style={{ background: 'var(--accent-color)' }} />Protected origin</span>
      </div>

      {showEmptyState && userRole === 'admin' && (
        <div className="tg-empty">
          <h3>No destination configured yet</h3>
          <p>
            The globe needs somewhere for attack arcs to land. This is usually auto-detected from
            this server's public IP a few seconds after backend startup — if it's been longer than
            that, set one manually below (useful behind a CDN or reverse proxy, where the
            auto-detected address often isn't the real deployment location).
          </p>
          <form className="tg-empty-form" onSubmit={submitOverride}>
            <input
              type="text" inputMode="decimal" placeholder="Latitude"
              value={overrideForm.lat}
              onChange={(e) => setOverrideForm({ ...overrideForm, lat: e.target.value })}
            />
            <input
              type="text" inputMode="decimal" placeholder="Longitude"
              value={overrideForm.lon}
              onChange={(e) => setOverrideForm({ ...overrideForm, lon: e.target.value })}
            />
            <input
              type="text" placeholder="Label (e.g. FRA-1)"
              value={overrideForm.label}
              onChange={(e) => setOverrideForm({ ...overrideForm, label: e.target.value })}
            />
            <button type="submit" disabled={savingOverride}>{savingOverride ? 'Saving…' : 'Set destination'}</button>
          </form>
          {overrideError && <p style={{ color: 'var(--danger-color)' }}>{overrideError}</p>}
        </div>
      )}
      {showEmptyState && userRole !== 'admin' && (
        <div className="tg-empty">
          <h3>No destination configured yet</h3>
          <p>An admin needs to set this deployment's location from this view before attack arcs can be plotted.</p>
        </div>
      )}
    </div>
  );
}
