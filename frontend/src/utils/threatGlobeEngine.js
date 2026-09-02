/**
 * threatGlobeEngine.js — CyberSentinel WAF
 * =========================================
 * The WebGL rendering engine behind the Threat Globe view (P1 item 4 of
 * the WAAP console teardown roadmap). Deliberately framework-agnostic and
 * imperative rather than a React-driven scene graph: this is a
 * continuously-animating WebGL canvas plus a HUD that can receive many
 * events per second under real attack traffic, and re-rendering that
 * through React state on every event would fight the animation loop for
 * no benefit — the same reasoning that keeps the rest of this codebase's
 * canvas-heavy work (e.g. sparkline draws) outside React's render cycle.
 *
 * ThreatGlobe.jsx owns the container markup (canvas + `data-tg="..."`
 * HUD nodes) and this module owns everything that happens inside it:
 * scene setup, the real Natural Earth country geometry baked into the
 * globe's texture, and the per-event arc/comet/ring/label lifecycle.
 *
 * Real-data notes (this is not the design mockup's simulator):
 * - fireAttack() takes an actual WAF event's {lat, lon, country, city,
 *   severity}; there is no random generator here.
 * - Origin markers are created fresh per event at that event's exact
 *   coordinates (real IPs land anywhere on Earth, not at a fixed set of
 *   demo cities) and are disposed together with their arc — there's no
 *   persistent per-city marker registry to maintain.
 * - The destination ("your server") is a single point, set once
 *   fireAttack calls start needing it via setDestination(); events that
 *   arrive before a destination is configured still light up the origin
 *   marker and HUD, they just don't get a flight path yet.
 */
import * as THREE from "three";

const SHIFTS = [-360, 0, 360]; // antimeridian-safe texture tracing — see convertWorldCountries below
const MAX_CONCURRENT_ARCS = 50; // burst safety: a real DDoS wave must stay legible, not become a solid mass of lines
const R = 5; // globe radius, arbitrary three.js units

function latLonToVector3(lat, lon, radius) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
}

function flagEmoji(cc) {
  if (!cc || cc === "Unknown" || cc === "Internal" || cc.length !== 2) return "🌐";
  try {
    return String.fromCodePoint(...cc.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0)));
  } catch {
    return "🌐";
  }
}

function roundRectPath(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function buildGlobeTexture(worldCountries) {
  const w = 2048, h = 1024;
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const ctx = c.getContext("2d");

  const ocean = ctx.createLinearGradient(0, 0, 0, h);
  ocean.addColorStop(0, "#0d1730");
  ocean.addColorStop(0.5, "#0a1226");
  ocean.addColorStop(1, "#0d1730");
  ctx.fillStyle = ocean;
  ctx.fillRect(0, 0, w, h);

  const mapX = (lon) => (lon + 180) / 360 * w;
  const mapY = (lat) => (90 - lat) / 180 * h;

  function traceAllRings() {
    ctx.beginPath();
    worldCountries.forEach((rings) => {
      rings.forEach((ring) => {
        SHIFTS.forEach((shift) => {
          for (let i = 0; i < ring.length; i += 2) {
            const x = mapX(ring[i] + shift), y = mapY(ring[i + 1]);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
          }
          ctx.closePath();
        });
      });
    });
  }

  ctx.fillStyle = "#204066";
  traceAllRings();
  ctx.fill();

  ctx.strokeStyle = "rgba(111,199,214,0.28)";
  ctx.lineWidth = 1;
  ctx.shadowColor = "rgba(111,199,214,0.55)";
  ctx.shadowBlur = 3;
  traceAllRings();
  ctx.stroke();
  ctx.shadowBlur = 0;

  ctx.strokeStyle = "rgba(111,199,214,0.10)";
  ctx.lineWidth = 1;
  for (let lon = 0; lon <= w; lon += w / 24) {
    ctx.beginPath(); ctx.moveTo(lon, 0); ctx.lineTo(lon, h); ctx.stroke();
  }
  for (let lat = 0; lat <= h; lat += h / 12) {
    ctx.beginPath(); ctx.moveTo(0, lat); ctx.lineTo(w, lat); ctx.stroke();
  }
  ctx.strokeStyle = "rgba(232,163,61,0.28)";
  ctx.lineWidth = 1.4;
  ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(w / 2, 0); ctx.lineTo(w / 2, h); ctx.stroke();

  const tex = new THREE.CanvasTexture(c);
  tex.anisotropy = 4;
  return tex;
}

function buildDotTexture() {
  const s = 128;
  const c = document.createElement("canvas");
  c.width = c.height = s;
  const ctx = c.getContext("2d");
  const g = ctx.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2);
  g.addColorStop(0, "rgba(255,255,255,1)");
  g.addColorStop(0.35, "rgba(255,255,255,0.7)");
  g.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, s, s);
  return new THREE.CanvasTexture(c);
}

function buildGlowTexture() {
  const s = 256;
  const c = document.createElement("canvas");
  c.width = c.height = s;
  const ctx = c.getContext("2d");
  const g = ctx.createRadialGradient(s / 2, s / 2, s * 0.32, s / 2, s / 2, s / 2);
  g.addColorStop(0, "rgba(111,199,214,0.5)");
  g.addColorStop(0.6, "rgba(111,199,214,0.13)");
  g.addColorStop(1, "rgba(111,199,214,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, s, s);
  return new THREE.CanvasTexture(c);
}

function makeOriginLabel(text, colorCss) {
  const fontPx = 26, padX = 16, padY = 11;
  const probe = document.createElement("canvas").getContext("2d");
  probe.font = `${fontPx}px "IBM Plex Mono", monospace`;
  const textW = probe.measureText(text).width;

  const c = document.createElement("canvas");
  c.width = Math.ceil(textW + padX * 2);
  c.height = fontPx + padY * 2;
  const ctx = c.getContext("2d");
  ctx.font = `${fontPx}px "IBM Plex Mono", monospace`;
  roundRectPath(ctx, 0.75, 0.75, c.width - 1.5, c.height - 1.5, 8);
  ctx.fillStyle = "rgba(7,11,20,0.85)";
  ctx.fill();
  ctx.strokeStyle = colorCss;
  ctx.lineWidth = 1.4;
  ctx.stroke();
  ctx.fillStyle = "#eef2fa";
  ctx.textBaseline = "middle";
  ctx.fillText(text, padX, c.height / 2 + 1);

  const tex = new THREE.CanvasTexture(c);
  const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false, opacity: 0 });
  const sprite = new THREE.Sprite(mat);
  const hUnits = 0.56, aspect = c.width / c.height;
  sprite.scale.set(hUnits * aspect, hUnits, 1);
  return sprite;
}

/**
 * @param {HTMLElement} rootEl - the `.tg-root` container; must already
 *   contain a `.tg-canvas` <canvas> and the `data-tg="..."` HUD nodes.
 * @param {Array} worldCountries - parsed world-countries.json (array of
 *   countries, each an array of rings, each ring a flat [lon,lat,...]).
 * @param {{critical:string, high:string, medium:string, low:string}} sevColors
 *   - real CSS color values (not var() refs — canvas 2D can't read those).
 */
export function createThreatGlobeEngine(rootEl, worldCountries, sevColors) {
  const canvas = rootEl.querySelector(".tg-canvas");
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 400);
  const REST_Z = 15.5;
  camera.position.set(0, 1.8, reducedMotion ? REST_Z : REST_Z + 9);

  function resize() {
    const w = rootEl.clientWidth, h = rootEl.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(rootEl);
  resize();

  scene.add(new THREE.AmbientLight(0x223355, 1.1));
  const sun = new THREE.DirectionalLight(0xfff3dd, 1.1);
  sun.position.set(6, 4, 8);
  scene.add(sun);

  // starfield
  let starPoints;
  {
    const COUNT = 2600;
    const positions = new Float32Array(COUNT * 3);
    for (let i = 0; i < COUNT; i++) {
      const r = 90 + Math.random() * 60;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const mat = new THREE.PointsMaterial({ color: 0xaebbdd, size: 0.55, sizeAttenuation: true, transparent: true, opacity: 0.75 });
    starPoints = new THREE.Points(geo, mat);
    scene.add(starPoints);
  }

  const globe = new THREE.Group();
  scene.add(globe);

  const surfaceTex = buildGlobeTexture(worldCountries);
  const globeMesh = new THREE.Mesh(
    new THREE.SphereGeometry(R, 64, 48),
    new THREE.MeshPhongMaterial({ map: surfaceTex, shininess: 10, specular: 0x1a2440 })
  );
  globe.add(globeMesh);

  const glowTex = buildGlowTexture();
  const glowSprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
  glowSprite.scale.set(R * 2.7, R * 2.7, 1);
  scene.add(glowSprite);

  const dotTex = buildDotTexture();

  // destination beacon — hidden until setDestination() is called
  const beacon = new THREE.Sprite(new THREE.SpriteMaterial({ map: dotTex, color: 0xe8a33d, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending }));
  beacon.scale.set(0.28, 0.28, 1);
  globe.add(beacon);
  const beaconRing = new THREE.Mesh(
    new THREE.RingGeometry(0.001, 0.02, 32),
    new THREE.MeshBasicMaterial({ color: 0xe8a33d, transparent: true, opacity: 0, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  globe.add(beaconRing);

  let destPos = null; // THREE.Vector3 | null — no arcs render until this is set

  function setDestination({ lat, lon }) {
    destPos = latLonToVector3(lat, lon, R * 1.01);
    beacon.position.copy(destPos);
    beacon.material.opacity = 0.9;
    beaconRing.position.copy(destPos).multiplyScalar(1.001);
    beaconRing.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), destPos.clone().normalize());
    beaconRing.material.opacity = 0.6;
  }

  // ------------------------------------------------------------- arcs
  const activeArcs = [];
  const activeRings = [];

  function arcPoint(a, b, t, height) {
    const v = a.clone().normalize();
    const w = b.clone().normalize();
    const omega = Math.acos(THREE.MathUtils.clamp(v.dot(w), -1, 1));
    const sinOmega = Math.sin(omega) || 1e-6;
    const s1 = Math.sin((1 - t) * omega) / sinOmega;
    const s2 = Math.sin(t * omega) / sinOmega;
    const dir = new THREE.Vector3(
      v.x * s1 + w.x * s2,
      v.y * s1 + w.y * s2,
      v.z * s1 + w.z * s2
    ).normalize();
    const radius = R * 1.01 + height * Math.sin(t * Math.PI);
    return dir.multiplyScalar(radius);
  }

  function spawnRing(pos) {
    const ring = new THREE.Mesh(
      new THREE.RingGeometry(0.06, 0.09, 40),
      new THREE.MeshBasicMaterial({ color: 0xe8a33d, transparent: true, opacity: 0.85, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false })
    );
    ring.position.copy(pos).multiplyScalar(1.002);
    ring.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), pos.clone().normalize());
    globe.add(ring);
    activeRings.push({ mesh: ring, start: performance.now(), duration: reducedMotion ? 1 : 750 });
  }

  function severityHex(sev) {
    const key = sevColors[sev] ? sev : "low";
    return new THREE.Color(sevColors[key]);
  }

  /**
   * event: { lat, lon, country, city, severity } — severity lowercased
   * ('critical'|'high'|'medium'|'low'). Skips the arc/comet entirely
   * (still shows the origin marker + label) if no destination is
   * configured yet, or silently drops the event once
   * MAX_CONCURRENT_ARCS is already in flight — a burst reads as "a lot
   * of activity", not as 500 overlapping lines.
   */
  function fireAttack(event) {
    if (paused) return;

    const { lat, lon, country, city, severity } = event;

    // HUD counters/feed always reflect real traffic, even when there's
    // nowhere to plot it — only the 3D visualization below is skipped.
    const mappable = lat != null && lon != null;
    onHudEvent({ country, severity, mappable });

    // No real point to draw for a private/loopback origin (RFC1918 has
    // no lat/lon) or a public IP the City DB couldn't resolve — the
    // event still counted above, it just isn't mappable.
    if (!mappable) return;

    if (activeArcs.length >= MAX_CONCURRENT_ARCS) return; // burst safety — see module docstring

    const a = latLonToVector3(lat, lon, R);
    const colorHex = severityHex(severity);
    const colorCss = sevColors[severity] || sevColors.low;

    const originMarker = new THREE.Sprite(new THREE.SpriteMaterial({ map: dotTex, color: colorHex, transparent: true, opacity: 1, depthWrite: false, blending: THREE.AdditiveBlending }));
    originMarker.position.copy(a.clone().normalize().multiplyScalar(R * 1.01));
    originMarker.scale.set(0.24, 0.24, 1);
    globe.add(originMarker);

    const labelText = `${flagEmoji(country)} ${country || "??"}${city ? " · " + city : ""}`;
    const label = makeOriginLabel(labelText, colorCss);
    label.position.copy(a.clone().normalize().multiplyScalar(R * 1.16));
    globe.add(label);

    if (destPos) {
      const b = destPos;
      const dist = a.distanceTo(b);
      const height = 0.9 + (dist / (R * 2)) * 1.6;
      const SEGMENTS = 64;
      const pts = [];
      for (let i = 0; i <= SEGMENTS; i++) pts.push(arcPoint(a, b, i / SEGMENTS, height));
      const geo = new THREE.BufferGeometry().setFromPoints(pts);
      const mat = new THREE.LineBasicMaterial({ color: colorHex, transparent: true, opacity: 0, blending: THREE.AdditiveBlending });
      const line = new THREE.Line(geo, mat);
      globe.add(line);

      const comet = new THREE.Sprite(new THREE.SpriteMaterial({ map: dotTex, color: colorHex, transparent: true, opacity: reducedMotion ? 0 : 1, depthWrite: false, blending: THREE.AdditiveBlending }));
      comet.scale.set(0.2, 0.2, 1);
      comet.position.copy(a);
      globe.add(comet);

      const travelMs = reducedMotion ? 1 : 950 + (dist / (R * 2)) * 900;
      const now = performance.now();
      activeArcs.push({
        line, comet, points: pts, start: now, travelMs, hasArc: true,
        lingerMs: 3200, removeAt: now + travelMs + 3200,
        label, labelHoldMs: travelMs + 900, originMarker,
      });
      setTimeout(() => spawnRing(b), travelMs);
    } else {
      // no destination yet — origin marker + label still get their own
      // lifecycle so they fade like a normal event instead of sticking
      // around forever
      const travelMs = reducedMotion ? 1 : 1200;
      const now = performance.now();
      activeArcs.push({
        line: null, comet: null, points: null, start: now, travelMs, hasArc: false,
        lingerMs: 1200, removeAt: now + travelMs + 1200,
        label, labelHoldMs: travelMs + 400, originMarker,
      });
    }
  }

  // ------------------------------------------------------- HUD wiring
  const hud = {
    rate: rootEl.querySelector('[data-tg="rate"]'),
    total: rootEl.querySelector('[data-tg="total"]'),
    feedList: rootEl.querySelector('[data-tg="feed-list"]'),
    feedCount: rootEl.querySelector('[data-tg="feed-count"]'),
    vectorList: rootEl.querySelector('[data-tg="vector-list"]'),
    sevMix: rootEl.querySelector('[data-tg="sev-mix"]'),
    spark: rootEl.querySelector('[data-tg="spark"]'),
    clock: rootEl.querySelector('[data-tg="clock"]'),
    btnRotate: rootEl.querySelector('[data-tg="btn-rotate"]'),
    btnPause: rootEl.querySelector('[data-tg="btn-pause"]'),
    unmappedRow: rootEl.querySelector('[data-tg="unmapped-row"]'),
    unmapped: rootEl.querySelector('[data-tg="unmapped"]'),
  };
  const sparkCtx = hud.spark ? hud.spark.getContext("2d") : null;

  let totalBlocked = 0;
  let unmappedCount = 0; // private/loopback origin, or no City DB fix — counted, never plotted
  let rateWindow = [];
  const countryTally = {};
  const sevTally = { critical: 0, high: 0, medium: 0, low: 0 };
  const sparkHistory = new Array(40).fill(0);

  function onHudEvent({ country, severity, mappable }) {
    totalBlocked++;
    rateWindow.push(performance.now());
    const key = country || "??";
    countryTally[key] = (countryTally[key] || 0) + 1;
    const sevKey = sevTally[severity] !== undefined ? severity : "low";
    sevTally[sevKey]++;

    if (!mappable) {
      unmappedCount++;
      if (hud.unmapped) hud.unmapped.textContent = unmappedCount.toLocaleString();
      if (hud.unmappedRow) hud.unmappedRow.hidden = false;
    }

    if (hud.total) hud.total.textContent = totalBlocked.toLocaleString();
    if (hud.feedCount) hud.feedCount.textContent = `${totalBlocked.toLocaleString()} events`;
    pushFeedRow(country, severity);
    refreshVectorList();
    refreshSevMix();
  }

  function pushFeedRow(country, severity) {
    if (!hud.feedList) return;
    const row = document.createElement("div");
    row.className = "tg-feed-row";
    row.innerHTML =
      `<span class="tg-dot" style="background:${sevColors[severity] || sevColors.low}"></span>` +
      `<span class="tg-origin">${flagEmoji(country)} ${country || "??"}</span>` +
      `<span class="tg-vec">Blocked request</span>` +
      `<span class="tg-ago">now</span>`;
    hud.feedList.insertBefore(row, hud.feedList.firstChild);
    while (hud.feedList.children.length > 40) hud.feedList.removeChild(hud.feedList.lastChild);
  }

  function refreshVectorList() {
    if (!hud.vectorList) return;
    const entries = Object.entries(countryTally)
      .map(([cc, n]) => ({ cc, n }))
      .sort((a, b) => b.n - a.n)
      .slice(0, 6);
    const max = entries.length ? entries[0].n : 1;
    hud.vectorList.innerHTML = entries.map(({ cc, n }) => {
      const pct = Math.round((n / max) * 100);
      return `<div class="tg-vector-row"><span class="tg-cc">${flagEmoji(cc)}</span>` +
        `<span class="tg-vname">${cc}</span>` +
        `<span class="tg-bar-track"><span class="tg-bar-fill" style="width:${pct}%"></span></span>` +
        `<span class="tg-n">${n}</span></div>`;
    }).join("");
  }

  function refreshSevMix() {
    if (!hud.sevMix) return;
    const total = sevTally.critical + sevTally.high + sevTally.medium + sevTally.low || 1;
    hud.sevMix.innerHTML = ["critical", "high", "medium", "low"].map((k) => {
      const pct = Math.round((sevTally[k] / total) * 100);
      return `<div class="tg-sev-row"><span class="tg-sev-chip" style="background:${sevColors[k]}"></span>` +
        `<span class="tg-label" style="text-transform:capitalize">${k}</span>` +
        `<span class="tg-pct">${pct}%</span></div>`;
    }).join("");
  }

  function drawSpark() {
    if (!sparkCtx) return;
    const w = hud.spark.width, h = hud.spark.height;
    sparkCtx.clearRect(0, 0, w, h);
    const max = Math.max(...sparkHistory, 3);
    const step = w / (sparkHistory.length - 1);
    sparkCtx.beginPath();
    sparkHistory.forEach((v, i) => {
      const x = i * step, y = h - (v / max) * (h - 6) - 2;
      if (i === 0) sparkCtx.moveTo(x, y); else sparkCtx.lineTo(x, y);
    });
    sparkCtx.strokeStyle = "#22d3ee";
    sparkCtx.lineWidth = 1.6;
    sparkCtx.stroke();
    const lastX = (sparkHistory.length - 1) * step;
    const lastY = h - (sparkHistory[sparkHistory.length - 1] / max) * (h - 6) - 2;
    sparkCtx.lineTo(lastX, h); sparkCtx.lineTo(0, h); sparkCtx.closePath();
    const fill = sparkCtx.createLinearGradient(0, 0, 0, h);
    fill.addColorStop(0, "rgba(34,211,238,0.22)");
    fill.addColorStop(1, "rgba(34,211,238,0)");
    sparkCtx.fillStyle = fill;
    sparkCtx.fill();
    sparkCtx.beginPath();
    sparkCtx.arc(lastX, lastY, 2.2, 0, Math.PI * 2);
    sparkCtx.fillStyle = "#22d3ee";
    sparkCtx.fill();
  }

  // ------------------------------------------------------- controls
  let autoRotate = !reducedMotion;
  let paused = false;
  if (hud.btnRotate) {
    hud.btnRotate.dataset.on = String(autoRotate);
    hud.btnRotate.addEventListener("click", () => {
      autoRotate = !autoRotate;
      hud.btnRotate.dataset.on = String(autoRotate);
    });
  }
  if (hud.btnPause) {
    hud.btnPause.addEventListener("click", () => {
      paused = !paused;
      hud.btnPause.dataset.on = String(paused);
      hud.btnPause.textContent = paused ? "▶ RESUME FEED" : "❚❚ PAUSE FEED";
    });
  }

  let dragging = false, lastX = 0, lastY = 0;
  function onPointerDown(e) { dragging = true; lastX = e.clientX; lastY = e.clientY; }
  function onPointerUp() { dragging = false; }
  function onPointerMove(e) {
    if (!dragging) return;
    const dx = e.clientX - lastX, dy = e.clientY - lastY;
    lastX = e.clientX; lastY = e.clientY;
    globe.rotation.y += dx * 0.005;
    globe.rotation.x = THREE.MathUtils.clamp(globe.rotation.x + dy * 0.005, -0.9, 0.9);
  }
  canvas.addEventListener("pointerdown", onPointerDown);
  window.addEventListener("pointerup", onPointerUp);
  window.addEventListener("pointermove", onPointerMove);

  function tickClock() {
    if (!hud.clock) return;
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    hud.clock.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
  }
  tickClock();
  const clockInterval = setInterval(tickClock, 1000);

  // ------------------------------------------------------- main loop
  const introStart = performance.now();
  const introMs = reducedMotion ? 0 : 1600;
  let lastSparkUpdate = performance.now();
  let rafId = null;
  let disposed = false;

  function animate(now) {
    if (disposed) return;
    rafId = requestAnimationFrame(animate);

    if (now - introStart < introMs) {
      const t = (now - introStart) / introMs;
      const ease = 1 - Math.pow(1 - t, 3);
      camera.position.z = (REST_Z + 9) - ease * 9;
      camera.position.y = 1.8 + (1 - ease) * 3;
    }

    if (autoRotate) globe.rotation.y += 0.0011;

    if (destPos) {
      if (reducedMotion) {
        beacon.material.opacity = 0.9;
        beaconRing.material.opacity = 0;
      } else {
        beacon.material.opacity = 0.9 + Math.sin(now * 0.0025) * 0.18;
        const ringScale = 1 + ((now * 0.0006) % 1) * 5;
        beaconRing.scale.set(ringScale, ringScale, 1);
        beaconRing.material.opacity = Math.max(0, 0.55 * (1 - ((now * 0.0006) % 1)));
      }
    }

    for (let i = activeArcs.length - 1; i >= 0; i--) {
      const arc = activeArcs[i];
      const elapsed = now - arc.start;

      if (arc.hasArc) {
        if (elapsed < arc.travelMs) {
          const t = elapsed / arc.travelMs;
          arc.line.material.opacity = Math.min(0.55, t * 1.8);
          const idx = Math.min(arc.points.length - 1, Math.floor(t * arc.points.length));
          arc.comet.position.copy(arc.points[idx]);
          arc.comet.material.opacity = reducedMotion ? 0 : 1;
        } else {
          const lingerT = (elapsed - arc.travelMs) / arc.lingerMs;
          arc.comet.material.opacity = 0;
          arc.line.material.opacity = Math.max(0, 0.42 * (1 - lingerT));
        }
      }

      arc.originMarker.material.opacity = Math.max(0, 1 - (elapsed / (arc.travelMs + arc.lingerMs)));

      const labelT = elapsed / arc.labelHoldMs;
      if (reducedMotion) {
        arc.label.material.opacity = elapsed < arc.labelHoldMs ? 0.95 : 0;
      } else if (labelT < 0.08) {
        arc.label.material.opacity = Math.min(0.95, (labelT / 0.08) * 0.95);
      } else if (labelT < 1) {
        arc.label.material.opacity = 0.95;
      } else {
        arc.label.material.opacity = Math.max(0, 0.95 * (1 - (labelT - 1) * 4));
      }

      if (now > arc.removeAt) {
        globe.remove(arc.originMarker); arc.originMarker.material.dispose();
        globe.remove(arc.label); arc.label.material.map.dispose(); arc.label.material.dispose();
        if (arc.hasArc) {
          globe.remove(arc.line); globe.remove(arc.comet);
          arc.line.geometry.dispose(); arc.line.material.dispose(); arc.comet.material.dispose();
        }
        activeArcs.splice(i, 1);
      }
    }

    for (let j = activeRings.length - 1; j >= 0; j--) {
      const rr = activeRings[j];
      const rt = (now - rr.start) / rr.duration;
      if (rt >= 1) {
        globe.remove(rr.mesh); rr.mesh.geometry.dispose(); rr.mesh.material.dispose();
        activeRings.splice(j, 1);
        continue;
      }
      const s = 1 + rt * 26;
      rr.mesh.scale.set(s, s, 1);
      rr.mesh.material.opacity = 0.75 * (1 - rt);
    }

    if (!reducedMotion) starPoints.rotation.y += 0.00006;

    if (now - lastSparkUpdate > 300) {
      lastSparkUpdate = now;
      const cutoff = now - 10000;
      rateWindow = rateWindow.filter((ts) => ts > cutoff);
      const perSec = rateWindow.length / 10;
      if (hud.rate) hud.rate.textContent = perSec.toFixed(1);
      sparkHistory.shift();
      sparkHistory.push(perSec);
      drawSpark();
    }

    renderer.render(scene, camera);
  }
  rafId = requestAnimationFrame(animate);

  refreshVectorList();
  refreshSevMix();
  drawSpark();

  function dispose() {
    disposed = true;
    if (rafId) cancelAnimationFrame(rafId);
    clearInterval(clockInterval);
    resizeObserver.disconnect();
    canvas.removeEventListener("pointerdown", onPointerDown);
    window.removeEventListener("pointerup", onPointerUp);
    window.removeEventListener("pointermove", onPointerMove);
    activeArcs.forEach((arc) => {
      globe.remove(arc.originMarker); arc.originMarker.material.dispose();
      globe.remove(arc.label); arc.label.material.map.dispose(); arc.label.material.dispose();
      if (arc.hasArc) {
        globe.remove(arc.line); globe.remove(arc.comet);
        arc.line.geometry.dispose(); arc.line.material.dispose(); arc.comet.material.dispose();
      }
    });
    activeRings.forEach((rr) => { globe.remove(rr.mesh); rr.mesh.geometry.dispose(); rr.mesh.material.dispose(); });
    globeMesh.geometry.dispose(); globeMesh.material.dispose(); surfaceTex.dispose();
    glowSprite.material.dispose(); glowTex.dispose();
    dotTex.dispose();
    starPoints.geometry.dispose(); starPoints.material.dispose();
    beacon.material.dispose(); beaconRing.geometry.dispose(); beaconRing.material.dispose();
    renderer.dispose();
  }

  return { fireAttack, setDestination, dispose };
}
