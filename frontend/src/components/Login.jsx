import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, Activity, Eye, EyeOff, Server, ShieldCheck, Zap, Brain, Globe } from 'lucide-react';

/* ─── Animated Particle Network Canvas ──────────────────── */
function ParticleCanvas() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    let W = canvas.width = canvas.offsetWidth;
    let H = canvas.height = canvas.offsetHeight;

    const PARTICLE_COUNT = 60;
    const CONNECTION_DIST = 140;

    const particles = Array.from({ length: PARTICLE_COUNT }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 2 + 1,
      pulse: Math.random() * Math.PI * 2,
      color: Math.random() > 0.7
        ? 'rgba(0,255,157,'
        : Math.random() > 0.4
          ? 'rgba(20,184,166,'
          : 'rgba(191,90,242,',
    }));

    function draw() {
      ctx.clearRect(0, 0, W, H);

      // Update positions
      particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        p.pulse += 0.02;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      });

      // Draw connections
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < CONNECTION_DIST) {
            const alpha = (1 - dist / CONNECTION_DIST) * 0.35;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(20,184,166,${alpha})`;
            ctx.lineWidth = 0.6;
            ctx.stroke();
          }
        }
      }

      // Draw particles
      particles.forEach(p => {
        const pulseFactor = 0.8 + Math.sin(p.pulse) * 0.3;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * pulseFactor, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color}${0.7 + Math.sin(p.pulse) * 0.3})`;
        ctx.fill();

        // Glow
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * pulseFactor * 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color}0.08)`;
        ctx.fill();
      });

      animId = requestAnimationFrame(draw);
    }

    const onResize = () => {
      W = canvas.width = canvas.offsetWidth;
      H = canvas.height = canvas.offsetHeight;
    };
    window.addEventListener('resize', onResize);
    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        zIndex: 2,
        pointerEvents: 'none',
      }}
    />
  );
}

/* ─── Typing Animation Text ─────────────────────────────── */
function TypingText({ text, speed = 60 }) {
  const [displayed, setDisplayed] = useState('');
  const [done, setDone] = useState(false);

  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setDisplayed(text.slice(0, i));
      if (i >= text.length) {
        clearInterval(interval);
        setDone(true);
      }
    }, speed);
    return () => clearInterval(interval);
  }, [text, speed]);

  return (
    <span>
      {displayed}
      {!done && (
        <span style={{
          display: 'inline-block',
          width: '2px',
          height: '1em',
          background: 'var(--accent-color)',
          marginLeft: '2px',
          verticalAlign: 'middle',
          animation: 'dangerPulse 0.8s infinite',
          borderRadius: '1px',
        }} />
      )}
    </span>
  );
}

/* ─── Live Threat Counter ───────────────────────────────── */
function ThreatCounter() {
  const [count, setCount] = useState(1_842_390);

  useEffect(() => {
    const interval = setInterval(() => {
      setCount(c => c + Math.floor(Math.random() * 5) + 1);
    }, 800);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      padding: '20px 28px',
      background: 'rgba(255,59,92,0.06)',
      border: '1px solid rgba(255,59,92,0.18)',
      borderRadius: '12px',
      marginBottom: '28px',
    }}>
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '38px',
        fontWeight: 700,
        color: 'var(--danger-color)',
        textShadow: '0 0 20px rgba(255,59,92,0.5)',
        letterSpacing: '-1px',
        lineHeight: 1,
      }}>
        {count.toLocaleString()}
      </div>
      <div style={{
        fontSize: '12px',
        color: 'rgba(255,59,92,0.7)',
        fontFamily: 'var(--font-mono)',
        textTransform: 'uppercase',
        letterSpacing: '1.5px',
        marginTop: '6px',
      }}>
        ▲ Global Threats Neutralized Today
      </div>
    </div>
  );
}

const Login = ({ setAuth, onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showMfa, setShowMfa] = useState(false);
  const [otpCode, setOtpCode] = useState('');

  const API_BASE = `${window.location.protocol}//${window.location.host}/api`;

  const completeLogin = async () => {
    // Auth cookie is now set. Immediately fetch the user profile so we
    // can pass the role to the parent before it renders — this prevents
    // the Settings tab from being absent on first login.
    let user = { role: 'analyst', username };
    try {
      const meRes = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' });
      if (meRes.ok) {
        const meData = await meRes.json();
        user = { role: meData.role || 'analyst', username: meData.username || username };
      }
    } catch {
      // Fall back to username from form if /me fails
    }

    // Notify parent with the user data BEFORE flipping isAuthenticated,
    // so userRole state is populated in the same render cycle.
    if (onLoginSuccess) onLoginSuccess(user);
    setAuth(true);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (showMfa) {
        // Step 2: exchange the pending-MFA session for a real one.
        const response = await fetch(`${API_BASE}/auth/login/mfa`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: otpCode }),
          credentials: 'include'
        });
        if (!response.ok) {
          throw new Error('Invalid or expired OTP code');
        }
        await completeLogin();
        return;
      }

      // Step 1: username + password.
      const payload = { username, password };
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(payload),
        credentials: 'include'
      });

      if (!response.ok) {
        throw new Error('Invalid credentials');
      }

      const data = await response.json().catch(() => ({}));
      if (data.mfa_required) {
        setShowMfa(true);
        return;
      }

      await completeLogin();
    } catch (err) {
      setError(err.message || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const features = [
    { icon: Activity, color: 'blue', title: 'Real-Time Monitoring', desc: 'Live attack detection & tracking' },
    { icon: Brain, color: 'purple', title: 'ML Threat Engine', desc: 'XGBoost + Isolation Forest' },
    { icon: ShieldCheck, color: 'green', title: 'OWASP CRS v4', desc: 'Industry-standard rule set' },
    { icon: Globe, color: 'orange', title: 'AbuseIPDB Intelligence', desc: 'Global IP reputation feed' },
  ];

  const systemStatus = [
    { label: 'WAF Engine', color: 'var(--success-color)' },
    { label: 'CyberSentinel Engine', color: 'var(--success-color)' },
    { label: 'ML Inference', color: 'var(--accent-color)' },
  ];

  return (
    <div className="login-container">

      <div className="login-panels">
        {/* ── Left Showcase Panel ─────────────────────────── */}
        <div className="login-showcase">
          {/* Animated backgrounds */}
          <div className="cyber-grid" />
          <div className="glow-sphere sphere-1" />
          <div className="glow-sphere sphere-2" />
          <div className="glow-sphere sphere-3" />
          <ParticleCanvas />

          <div className="showcase-content">
            <motion.div
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7 }}
            >
              {/* Logo */}
              <div className="login-brand" style={{ marginBottom: '16px', display: 'flex', justifyContent: 'center' }}>
                <motion.img
                  src="/Cybersentinel.png"
                  alt="CyberSentinel"
                  className="brand-icon-large"
                  style={{ maxHeight: '120px', maxWidth: '400px', objectFit: 'contain' }}
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ duration: 0.6, delay: 0.1 }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', margin: '0 auto 32px' }}>
                <div style={{ 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '10px',
                  padding: '8px 18px', 
                  background: 'var(--accent-bg)', 
                  border: '1px solid var(--accent-border)', 
                  borderRadius: '30px',
                  boxShadow: '0 4px 20px var(--accent-glow)',
                  color: 'var(--accent-color)',
                  textTransform: 'uppercase',
                  letterSpacing: '1.5px',
                  fontSize: '12px',
                  fontWeight: 600,
                  fontFamily: 'var(--font-mono)'
                }}>
                  <ShieldCheck size={16} />
                  <span>Web Application Firewall</span>
                </div>
              </div>
            </motion.div>

            {/* Live counter */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              <ThreatCounter />
            </motion.div>

            {/* Feature Grid */}
            <div className="feature-grid">
              {features.map((f, i) => {
                const Icon = f.icon;
                return (
                  <motion.div
                    key={f.title}
                    className="feature-card"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.35 + i * 0.08 }}
                  >
                    <Icon size={22} className={`feature-icon ${f.color}`} />
                    <div>
                      <h3>{f.title}</h3>
                      <p>{f.desc}</p>
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {/* System Status */}
            <motion.div
              className="system-status-panel"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7 }}
            >
              {systemStatus.map(s => (
                <div key={s.label} className="status-item">
                  <div style={{
                    width: '8px', height: '8px',
                    borderRadius: '50%',
                    backgroundColor: s.color,
                    boxShadow: `0 0 8px ${s.color}`,
                    animation: 'pulseGlow 1.8s ease-in-out infinite',
                  }} />
                  {s.label}
                </div>
              ))}
            </motion.div>
          </div>
        </div>

        {/* ── Right Login Panel ────────────────────────────── */}
        <div className="login-form-wrapper">
          <motion.div
            className="login-card"
            initial={{ opacity: 0, scale: 0.94, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.2 }}
          >
            <div className="login-card-header">
              <div className="auth-icon">
                <Lock size={26} />
              </div>
              <h2>
                <TypingText text="Secure Access" speed={65} />
              </h2>
              <p>Authenticate to access the SOC dashboard</p>
            </div>

            <AnimatePresence>
              {error && (
                <motion.div
                  className="login-error"
                  initial={{ opacity: 0, height: 0, marginBottom: 0 }}
                  animate={{ opacity: 1, height: 'auto', marginBottom: 20 }}
                  exit={{ opacity: 0, height: 0, marginBottom: 0 }}
                >
                  ⚠ {error}
                </motion.div>
              )}
            </AnimatePresence>

            <form onSubmit={handleLogin} className="login-form">
              {!showMfa ? (
                <>
                  <div className="form-group">
                    <label htmlFor="username">Admin Identity</label>
                    <div className="input-with-icon">
                      <Server size={16} className="input-icon" />
                      <input
                        id="username"
                        type="text"
                        placeholder="Enter username"
                        value={username}
                        onChange={e => setUsername(e.target.value)}
                        autoComplete="username"
                        required
                      />
                    </div>
                  </div>

                  <div className="form-group">
                    <label htmlFor="password">Authentication Key</label>
                    <div className="input-with-icon">
                      <Lock size={16} className="input-icon" />
                      <input
                        id="password"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="Enter password"
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        autoComplete="current-password"
                        required
                      />
                      <button
                        type="button"
                        className="password-toggle"
                        onClick={() => setShowPassword(s => !s)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                <div className="form-group">
                  <label htmlFor="otpCode">Google Authenticator OTP Code</label>
                  <div className="input-with-icon">
                    <ShieldCheck size={16} className="input-icon" color="var(--accent-color)" />
                    <input
                      id="otpCode"
                      type="text"
                      maxLength={6}
                      placeholder="Enter 6-digit OTP code"
                      value={otpCode}
                      onChange={e => setOtpCode(e.target.value)}
                      autoComplete="one-time-code"
                      required
                      autoFocus
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                className={`login-btn ${loading ? 'loading' : ''}`}
                disabled={loading}
                id="login-submit-btn"
              >
                {loading ? (
                  <>
                    <Activity className="animate-spin" size={17} />
                    Authenticating...
                  </>
                ) : (
                  <>
                    <Zap size={17} />
                    {showMfa ? "Verify OTP & Access" : "Initialize Session"}
                  </>
                )}
              </button>
              {showMfa && (
                <button
                  type="button"
                  className="login-btn"
                  style={{ background: 'var(--surface-hover)', marginTop: '8px', border: '1px solid var(--border-strong)' }}
                  onClick={() => {
                    setShowMfa(false);
                    setOtpCode('');
                    setError('');
                  }}
                >
                  Cancel MFA Check
                </button>
              )}
            </form>

            <div className="login-footer">
              <p>Unauthorized access is strictly prohibited and monitored.</p>
            </div>
          </motion.div>
        </div>
      </div> {/* end .login-panels */}

      {/* Footer Bar */}
      <div className="login-footer-bar">
        <div className="footer-left">
          <img src="/Virtual_logo.png" alt="Virtual Galaxy" className="footer-logo" />
          <div className="footer-divider" />
          <span>Information Technology Services Management</span>
        </div>
        <div className="footer-center">
          <span>© 2026 Virtual Galaxy Ltd. All Rights Reserved.</span>
        </div>
        <div className="footer-right">
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--accent-color)' }}>
            v2.0.0-2026
          </span>
          <div className="footer-divider" />
          <a href="#support">Support</a>
          <div className="footer-divider" />
          <a href="#privacy">Privacy Policy</a>
        </div>
      </div>
    </div>
  );
};

export default Login;
