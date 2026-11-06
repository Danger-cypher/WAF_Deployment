import { useState, useEffect, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Lock, Activity, Eye, EyeOff, ShieldCheck, Zap,
  AlertTriangle, KeyRound, Sun, Moon, HelpCircle,
  ExternalLink, X, ShieldAlert, User, Server
} from 'lucide-react';
import { ThemeContext } from '../context/theme-context.js';

export default function Login({ setAuth, onLoginSuccess }) {
  const [username, setUsername] = useState(() => {
    try {
      return localStorage.getItem('cybersentinel_remember_username') || '';
    } catch {
      return '';
    }
  });
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showMfa, setShowMfa] = useState(false);
  const [otpCode, setOtpCode] = useState('');
  const [rememberMe, setRememberMe] = useState(() => {
    try {
      return localStorage.getItem('cybersentinel_remember_username') !== null;
    } catch {
      return false;
    }
  });
  const [capsLockActive, setCapsLockActive] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [showRequestAccessModal, setShowRequestAccessModal] = useState(false);

  // Theme integration with safe fallback
  const themeCtx = useContext(ThemeContext);
  const isLight = themeCtx?.resolvedTheme === 'light';
  const toggleTheme = () => {
    if (themeCtx?.setTheme) {
      themeCtx.setTheme(isLight ? 'dark' : 'light');
    }
  };

  const API_BASE = `${window.location.protocol}//${window.location.host}/api`;

  // Key modifier listener for Caps Lock detection
  const handleKeyCheck = (e) => {
    if (e.getModifierState) {
      setCapsLockActive(e.getModifierState('CapsLock'));
    }
  };

  // Keyboard Escape listener to dismiss modals
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setShowForgotModal(false);
        setShowRequestAccessModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const completeLogin = async () => {
    // Remember username preference
    try {
      if (rememberMe && username.trim()) {
        localStorage.setItem('cybersentinel_remember_username', username.trim());
      } else {
        localStorage.removeItem('cybersentinel_remember_username');
      }
    } catch {
      // Storage unavailable
    }

    let user = { role: 'analyst', username };
    try {
      const meRes = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' });
      if (meRes.ok) {
        const meData = await meRes.json();
        user = { role: meData.role || 'analyst', username: meData.username || username };
      }
    } catch {
      // Fallback to form username if /me fails
    }

    if (onLoginSuccess) onLoginSuccess(user);
    setAuth(true);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (showMfa) {
        const response = await fetch(`${API_BASE}/auth/login/mfa`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: otpCode.trim() }),
          credentials: 'include'
        });

        if (!response.ok) {
          let detail;
          try { detail = (await response.json())?.detail; } catch { /* no JSON body */ }
          throw new Error(detail || 'Invalid or expired OTP code');
        }

        await completeLogin();
        return;
      }

      // Primary Credentials step
      const payload = { username: username.trim(), password };
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(payload),
        credentials: 'include'
      });

      if (!response.ok) {
        let detail;
        try { detail = (await response.json())?.detail; } catch { /* no JSON body */ }
        throw new Error(detail || 'Invalid credentials');
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

  return (
    <div className="login-container" onKeyDown={handleKeyCheck} onKeyUp={handleKeyCheck}>
      {/* ── Ambient Background Visual (Calm, Constant, Low Context) ─ */}
      <div className="login-ambient-backdrop" aria-hidden="true">
        <div className="ambient-glow glow-primary" />
        <div className="ambient-glow glow-secondary" />
        <div className="ambient-grid-overlay" />
      </div>

      {/* ── Top Bar Controls ──────────────────────────────────── */}
      <header className="login-top-bar">
        <div className="login-top-brand">
          <ShieldAlert size={20} className="login-brand-shield-icon" />
          <span className="login-brand-text">CYBERSENTINEL</span>
          <span className="login-brand-subbadge">WAF v2.4</span>
        </div>

        <div className="login-top-actions">
          <div className="login-status-indicator">
            <span className="status-dot-pulse" />
            <span className="status-label">Engine Active</span>
          </div>

          <button
            type="button"
            className="login-theme-toggle-btn"
            onClick={toggleTheme}
            aria-label={isLight ? 'Switch to Dark Console' : 'Switch to Matte Slate'}
            title={isLight ? 'Switch to Dark Console' : 'Switch to Matte Slate'}
          >
            {isLight ? <Moon size={16} /> : <Sun size={16} />}
          </button>
        </div>
      </header>

      {/* ── Main Viewport Center Stage ────────────────────────── */}
      <main className="login-main-stage">
        <div className="login-card-wrapper">
          <div className="login-form-card">
            
            <div className="login-card-header">
              <div className="login-badge-pill">
                <ShieldCheck size={14} />
                <span>Zero-Trust Gateway</span>
              </div>
              <h1 id="login-heading" className="login-title">
                {showMfa ? 'Two-Factor Verification' : 'Enterprise Access'}
              </h1>
              <p className="login-subtitle">
                {showMfa
                  ? 'Enter the 6-digit verification code from your authenticator app.'
                  : 'Authenticate to access the Security Operations Center dashboard.'}
              </p>
            </div>

            {/* Error Notification Banner */}
            <AnimatePresence>
              {error && (
                <motion.div
                  className="login-error-banner"
                  role="alert"
                  aria-live="polite"
                  initial={{ opacity: 0, y: -8, height: 0 }}
                  animate={{ opacity: 1, y: 0, height: 'auto' }}
                  exit={{ opacity: 0, y: -8, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <AlertTriangle size={16} className="error-icon" />
                  <span>{error}</span>
                </motion.div>
              )}
            </AnimatePresence>

            <form onSubmit={handleLogin} className="login-form" noValidate>
              {!showMfa ? (
                <>
                  {/* Username Field */}
                  <div className="login-field-group">
                    <label htmlFor="username" className="login-field-label">
                      Username or Corporate Email
                    </label>
                    <div className="login-input-wrapper">
                      <User size={16} className="login-field-icon" aria-hidden="true" />
                      <input
                        id="username"
                        type="text"
                        placeholder="Enter username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        autoComplete="username"
                        required
                        className="login-input"
                        disabled={loading}
                      />
                    </div>
                  </div>

                  {/* Password Field */}
                  <div className="login-field-group">
                    <div className="login-label-row">
                      <label htmlFor="password" className="login-field-label">
                        Password
                      </label>
                      {capsLockActive && (
                        <span className="caps-lock-warning" role="status">
                          <AlertTriangle size={12} /> Caps Lock ON
                        </span>
                      )}
                    </div>
                    <div className="login-input-wrapper">
                      <Lock size={16} className="login-field-icon" aria-hidden="true" />
                      <input
                        id="password"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="Enter password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="current-password"
                        required
                        className="login-input password-input"
                        disabled={loading}
                      />
                      <button
                        type="button"
                        className="password-toggle-btn"
                        onClick={() => setShowPassword((s) => !s)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        tabIndex={0}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  {/* Options Row: Remember Me & Forgot Password */}
                  <div className="login-utilities-row">
                    <label className="remember-checkbox-label">
                      <input
                        type="checkbox"
                        checked={rememberMe}
                        onChange={(e) => setRememberMe(e.target.checked)}
                        className="remember-checkbox-input"
                      />
                      <span>Remember username</span>
                    </label>

                    <button
                      type="button"
                      className="text-link-button"
                      onClick={() => setShowForgotModal(true)}
                    >
                      Forgot password?
                    </button>
                  </div>
                </>
              ) : (
                /* ── MFA OTP Step ──────────────────────────────── */
                <div className="login-field-group mfa-field-group">
                  <label htmlFor="otpCode" className="login-field-label">
                    Authenticator 6-Digit Code
                  </label>
                  <div className="login-input-wrapper mfa-input-wrapper">
                    <KeyRound size={16} className="login-field-icon" color="var(--accent-color)" aria-hidden="true" />
                    <input
                      id="otpCode"
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={6}
                      placeholder="Enter 6-digit OTP code"
                      value={otpCode}
                      onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                      autoComplete="one-time-code"
                      required
                      autoFocus
                      className="login-input mfa-input"
                      disabled={loading}
                    />
                  </div>
                  <span className="mfa-hint-text">
                    Supported: Google Authenticator, YubiKey Authenticator, 1Password, Duo.
                  </span>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                className={`login-submit-btn ${loading ? 'loading' : ''}`}
                disabled={loading}
                id="login-submit-btn"
                aria-label={showMfa ? 'Verify OTP & Access' : 'Initialize Session'}
              >
                {loading ? (
                  <>
                    <Activity className="animate-spin" size={17} />
                    <span>{showMfa ? 'Verifying Code...' : 'Authenticating...'}</span>
                  </>
                ) : (
                  <>
                    {showMfa ? <ShieldCheck size={17} /> : <Zap size={17} />}
                    <span>{showMfa ? 'Verify OTP & Access' : 'Initialize Session'}</span>
                  </>
                )}
              </button>

              {/* MFA Return Action */}
              {showMfa && (
                <button
                  type="button"
                  className="login-cancel-mfa-btn"
                  onClick={() => {
                    setShowMfa(false);
                    setOtpCode('');
                    setError('');
                  }}
                  disabled={loading}
                >
                  Return to Username & Password
                </button>
              )}
            </form>

            {/* Enterprise SSO Entry Point */}
            {!showMfa && (
              <div className="login-sso-section">
                <div className="login-divider-row">
                  <span className="divider-line" />
                  <span className="divider-text">OR ENTERPRISE IDENTITY</span>
                  <span className="divider-line" />
                </div>

                <a
                  href="/auth/sso"
                  className="login-sso-btn"
                  title="Authenticate via Enterprise Single Sign-On"
                >
                  <KeyRound size={16} />
                  <span>Single Sign-On (IdP / SAML 2.0 / OIDC)</span>
                  <ExternalLink size={14} className="sso-ext-icon" />
                </a>
              </div>
            )}

            {/* Request Access & Footer Note */}
            <div className="login-card-footer">
              <p className="request-access-text">
                Need SOC credentials?{' '}
                <button
                  type="button"
                  className="text-link-button"
                  onClick={() => setShowRequestAccessModal(true)}
                >
                  Request Analyst Access
                </button>
              </p>
              <div className="security-assurance-tag">
                <Lock size={12} />
                <span>TLS 1.3 • FIPS 140-3 Compliant Session Encryption</span>
              </div>
            </div>

          </div>
        </div>
      </main>

      {/* ── Global Footer Bar ─────────────────────────────────── */}
      <footer className="login-footer-bar">
        <div className="footer-left">
          <span>© 2026 Virtual Galaxy Ltd. All Rights Reserved.</span>
        </div>
        <div className="footer-center">
          <span className="confidential-badge">CONFIDENTIAL • AUTHORIZED SOC PERSONNEL ONLY</span>
        </div>
        <div className="footer-right">
          <button type="button" className="footer-link-btn" onClick={() => setShowForgotModal(true)}>
            Help & Recovery
          </button>
          <span className="footer-dot">•</span>
          <a href="#privacy" className="footer-link">Privacy Policy</a>
          <span className="footer-dot">•</span>
          <span className="footer-version-tag">v2.4.0-SEC</span>
        </div>
      </footer>

      {/* ── Modal: Credential Recovery ───────────────────────── */}
      <AnimatePresence>
        {showForgotModal && (
          <div className="login-modal-backdrop" onClick={() => setShowForgotModal(false)} role="presentation">
            <motion.div
              className="login-modal-dialog"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-labelledby="forgot-modal-title"
              aria-modal="true"
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              transition={{ duration: 0.18 }}
            >
              <div className="login-modal-header">
                <div className="modal-title-group">
                  <HelpCircle size={20} color="var(--accent-color)" />
                  <h3 id="forgot-modal-title">Enterprise Credential Recovery</h3>
                </div>
                <button
                  type="button"
                  className="modal-close-btn"
                  onClick={() => setShowForgotModal(false)}
                  aria-label="Close dialog"
                >
                  <X size={18} />
                </button>
              </div>

              <div className="login-modal-body">
                <p>
                  To prevent unauthorized account enumeration and comply with <strong>PCI-DSS v4.0 Req 8.3</strong>, automated self-service email resets are disabled on this management node.
                </p>
                <div className="modal-instructions-box">
                  <strong>Standard Recovery Procedure:</strong>
                  <ol>
                    <li>Contact your designated Security Operations Center (SOC) Lead.</li>
                    <li>Verify your employee identity and workstation hardware fingerprint.</li>
                    <li>An administrator will rotate your credentials via the administrative console.</li>
                  </ol>
                </div>
              </div>

              <div className="login-modal-footer">
                <button
                  type="button"
                  className="login-modal-confirm-btn"
                  onClick={() => setShowForgotModal(false)}
                >
                  Understood
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Modal: Request Access ────────────────────────────── */}
      <AnimatePresence>
        {showRequestAccessModal && (
          <div className="login-modal-backdrop" onClick={() => setShowRequestAccessModal(false)} role="presentation">
            <motion.div
              className="login-modal-dialog"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-labelledby="request-modal-title"
              aria-modal="true"
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              transition={{ duration: 0.18 }}
            >
              <div className="login-modal-header">
                <div className="modal-title-group">
                  <Server size={20} color="var(--success-color)" />
                  <h3 id="request-modal-title">Request Analyst Provisioning</h3>
                </div>
                <button
                  type="button"
                  className="modal-close-btn"
                  onClick={() => setShowRequestAccessModal(false)}
                  aria-label="Close dialog"
                >
                  <X size={18} />
                </button>
              </div>

              <div className="login-modal-body">
                <p>
                  CyberSentinel WAF console provisioning requires Role-Based Access Control (RBAC) authorization from your enterprise SecOps group.
                </p>
                <div className="modal-instructions-box">
                  <strong>Access Tiers Available:</strong>
                  <ul>
                    <li><strong>Security Analyst:</strong> Telemetry inspection, log analysis, false-positive flagging.</li>
                    <li><strong>WAF Administrator:</strong> Core Rule Set tuning, rate limits, virtual patching, TLS configurations.</li>
                  </ul>
                  <p style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text-muted)' }}>
                    Submit an internal ticket to your IT / SecOps administrator referencing node cluster <code>CS-NODE-01</code>.
                  </p>
                </div>
              </div>

              <div className="login-modal-footer">
                <button
                  type="button"
                  className="login-modal-confirm-btn"
                  onClick={() => setShowRequestAccessModal(false)}
                >
                  Close
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}
