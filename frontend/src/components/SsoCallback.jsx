import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, Activity, AlertTriangle } from 'lucide-react';

/**
 * SIEM SSO landing page (/auth/sso). The SIEM redirects here with the
 * signed exchange JWT in the URL *fragment* (`#token=...`) rather than a
 * query param specifically so it's never sent to any server — browsers
 * never transmit the fragment, so it can't leak into access logs, proxy
 * logs, or a Referer header. We read it client-side, strip it from the
 * address bar immediately, then POST it to the backend to redeem it for
 * a real session.
 */
const SsoCallback = ({ setAuth, onLoginSuccess }) => {
  const [status, setStatus] = useState('exchanging'); // 'exchanging' | 'error'
  const [error, setError] = useState('');
  const ranRef = useRef(false);

  const API_BASE = `${window.location.protocol}//${window.location.host}/api`;

  useEffect(() => {
    // Effects can double-fire in dev (StrictMode); the token is single-use
    // server-side anyway, but avoid burning it on a harmless double-call.
    if (ranRef.current) return;
    ranRef.current = true;

    const hash = window.location.hash; // e.g. "#token=eyJ..."
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const token = params.get('token');

    // Strip the token from the address bar right away, regardless of what
    // happens next — it must never sit in browser history.
    window.history.replaceState({}, '', '/auth/sso');

    if (!token) {
      setStatus('error');
      setError('No SSO token was provided.');
      return;
    }

    (async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/sso/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
          credentials: 'include',
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || 'SSO sign-in failed.');
        }

        const data = await res.json().catch(() => ({}));

        // Session cookie is set. Fetch the profile so we have the username
        // too (the exchange response only carries role), same as the
        // password-login path in components/Login.jsx.
        let user = { role: data.role || 'analyst', username: 'user' };
        try {
          const meRes = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' });
          if (meRes.ok) {
            const meData = await meRes.json();
            user = { role: meData.role || user.role, username: meData.username || user.username };
          }
        } catch {
          // Fall back to the exchange response's role.
        }

        window.history.replaceState({ tab: 'overview' }, '', '/dashboard');
        if (onLoginSuccess) onLoginSuccess(user);
        setAuth(true);
      } catch (err) {
        setStatus('error');
        setError(err.message || 'SSO sign-in failed.');
      }
    })();
  }, [API_BASE, onLoginSuccess, setAuth]);

  return (
    <div className="login-container" style={{ alignItems: 'center', justifyContent: 'center', display: 'flex' }}>
      <motion.div
        className="login-card"
        initial={{ opacity: 0, scale: 0.94, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        style={{ maxWidth: '420px', textAlign: 'center', padding: '40px 32px' }}
      >
        <div className="auth-icon" style={{ margin: '0 auto 16px' }}>
          {status === 'error' ? <AlertTriangle size={26} /> : <ShieldCheck size={26} />}
        </div>

        {status === 'exchanging' && (
          <>
            <h2>Signing you in&hellip;</h2>
            <p style={{ marginTop: '8px', color: 'var(--text-secondary)' }}>
              Verifying your SIEM session with CyberSentinel WAF.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', marginTop: '20px' }}>
              <Activity className="animate-spin" size={22} color="var(--accent-color)" />
            </div>
          </>
        )}

        {status === 'error' && (
          <>
            <h2>Single Sign-On Failed</h2>
            <p style={{ marginTop: '8px', color: 'var(--text-secondary)' }}>{error}</p>
            <button
              type="button"
              className="login-btn"
              style={{ marginTop: '20px' }}
              onClick={() => { window.location.href = '/'; }}
            >
              Go to Login
            </button>
          </>
        )}
      </motion.div>
    </div>
  );
};

export default SsoCallback;
