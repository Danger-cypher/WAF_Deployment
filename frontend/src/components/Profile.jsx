import { useState, useEffect } from 'react';
import { User, X, ShieldCheck, KeyRound, Save, BellOff, Smartphone, Monitor } from 'lucide-react';
import { useToast } from '../hooks/useToast';
import Toast from './Toast';
import Button from './Button';
import { initialsFor, formatLocalTime } from '../utils/helpers';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import {
  getMyProfile, updateMyProfile, changeMyPassword,
  getMyNotificationPreferences, updateMyNotificationPreferences,
  getMyMfaStatus, setupMyMfa, confirmMyMfa, disableMyMfa,
  getMySessions, revokeMySession,
} from '../services/api';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const EVENT_TYPES = [
  { id: 'attack_detected', label: 'Attack Detected' },
  { id: 'high_threat_score', label: 'High Threat Score' },
  { id: 'ddos_detected', label: 'DDoS Detected' },
  { id: 'rate_limit_exceeded', label: 'Rate Limit Exceeded' },
  { id: 'ml_anomaly', label: 'ML Anomaly' },
  { id: 'geo_violation', label: 'Geo Violation' },
  { id: 'system_error', label: 'System Error' },
  { id: 'health_check_failed', label: 'Health Check Failed' },
  { id: 'config_changed', label: 'Config Changed' },
];

const inputStyle = {
  width: '100%',
  padding: '9px 11px',
  background: 'rgba(0,0,0,0.25)',
  border: '1px solid var(--border-strong)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  fontSize: '13.5px',
  boxSizing: 'border-box',
};

const labelStyle = {
  display: 'block',
  fontSize: '11.5px',
  fontWeight: 600,
  color: 'var(--text-secondary)',
  marginBottom: '5px',
};

const fieldGroupStyle = { display: 'flex', flexDirection: 'column', gap: '12px' };

export default function Profile({ onClose }) {
  useEscapeToClose(onClose, true);
  const [profile, setProfile] = useState(null);
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [prefs, setPrefs] = useState(null);
  const [savingPrefs, setSavingPrefs] = useState(false);
  const [mfaStatus, setMfaStatus] = useState(null);
  const [mfaSetupData, setMfaSetupData] = useState(null);
  const [mfaConfirmCode, setMfaConfirmCode] = useState('');
  const [mfaSavingSetup, setMfaSavingSetup] = useState(false);
  const [mfaSavingConfirm, setMfaSavingConfirm] = useState(false);
  const [showMfaDisableForm, setShowMfaDisableForm] = useState(false);
  const [mfaDisablePassword, setMfaDisablePassword] = useState('');
  const [mfaDisableCode, setMfaDisableCode] = useState('');
  const [mfaSavingDisable, setMfaSavingDisable] = useState(false);
  const [sessions, setSessions] = useState(null);
  const [revokingSessionId, setRevokingSessionId] = useState(null);
  const { toast, showToast } = useToast();

  const loadSessions = () => {
    getMySessions()
      .then(setSessions)
      .catch((err) => showToast('Failed to load sessions: ' + (err.message || 'Unknown error'), 'error'));
  };

  useEffect(() => {
    getMyProfile()
      .then((data) => {
        setProfile(data);
        setDisplayName(data.display_name || '');
        setEmail(data.email || '');
      })
      .catch((err) => showToast('Failed to load profile: ' + (err.message || 'Unknown error'), 'error'));

    getMyNotificationPreferences()
      .then(setPrefs)
      .catch((err) => showToast('Failed to load notification preferences: ' + (err.message || 'Unknown error'), 'error'));

    getMyMfaStatus()
      .then(setMfaStatus)
      .catch((err) => showToast('Failed to load MFA status: ' + (err.message || 'Unknown error'), 'error'));

    loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRevokeSession = async (sessionId, isCurrent) => {
    if (isCurrent && !window.confirm('This is your current session — revoking it will log you out immediately. Continue?')) {
      return;
    }
    setRevokingSessionId(sessionId);
    try {
      await revokeMySession(sessionId);
      showToast(isCurrent ? 'Session revoked — logging out…' : 'Session revoked.');
      if (isCurrent) {
        window.location.reload();
        return;
      }
      loadSessions();
    } catch (err) {
      showToast('Failed to revoke session: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setRevokingSessionId(null);
    }
  };

  const handleSaveProfile = async () => {
    setSavingProfile(true);
    try {
      const updated = await updateMyProfile({ display_name: displayName.trim() || null, email: email.trim() || null });
      setProfile(updated);
      showToast('Profile updated.');
    } catch (err) {
      showToast('Failed to update profile: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setSavingProfile(false);
    }
  };

  const handleChangePassword = async () => {
    if (newPassword.length < 12) {
      showToast('New password must be at least 12 characters.', 'error');
      return;
    }
    setSavingPassword(true);
    try {
      await changeMyPassword(currentPassword, newPassword);
      showToast('Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
    } catch (err) {
      showToast('Failed to change password: ' + (err.message || 'Incorrect current password'), 'error');
    } finally {
      setSavingPassword(false);
    }
  };

  const handleStartMfaSetup = async () => {
    setMfaSavingSetup(true);
    try {
      const data = await setupMyMfa();
      setMfaSetupData(data);
    } catch (err) {
      showToast('Failed to start MFA setup: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setMfaSavingSetup(false);
    }
  };

  const handleCancelMfaSetup = () => {
    setMfaSetupData(null);
    setMfaConfirmCode('');
  };

  const handleConfirmMfaSetup = async () => {
    setMfaSavingConfirm(true);
    try {
      const status = await confirmMyMfa(mfaConfirmCode);
      setMfaStatus(status);
      setMfaSetupData(null);
      setMfaConfirmCode('');
      showToast('Two-factor authentication enabled.');
    } catch {
      showToast('Invalid code — check your authenticator app and try again.', 'error');
    } finally {
      setMfaSavingConfirm(false);
    }
  };

  const handleDisableMfa = async () => {
    // Previously the "Confirm Disable" button was disabled={!mfaDisablePassword
    // || mfaDisableCode.length !== 6} — gated entirely on React state that only
    // updates via onChange. Browser/password-manager autofill on a password
    // field frequently fills the DOM without firing a synthetic onChange, so
    // the field looks filled but the button silently stays disabled forever
    // with zero feedback — indistinguishable from "the feature doesn't work."
    // The button below is no longer hard-disabled; validate here instead, so
    // a click always does SOMETHING visible.
    if (!mfaDisablePassword || mfaDisableCode.length !== 6) {
      showToast('Enter your current password and the 6-digit code to disable 2FA.', 'error');
      return;
    }
    setMfaSavingDisable(true);
    try {
      const status = await disableMyMfa(mfaDisablePassword, mfaDisableCode);
      setMfaStatus(status);
      setShowMfaDisableForm(false);
      setMfaDisablePassword('');
      setMfaDisableCode('');
      showToast('Two-factor authentication disabled.');
    } catch (err) {
      showToast('Failed to disable MFA: ' + (err.message || 'Incorrect password or code'), 'error');
    } finally {
      setMfaSavingDisable(false);
    }
  };

  const togglePref = async (listKey, value) => {
    const current = prefs[listKey];
    const next = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    const optimistic = { ...prefs, [listKey]: next };
    setPrefs(optimistic);
    setSavingPrefs(true);
    try {
      const saved = await updateMyNotificationPreferences(optimistic);
      setPrefs(saved);
    } catch (err) {
      setPrefs(prefs); // revert on failure
      showToast('Failed to update notification preferences: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setSavingPrefs(false);
    }
  };

  const isAdmin = profile?.role === 'admin';

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        role="dialog"
        aria-modal="true"
        aria-labelledby="profile-modal-title"
        style={{ width: '620px', maxWidth: '94vw', maxHeight: '85vh' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="modal-title" id="profile-modal-title">
            <User size={17} style={{ color: 'var(--accent-color)' }} />
            My Profile
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close profile">
            <X size={18} />
          </button>
        </div>

        {profile && (
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Identity */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: '12px',
              padding: '12px 14px', background: 'var(--surface-subtle)', borderRadius: 'var(--radius-lg)',
            }}>
              <div
                aria-hidden="true"
                style={{
                  width: '38px', height: '38px', borderRadius: '50%', flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '13px', fontWeight: 700,
                  background: isAdmin ? 'var(--danger-bg)' : 'var(--accent-bg)',
                  color: isAdmin ? 'var(--danger-color)' : 'var(--accent-color)',
                  border: isAdmin ? '1px solid rgba(244,63,94,0.35)' : '1px solid var(--accent-border)',
                }}
              >
                {initialsFor(profile.username, profile.display_name)}
              </div>
              <ShieldCheck size={14} style={{ color: isAdmin ? 'var(--danger-color)' : 'var(--accent-color)', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                Signed in as <strong style={{ color: 'var(--text-primary)' }}>{profile.username}</strong> · {profile.role}
                {profile.enabled === false ? ' · Disabled' : ''}
              </span>
            </div>

            {/* Account info + Password, side by side on wide viewports */}
            <div className="panel-grid-2">
              <div className="panel-card">
                <div className="panel-card-header">
                  <span className="panel-card-title"><User size={12} /> Account Information</span>
                </div>
                <div style={fieldGroupStyle}>
                  <div>
                    <label htmlFor="profile-display-name" style={labelStyle}>Display Name</label>
                    <input
                      id="profile-display-name" style={inputStyle} value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)} placeholder="Your name"
                    />
                  </div>
                  <div>
                    <label htmlFor="profile-email" style={labelStyle}>Email</label>
                    <input
                      id="profile-email" style={inputStyle} type="email" value={email}
                      onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com"
                    />
                  </div>
                  <Button variant="primary" size="sm" icon={Save} loading={savingProfile} onClick={handleSaveProfile}>
                    {savingProfile ? 'Saving…' : 'Save Profile'}
                  </Button>
                </div>
              </div>

              <div className="panel-card">
                <div className="panel-card-header">
                  <span className="panel-card-title"><KeyRound size={12} /> Password</span>
                </div>
                <div style={fieldGroupStyle}>
                  <div>
                    <label htmlFor="profile-current-password" style={labelStyle}>Current Password</label>
                    <input
                      id="profile-current-password" style={inputStyle} type="password" value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password"
                    />
                  </div>
                  <div>
                    <label htmlFor="profile-new-password" style={labelStyle}>New Password</label>
                    <input
                      id="profile-new-password" style={inputStyle} type="password" value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (min 12 chars, 3+ char types)"
                      onKeyDown={(e) => { if (e.key === 'Enter' && currentPassword && newPassword) handleChangePassword(); }}
                    />
                  </div>
                  <Button
                    variant="primary"
                    size="sm"
                    loading={savingPassword}
                    disabled={!currentPassword || !newPassword}
                    onClick={handleChangePassword}
                  >
                    {savingPassword ? 'Updating…' : 'Update Password'}
                  </Button>
                </div>
              </div>
            </div>

            {/* Two-Factor Authentication */}
            {mfaStatus && (
              <div className="panel-card">
                <div className="panel-card-header">
                  <span className="panel-card-title"><Smartphone size={12} /> Two-Factor Authentication</span>
                  <span style={{
                    fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: 'var(--radius-pill)', textTransform: 'uppercase',
                    background: mfaStatus.enabled ? 'var(--success-bg)' : 'var(--surface-hover)',
                    color: mfaStatus.enabled ? 'var(--success-color)' : 'var(--text-secondary)',
                    border: mfaStatus.enabled ? '1px solid rgba(16,185,129,0.3)' : '1px solid var(--border-color)',
                  }}>
                    {mfaStatus.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>

                {!mfaSetupData && !showMfaDisableForm && (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                    <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {mfaStatus.enabled
                        ? 'Your account requires a one-time code at sign-in.'
                        : 'Add an authenticator app as a second sign-in factor.'}
                    </p>
                    {mfaStatus.enabled ? (
                      <Button variant="danger" size="sm" onClick={() => setShowMfaDisableForm(true)}>
                        Disable
                      </Button>
                    ) : (
                      <Button variant="secondary" size="sm" loading={mfaSavingSetup} onClick={handleStartMfaSetup}>
                        {mfaSavingSetup ? 'Starting…' : 'Enable 2FA'}
                      </Button>
                    )}
                  </div>
                )}

                {mfaSetupData && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      Scan with Google Authenticator, Authy, or any TOTP app:
                    </div>
                    <img
                      src={`data:image/png;base64,${mfaSetupData.qr_code_png_base64}`}
                      alt="MFA QR code"
                      style={{ width: '140px', height: '140px', alignSelf: 'center', background: '#fff', padding: '8px', borderRadius: 'var(--radius-sm)' }}
                    />
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Or enter manually: <code style={{ color: 'var(--accent-color)', wordBreak: 'break-all' }}>{mfaSetupData.secret}</code>
                    </div>
                    <div>
                      <label htmlFor="mfa-confirm-code" style={labelStyle}>Verification Code</label>
                      <input
                        id="mfa-confirm-code" style={inputStyle} value={mfaConfirmCode} maxLength={6}
                        onChange={(e) => setMfaConfirmCode(e.target.value)} placeholder="Enter 6-digit code to confirm"
                        onKeyDown={(e) => { if (e.key === 'Enter' && mfaConfirmCode.length === 6) handleConfirmMfaSetup(); }}
                      />
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <Button
                        variant="primary"
                        size="sm"
                        loading={mfaSavingConfirm}
                        disabled={mfaConfirmCode.length !== 6}
                        onClick={handleConfirmMfaSetup}
                        style={{ flex: 1 }}
                      >
                        {mfaSavingConfirm ? 'Confirming…' : 'Confirm & Enable'}
                      </Button>
                      <Button variant="secondary" size="sm" onClick={handleCancelMfaSetup}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}

                {showMfaDisableForm && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Confirm your password and a current code to disable 2FA.
                    </div>
                    <div>
                      <label htmlFor="mfa-disable-password" style={labelStyle}>Current Password</label>
                      <input
                        id="mfa-disable-password" style={inputStyle} type="password" value={mfaDisablePassword}
                        autoComplete="current-password"
                        onChange={(e) => setMfaDisablePassword(e.target.value)} placeholder="Current password to confirm"
                      />
                    </div>
                    <div>
                      <label htmlFor="mfa-disable-code" style={labelStyle}>Verification Code</label>
                      <input
                        id="mfa-disable-code" style={inputStyle} value={mfaDisableCode} maxLength={6}
                        autoComplete="one-time-code" inputMode="numeric"
                        onChange={(e) => setMfaDisableCode(e.target.value)} placeholder="6-digit code"
                        onKeyDown={(e) => { if (e.key === 'Enter') handleDisableMfa(); }}
                      />
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <Button
                        variant="danger"
                        size="sm"
                        loading={mfaSavingDisable}
                        onClick={handleDisableMfa}
                        style={{ flex: 1 }}
                      >
                        {mfaSavingDisable ? 'Disabling…' : 'Confirm Disable'}
                      </Button>
                      <Button variant="secondary" size="sm" onClick={() => setShowMfaDisableForm(false)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Active Sessions */}
            {sessions && (
              <div className="panel-card">
                <div className="panel-card-header">
                  <span className="panel-card-title"><Monitor size={12} /> Active Sessions</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{sessions.length} active</span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Every device/browser currently logged into your account. Revoke one you don't recognize
                  or left open elsewhere without changing your password or logging out everywhere.
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {sessions.map((s) => (
                    <div
                      key={s.session_id}
                      style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px',
                        padding: '8px 10px', borderRadius: 'var(--radius-sm)',
                        background: s.is_current ? 'var(--accent-bg)' : 'var(--surface-subtle)',
                        border: s.is_current ? '1px solid var(--accent-border)' : '1px solid transparent',
                      }}
                    >
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', minWidth: 0 }}>
                        <span style={{ fontSize: '12px', color: 'var(--text-primary)', display: 'flex', gap: '6px', alignItems: 'center' }}>
                          {s.ip}
                          {s.is_current && (
                            <span style={{
                              fontSize: '9px', fontWeight: 700, padding: '1px 6px', borderRadius: 'var(--radius-pill)',
                              background: 'var(--accent-color)', color: '#fff', textTransform: 'uppercase',
                            }}>
                              This device
                            </span>
                          )}
                        </span>
                        <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.user_agent} · last used {s.last_seen_at ? formatLocalTime(s.last_seen_at) : 'unknown'}
                        </span>
                      </div>
                      <Button
                        variant="danger" size="sm"
                        loading={revokingSessionId === s.session_id}
                        onClick={() => handleRevokeSession(s.session_id, s.is_current)}
                        style={{ flexShrink: 0 }}
                      >
                        Revoke
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Notification preferences */}
            {prefs && (
              <div className="panel-card">
                <div className="panel-card-header">
                  <span className="panel-card-title"><BellOff size={12} /> Mute Bell Notifications</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Muted items won't count toward your bell badge, but stay visible in the full alert history.
                  </div>

                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>By severity</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {SEVERITIES.map((sev) => {
                      const muted = prefs.muted_severities.includes(sev);
                      return (
                        <button
                          key={sev}
                          onClick={() => togglePref('muted_severities', sev)}
                          disabled={savingPrefs}
                          style={{
                            padding: '5px 10px', borderRadius: 'var(--radius-pill)', fontSize: '11px', fontWeight: 600,
                            textTransform: 'capitalize', cursor: savingPrefs ? 'not-allowed' : 'pointer',
                            background: muted ? 'var(--surface-hover)' : 'var(--accent-bg)',
                            color: muted ? 'var(--text-secondary)' : 'var(--accent-color)',
                            border: muted ? '1px solid var(--border-strong)' : '1px solid var(--accent-border)',
                            textDecoration: muted ? 'line-through' : 'none',
                          }}
                        >
                          {sev}
                        </button>
                      );
                    })}
                  </div>

                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px' }}>By event type</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {EVENT_TYPES.map(({ id, label }) => {
                      const muted = prefs.muted_event_types.includes(id);
                      return (
                        <button
                          key={id}
                          onClick={() => togglePref('muted_event_types', id)}
                          disabled={savingPrefs}
                          style={{
                            padding: '5px 10px', borderRadius: 'var(--radius-pill)', fontSize: '11px', fontWeight: 600,
                            cursor: savingPrefs ? 'not-allowed' : 'pointer',
                            background: muted ? 'var(--surface-hover)' : 'var(--accent-bg)',
                            color: muted ? 'var(--text-secondary)' : 'var(--accent-color)',
                            border: muted ? '1px solid var(--border-strong)' : '1px solid var(--accent-border)',
                            textDecoration: muted ? 'line-through' : 'none',
                          }}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        <Toast toast={toast} />
      </div>
    </div>
  );
}
