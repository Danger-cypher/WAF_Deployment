import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { User, X, Check, ShieldCheck, KeyRound, Save, BellOff, Smartphone } from 'lucide-react';
import {
  getMyProfile, updateMyProfile, changeMyPassword,
  getMyNotificationPreferences, updateMyNotificationPreferences,
  getMyMfaStatus, setupMyMfa, confirmMyMfa, disableMyMfa,
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
  padding: '10px 12px',
  background: 'rgba(0,0,0,0.25)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: '8px',
  color: '#fff',
  fontSize: '14px',
  boxSizing: 'border-box',
};

const labelStyle = {
  display: 'block',
  fontSize: '12px',
  fontWeight: 600,
  color: 'rgba(255,255,255,0.6)',
  marginBottom: '6px',
  textTransform: 'uppercase',
  letterSpacing: '0.03em',
};

export default function Profile({ onClose }) {
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
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
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
  }, []);

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
    if (newPassword.length < 8) {
      showToast('New password must be at least 8 characters.', 'error');
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

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 99998 }}
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 10, scale: 0.97 }}
        style={{
          width: '440px', maxWidth: '92vw', maxHeight: '85vh', overflowY: 'auto',
          background: '#12141c', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '14px', padding: '24px',
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <User size={18} style={{ color: 'var(--accent-color)' }} />
            My Profile
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.5)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>

        {profile && (
          <>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px',
              padding: '10px 14px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px',
            }}>
              <ShieldCheck size={14} style={{ color: profile.role === 'admin' ? '#fca5a5' : '#a5b4fc' }} />
              <span style={{ fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                Signed in as <strong style={{ color: '#fff' }}>{profile.username}</strong> · {profile.role}
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginBottom: '10px' }}>
              <div>
                <label style={labelStyle}>Display Name</label>
                <input style={inputStyle} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Your name" />
              </div>
              <div>
                <label style={labelStyle}>Email</label>
                <input style={inputStyle} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
              </div>
              <button
                onClick={handleSaveProfile}
                disabled={savingProfile}
                style={{
                  padding: '10px', background: 'rgba(0, 212, 255, 0.12)', border: '1px solid var(--accent-color)',
                  borderRadius: '8px', color: 'var(--accent-color)', fontWeight: 600, cursor: savingProfile ? 'not-allowed' : 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', opacity: savingProfile ? 0.7 : 1,
                }}
              >
                <Save size={14} />
                {savingProfile ? 'Saving…' : 'Save Profile'}
              </button>
            </div>

            <div style={{ height: '1px', background: 'rgba(255,255,255,0.08)', margin: '18px 0' }} />

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <label style={{ ...labelStyle, marginBottom: '-4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <KeyRound size={12} /> Change Password
              </label>
              <input
                style={inputStyle} type="password" value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password"
              />
              <input
                style={inputStyle} type="password" value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (min 8 chars)"
              />
              <button
                onClick={handleChangePassword}
                disabled={savingPassword || !currentPassword || !newPassword}
                style={{
                  padding: '10px', background: 'var(--accent-color)', border: 'none', borderRadius: '8px',
                  color: '#000', fontWeight: 700,
                  cursor: (savingPassword || !currentPassword || !newPassword) ? 'not-allowed' : 'pointer',
                  opacity: (savingPassword || !currentPassword || !newPassword) ? 0.6 : 1,
                }}
              >
                {savingPassword ? 'Updating…' : 'Update Password'}
              </button>
            </div>

            {mfaStatus && (
              <>
                <div style={{ height: '1px', background: 'rgba(255,255,255,0.08)', margin: '18px 0' }} />

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <label style={{ ...labelStyle, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Smartphone size={12} /> Two-Factor Authentication
                  </label>

                  {!mfaSetupData && (
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px',
                      padding: '10px 14px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px',
                    }}>
                      <span style={{
                        fontSize: '12px', fontWeight: 600,
                        color: mfaStatus.enabled ? '#34d399' : 'rgba(255,255,255,0.5)',
                      }}>
                        {mfaStatus.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                      {mfaStatus.enabled ? (
                        <button
                          onClick={() => setShowMfaDisableForm((v) => !v)}
                          style={{
                            padding: '6px 12px', background: 'rgba(255,59,92,0.1)', border: '1px solid rgba(255,59,92,0.4)',
                            borderRadius: '6px', color: '#ff3b5c', fontWeight: 600, fontSize: '12px', cursor: 'pointer',
                          }}
                        >
                          Disable
                        </button>
                      ) : (
                        <button
                          onClick={handleStartMfaSetup}
                          disabled={mfaSavingSetup}
                          style={{
                            padding: '6px 12px', background: 'rgba(0,212,255,0.12)', border: '1px solid var(--accent-color)',
                            borderRadius: '6px', color: 'var(--accent-color)', fontWeight: 600, fontSize: '12px',
                            cursor: mfaSavingSetup ? 'not-allowed' : 'pointer',
                          }}
                        >
                          {mfaSavingSetup ? 'Starting…' : 'Enable 2FA'}
                        </button>
                      )}
                    </div>
                  )}

                  {mfaSetupData && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', padding: '14px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px' }}>
                      <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.6)' }}>
                        Scan with Google Authenticator, Authy, or any TOTP app:
                      </div>
                      <img
                        src={`data:image/png;base64,${mfaSetupData.qr_code_png_base64}`}
                        alt="MFA QR code"
                        style={{ width: '160px', height: '160px', alignSelf: 'center', background: '#fff', padding: '8px', borderRadius: '8px' }}
                      />
                      <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.5)' }}>
                        Or enter manually: <code style={{ color: 'var(--accent-color)', wordBreak: 'break-all' }}>{mfaSetupData.secret}</code>
                      </div>
                      <input
                        style={inputStyle} value={mfaConfirmCode} maxLength={6}
                        onChange={(e) => setMfaConfirmCode(e.target.value)} placeholder="Enter 6-digit code to confirm"
                      />
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          onClick={handleConfirmMfaSetup}
                          disabled={mfaSavingConfirm || mfaConfirmCode.length !== 6}
                          style={{
                            flex: 1, padding: '10px', background: 'var(--accent-color)', border: 'none', borderRadius: '8px',
                            color: '#000', fontWeight: 700,
                            cursor: (mfaSavingConfirm || mfaConfirmCode.length !== 6) ? 'not-allowed' : 'pointer',
                            opacity: (mfaSavingConfirm || mfaConfirmCode.length !== 6) ? 0.6 : 1,
                          }}
                        >
                          {mfaSavingConfirm ? 'Confirming…' : 'Confirm & Enable'}
                        </button>
                        <button
                          onClick={handleCancelMfaSetup}
                          style={{
                            padding: '10px 14px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                            borderRadius: '8px', color: 'rgba(255,255,255,0.6)', fontWeight: 600, cursor: 'pointer',
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}

                  {showMfaDisableForm && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', padding: '14px', background: 'rgba(255,59,92,0.05)', border: '1px solid rgba(255,59,92,0.2)', borderRadius: '8px' }}>
                      <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.6)' }}>
                        Confirm your password and a current code to disable 2FA.
                      </div>
                      <input
                        style={inputStyle} type="password" value={mfaDisablePassword}
                        onChange={(e) => setMfaDisablePassword(e.target.value)} placeholder="Current password to confirm"
                      />
                      <input
                        style={inputStyle} value={mfaDisableCode} maxLength={6}
                        onChange={(e) => setMfaDisableCode(e.target.value)} placeholder="6-digit code"
                      />
                      <button
                        onClick={handleDisableMfa}
                        disabled={mfaSavingDisable || !mfaDisablePassword || mfaDisableCode.length !== 6}
                        style={{
                          padding: '10px', background: '#ff3b5c', border: 'none', borderRadius: '8px',
                          color: '#fff', fontWeight: 700,
                          cursor: (mfaSavingDisable || !mfaDisablePassword || mfaDisableCode.length !== 6) ? 'not-allowed' : 'pointer',
                          opacity: (mfaSavingDisable || !mfaDisablePassword || mfaDisableCode.length !== 6) ? 0.6 : 1,
                        }}
                      >
                        {mfaSavingDisable ? 'Disabling…' : 'Confirm Disable'}
                      </button>
                    </div>
                  )}
                </div>
              </>
            )}

            {prefs && (
              <>
                <div style={{ height: '1px', background: 'rgba(255,255,255,0.08)', margin: '18px 0' }} />

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <label style={{ ...labelStyle, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <BellOff size={12} /> Mute Bell Notifications
                  </label>
                  <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.4)', marginTop: '-6px' }}>
                    Muted items won't count toward your bell badge, but stay visible in the full alert history.
                  </div>

                  <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>By severity</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {SEVERITIES.map((sev) => {
                      const muted = prefs.muted_severities.includes(sev);
                      return (
                        <button
                          key={sev}
                          onClick={() => togglePref('muted_severities', sev)}
                          disabled={savingPrefs}
                          style={{
                            padding: '5px 10px', borderRadius: '999px', fontSize: '11px', fontWeight: 600,
                            textTransform: 'capitalize', cursor: savingPrefs ? 'not-allowed' : 'pointer',
                            background: muted ? 'rgba(255,255,255,0.05)' : 'rgba(0,212,255,0.1)',
                            color: muted ? 'rgba(255,255,255,0.35)' : 'var(--accent-color)',
                            border: muted ? '1px solid rgba(255,255,255,0.1)' : '1px solid var(--accent-color)',
                            textDecoration: muted ? 'line-through' : 'none',
                          }}
                        >
                          {sev}
                        </button>
                      );
                    })}
                  </div>

                  <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.5)', marginTop: '8px' }}>By event type</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {EVENT_TYPES.map(({ id, label }) => {
                      const muted = prefs.muted_event_types.includes(id);
                      return (
                        <button
                          key={id}
                          onClick={() => togglePref('muted_event_types', id)}
                          disabled={savingPrefs}
                          style={{
                            padding: '5px 10px', borderRadius: '999px', fontSize: '11px', fontWeight: 600,
                            cursor: savingPrefs ? 'not-allowed' : 'pointer',
                            background: muted ? 'rgba(255,255,255,0.05)' : 'rgba(0,212,255,0.1)',
                            color: muted ? 'rgba(255,255,255,0.35)' : 'var(--accent-color)',
                            border: muted ? '1px solid rgba(255,255,255,0.1)' : '1px solid var(--accent-color)',
                            textDecoration: muted ? 'line-through' : 'none',
                          }}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </>
            )}
          </>
        )}

        <AnimatePresence>
          {toast && (
            <motion.div
              initial={{ opacity: 0, y: 20, scale: 0.95 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 10, scale: 0.95 }}
              style={{
                marginTop: '16px', padding: '10px 14px',
                background: toast.type === 'error' ? 'rgba(255, 59, 92, 0.15)' : 'rgba(52, 211, 153, 0.15)',
                border: toast.type === 'error' ? '1px solid #ff3b5c' : '1px solid #34d399',
                borderRadius: '8px', color: toast.type === 'error' ? '#ff3b5c' : '#34d399', fontWeight: 600,
                fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px',
              }}
            >
              {toast.type === 'error' ? <X size={14} /> : <Check size={14} />}
              <span>{toast.message}</span>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </motion.div>
  );
}
