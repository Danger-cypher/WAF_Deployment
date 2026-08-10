import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Users, Plus, Trash2, KeyRound, Check, X, ShieldCheck, ShieldAlert, Power, Smartphone } from 'lucide-react';
import { listUsers, createUser, updateUser, resetUserPassword, deleteUser, adminDisableUserMfa } from '../services/api';

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

function ModalShell({ title, onClose, children }) {
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 99998,
      }}
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 10, scale: 0.97 }}
        style={{
          width: '420px', maxWidth: '92vw', background: '#12141c',
          border: '1px solid rgba(255,255,255,0.1)', borderRadius: '14px', padding: '24px',
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#fff' }}>{title}</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.5)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>
        {children}
      </motion.div>
    </motion.div>
  );
}

function CreateUserModal({ onClose, onCreated, showToast }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async () => {
    if (!username.trim() || password.length < 8) {
      showToast('Username is required and password must be at least 8 characters.', 'error');
      return;
    }
    setSaving(true);
    try {
      await createUser({
        username: username.trim(),
        password,
        role,
        display_name: displayName.trim() || null,
        email: email.trim() || null,
      });
      showToast('User created successfully.');
      onCreated();
      onClose();
    } catch (err) {
      showToast('Failed to create user: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <ModalShell title="Add New User" onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div>
          <label style={labelStyle}>Username</label>
          <input style={inputStyle} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="jdoe" autoFocus />
        </div>
        <div>
          <label style={labelStyle}>Temporary Password (min 8 chars)</label>
          <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
        </div>
        <div>
          <label style={labelStyle}>Role</label>
          <select style={inputStyle} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">Analyst (read-only)</option>
            <option value="admin">Admin (full access)</option>
          </select>
        </div>
        <div>
          <label style={labelStyle}>Display Name (optional)</label>
          <input style={inputStyle} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Jane Doe" />
        </div>
        <div>
          <label style={labelStyle}>Email (optional)</label>
          <input style={inputStyle} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="jane@example.com" />
        </div>
        <button
          onClick={handleSubmit}
          disabled={saving}
          style={{
            marginTop: '4px', padding: '11px', background: 'var(--accent-color)', border: 'none',
            borderRadius: '8px', color: '#000', fontWeight: 700, cursor: saving ? 'not-allowed' : 'pointer',
            opacity: saving ? 0.7 : 1,
          }}
        >
          {saving ? 'Creating…' : 'Create User'}
        </button>
      </div>
    </ModalShell>
  );
}

function ResetPasswordModal({ user, onClose, showToast }) {
  const [password, setPassword] = useState('');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async () => {
    if (password.length < 8) {
      showToast('New password must be at least 8 characters.', 'error');
      return;
    }
    setSaving(true);
    try {
      await resetUserPassword(user.id, password);
      showToast(`Password reset for ${user.username}.`);
      onClose();
    } catch (err) {
      showToast('Failed to reset password: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <ModalShell title={`Reset Password — ${user.username}`} onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div>
          <label style={labelStyle}>New Password (min 8 chars)</label>
          <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoFocus />
        </div>
        <button
          onClick={handleSubmit}
          disabled={saving}
          style={{
            padding: '11px', background: 'var(--accent-color)', border: 'none',
            borderRadius: '8px', color: '#000', fontWeight: 700, cursor: saving ? 'not-allowed' : 'pointer',
            opacity: saving ? 0.7 : 1,
          }}
        >
          {saving ? 'Saving…' : 'Reset Password'}
        </button>
      </div>
    </ModalShell>
  );
}

export default function UserManagement({ currentUsername }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [resetTarget, setResetTarget] = useState(null);
  const [busyId, setBusyId] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const fetchUsers = useCallback(async () => {
    try {
      const data = await listUsers();
      setUsers(data);
    } catch (err) {
      showToast('Failed to load users: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const handleToggleEnabled = async (user) => {
    setBusyId(user.id);
    try {
      await updateUser(user.id, { enabled: !user.enabled });
      showToast(`${user.username} ${user.enabled ? 'disabled' : 'enabled'}.`);
      fetchUsers();
    } catch (err) {
      showToast('Failed: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleRoleChange = async (user, role) => {
    if (role === user.role) return;
    setBusyId(user.id);
    try {
      await updateUser(user.id, { role });
      showToast(`${user.username}'s role changed to ${role}.`);
      fetchUsers();
    } catch (err) {
      showToast('Failed: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (user) => {
    if (!window.confirm(`Delete user "${user.username}"? This cannot be undone.`)) return;
    setBusyId(user.id);
    try {
      await deleteUser(user.id);
      showToast(`${user.username} deleted.`);
      fetchUsers();
    } catch (err) {
      showToast('Failed: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleForceDisableMfa = async (user) => {
    if (!window.confirm(`Disable two-factor authentication for "${user.username}"? Use this if they lost their authenticator device.`)) return;
    setBusyId(user.id);
    try {
      await adminDisableUserMfa(user.id);
      showToast(`2FA disabled for ${user.username}.`);
      fetchUsers();
    } catch (err) {
      showToast('Failed: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="user-management-tab" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h2 style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: 0, fontSize: '24px', fontWeight: 700 }}>
          <Users size={24} style={{ color: 'var(--accent-color)' }} />
          <span>User Management</span>
        </h2>
        <button
          onClick={() => setShowCreate(true)}
          style={{
            padding: '10px 20px', background: 'var(--accent-color)', border: 'none', borderRadius: '8px',
            color: '#000', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px',
            boxShadow: '0 4px 14px rgba(0, 212, 255, 0.3)',
          }}
        >
          <Plus size={18} />
          Add User
        </button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'rgba(255,255,255,0.5)' }}>Loading users…</div>
      ) : (
        <div style={{
          background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '12px', overflow: 'hidden',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
            <thead>
              <tr style={{ background: 'rgba(255,255,255,0.03)', textAlign: 'left' }}>
                {['User', 'Role', 'Status', '2FA', 'Last Login', ''].map((h) => (
                  <th key={h} style={{ padding: '12px 16px', color: 'rgba(255,255,255,0.5)', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.username === currentUsername;
                return (
                  <tr key={u.id} style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                    <td style={{ padding: '14px 16px' }}>
                      <div style={{ fontWeight: 600, color: '#fff' }}>{u.username}{isSelf && <span style={{ color: 'var(--accent-color)', fontSize: '11px', marginLeft: '8px' }}>(you)</span>}</div>
                      {(u.display_name || u.email) && (
                        <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.45)' }}>
                          {[u.display_name, u.email].filter(Boolean).join(' · ')}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <select
                        value={u.role}
                        disabled={isSelf || busyId === u.id}
                        title={isSelf ? "You can't change your own role" : undefined}
                        onChange={(e) => handleRoleChange(u, e.target.value)}
                        style={{
                          ...inputStyle, width: 'auto', padding: '6px 10px', fontSize: '12px',
                          color: u.role === 'admin' ? '#fca5a5' : '#a5b4fc',
                        }}
                      >
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: '6px',
                        padding: '4px 10px', borderRadius: '999px', fontSize: '12px', fontWeight: 600,
                        background: u.enabled ? 'rgba(52,211,153,0.12)' : 'rgba(255,255,255,0.08)',
                        color: u.enabled ? '#34d399' : 'rgba(255,255,255,0.5)',
                      }}>
                        {u.enabled ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                        {u.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span
                        title={u.mfa_enabled ? 'Two-factor authentication enabled' : 'Two-factor authentication not enabled'}
                        style={{ display: 'inline-flex', alignItems: 'center', color: u.mfa_enabled ? '#34d399' : 'rgba(255,255,255,0.25)' }}
                      >
                        <Smartphone size={16} />
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px', color: 'rgba(255,255,255,0.5)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      {u.last_login_at ? u.last_login_at.replace('T', ' ').split('.')[0] : 'Never'}
                    </td>
                    <td style={{ padding: '14px 16px', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button
                        title="Reset password"
                        onClick={() => setResetTarget(u)}
                        style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.5)', cursor: 'pointer', padding: '6px' }}
                      >
                        <KeyRound size={16} />
                      </button>
                      {u.mfa_enabled && (
                        <button
                          title="Force-disable 2FA (account recovery)"
                          disabled={busyId === u.id}
                          onClick={() => handleForceDisableMfa(u)}
                          style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.5)', cursor: busyId === u.id ? 'not-allowed' : 'pointer', padding: '6px' }}
                        >
                          <Smartphone size={16} />
                        </button>
                      )}
                      <button
                        title={u.enabled ? 'Disable user' : 'Enable user'}
                        disabled={isSelf || busyId === u.id}
                        onClick={() => handleToggleEnabled(u)}
                        style={{ background: 'none', border: 'none', color: isSelf ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.5)', cursor: isSelf ? 'not-allowed' : 'pointer', padding: '6px' }}
                      >
                        <Power size={16} />
                      </button>
                      <button
                        title="Delete user"
                        disabled={isSelf || busyId === u.id}
                        onClick={() => handleDelete(u)}
                        style={{ background: 'none', border: 'none', color: isSelf ? 'rgba(255,255,255,0.2)' : '#f87171', cursor: isSelf ? 'not-allowed' : 'pointer', padding: '6px' }}
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <AnimatePresence>
        {showCreate && (
          <CreateUserModal onClose={() => setShowCreate(false)} onCreated={fetchUsers} showToast={showToast} />
        )}
        {resetTarget && (
          <ResetPasswordModal user={resetTarget} onClose={() => setResetTarget(null)} showToast={showToast} />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.95 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 20, scale: 0.95 }}
            style={{
              position: 'fixed', bottom: '24px', right: '24px', padding: '12px 24px',
              background: toast.type === 'error' ? 'rgba(255, 59, 92, 0.95)' : 'rgba(0, 212, 255, 0.95)',
              border: toast.type === 'error' ? '1px solid #ff3b5c' : '1px solid #00d4ff',
              borderRadius: '8px', color: toast.type === 'error' ? '#fff' : '#000', fontWeight: 600,
              display: 'flex', alignItems: 'center', gap: '10px', zIndex: 99999, boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
            }}
          >
            {toast.type === 'error' ? <X size={16} /> : <Check size={16} />}
            <span>{toast.message}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
