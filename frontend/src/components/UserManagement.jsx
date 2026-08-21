import { useState, useEffect, useCallback } from 'react';
import { AnimatePresence } from 'framer-motion';
import { Users, Plus, Trash2, KeyRound, X, ShieldCheck, ShieldAlert, Power, Smartphone, Server } from 'lucide-react';
import { listUsers, createUser, updateUser, resetUserPassword, deleteUser, adminDisableUserMfa, getProtectedApps } from '../services/api';
import { useToast } from '../hooks/useToast';
import Toast from './Toast';
import Button from './Button';
import { useConfirm } from '../hooks/useConfirm';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { usePagination } from '../hooks/usePagination';
import Pagination from './Pagination';

const inputStyle = {
  width: '100%',
  padding: '10px 12px',
  background: 'rgba(0,0,0,0.25)',
  border: '1px solid var(--border-strong)',
  borderRadius: '8px',
  color: 'var(--text-primary)',
  fontSize: '14px',
  boxSizing: 'border-box',
};

const labelStyle = {
  display: 'block',
  fontSize: '12px',
  fontWeight: 600,
  color: 'var(--text-secondary)',
  marginBottom: '6px',
  textTransform: 'uppercase',
  letterSpacing: '0.03em',
};

function ModalShell({ title, onClose, children }) {
  useEscapeToClose(onClose, true);
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '420px' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">{title}</div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">
          {children}
        </div>
      </div>
    </div>
  );
}

function AppChecklist({ apps, selectedIds, onChange }) {
  const toggle = (id) => {
    onChange(selectedIds.includes(id) ? selectedIds.filter((x) => x !== id) : [...selectedIds, id]);
  };
  if (apps.length === 0) {
    return <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>No protected applications exist yet.</div>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '160px', overflowY: 'auto', padding: '8px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
      {apps.map((app) => (
        <label key={app.id} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-primary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={selectedIds.includes(app.id)} onChange={() => toggle(app.id)} />
          {app.name} <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>({app.domain})</span>
        </label>
      ))}
    </div>
  );
}

function CreateUserModal({ onClose, onCreated, showToast }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [saving, setSaving] = useState(false);
  const [apps, setApps] = useState([]);
  const [appIds, setAppIds] = useState([]);

  useEffect(() => {
    getProtectedApps().then(setApps).catch(() => setApps([]));
  }, []);

  const handleSubmit = async () => {
    if (!username.trim() || password.length < 12) {
      showToast('Username is required and password must be at least 12 characters.', 'error');
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
        app_ids: role === 'app_admin' ? appIds : [],
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
          <label style={labelStyle}>Temporary Password (min 12 chars, 3+ char types)</label>
          <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
        </div>
        <div>
          <label style={labelStyle}>Role</label>
          <select style={inputStyle} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">Analyst (read-only)</option>
            <option value="admin">Admin (full access)</option>
            <option value="app_admin">App Admin (scoped to specific apps)</option>
          </select>
        </div>
        {role === 'app_admin' && (
          <div>
            <label style={labelStyle}>Protected Applications</label>
            <AppChecklist apps={apps} selectedIds={appIds} onChange={setAppIds} />
          </div>
        )}
        <div>
          <label style={labelStyle}>Display Name (optional)</label>
          <input style={inputStyle} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Jane Doe" />
        </div>
        <div>
          <label style={labelStyle}>Email (optional)</label>
          <input style={inputStyle} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="jane@example.com" />
        </div>
        <Button variant="primary" loading={saving} onClick={handleSubmit} style={{ marginTop: '4px' }}>
          {saving ? 'Creating…' : 'Create User'}
        </Button>
      </div>
    </ModalShell>
  );
}

function AppAccessModal({ user, onClose, onSaved, showToast }) {
  const [apps, setApps] = useState([]);
  const [appIds, setAppIds] = useState(user.app_ids || []);
  const [saving, setSaving] = useState(false);
  const [loadingApps, setLoadingApps] = useState(true);

  useEffect(() => {
    getProtectedApps().then(setApps).catch(() => setApps([])).finally(() => setLoadingApps(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateUser(user.id, { app_ids: appIds });
      showToast(`App access updated for ${user.username}.`);
      onSaved();
      onClose();
    } catch (err) {
      showToast('Failed to update app access: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <ModalShell title={`App Access — ${user.username}`} onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          This user can only view and manage the protected applications checked below.
        </div>
        {loadingApps ? (
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Loading applications…</div>
        ) : (
          <AppChecklist apps={apps} selectedIds={appIds} onChange={setAppIds} />
        )}
        <Button variant="primary" loading={saving} onClick={handleSave} style={{ marginTop: '4px' }}>
          {saving ? 'Saving…' : 'Save Access'}
        </Button>
      </div>
    </ModalShell>
  );
}

function ResetPasswordModal({ user, onClose, showToast }) {
  const [password, setPassword] = useState('');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async () => {
    if (password.length < 12) {
      showToast('New password must be at least 12 characters.', 'error');
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
          <label style={labelStyle}>New Password (min 12 chars, 3+ char types)</label>
          <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoFocus />
        </div>
        <Button variant="primary" loading={saving} onClick={handleSubmit}>
          {saving ? 'Saving…' : 'Reset Password'}
        </Button>
      </div>
    </ModalShell>
  );
}

export default function UserManagement({ currentUsername }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const { toast, showToast } = useToast();
  const confirm = useConfirm();
  const { page, totalPages, total, pageItems, goToPrev, goToNext } = usePagination(users, 15);
  const [showCreate, setShowCreate] = useState(false);
  const [resetTarget, setResetTarget] = useState(null);
  const [appAccessTarget, setAppAccessTarget] = useState(null);
  const [busyId, setBusyId] = useState(null);

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
    if (!(await confirm({
      title: 'Delete user',
      message: `Delete user "${user.username}"? This cannot be undone.`,
      confirmLabel: 'Delete',
      danger: true,
    }))) return;
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
    if (!(await confirm({
      title: 'Disable 2FA',
      message: `Disable two-factor authentication for "${user.username}"? Use this if they lost their authenticator device.`,
      confirmLabel: 'Disable 2FA',
      danger: true,
    }))) return;
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
        <Button variant="primary" icon={Plus} onClick={() => setShowCreate(true)}>
          Add User
        </Button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-secondary)' }}>Loading users…</div>
      ) : (
        <div style={{
          background: 'var(--inset-bg)', border: '1px solid var(--surface-strong)',
          borderRadius: '12px', overflow: 'hidden',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
            <thead>
              <tr style={{ background: 'var(--surface-subtle)', textAlign: 'left' }}>
                {['User', 'Role', 'Status', '2FA', 'Last Login', ''].map((h) => (
                  <th key={h} style={{ padding: '12px 16px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageItems.map((u) => {
                const isSelf = u.username === currentUsername;
                return (
                  <tr key={u.id} style={{ borderTop: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '14px 16px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.username}{isSelf && <span style={{ color: 'var(--accent-color)', fontSize: '11px', marginLeft: '8px' }}>(you)</span>}</div>
                      {(u.display_name || u.email) && (
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
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
                          color: u.role === 'admin' ? 'var(--danger-color)' : 'var(--accent-color)',
                        }}
                      >
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                        <option value="app_admin">App Admin</option>
                      </select>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: '6px',
                        padding: '4px 10px', borderRadius: '999px', fontSize: '12px', fontWeight: 600,
                        background: u.enabled ? 'var(--success-bg)' : 'var(--surface-strong)',
                        color: u.enabled ? 'var(--success-color)' : 'var(--text-secondary)',
                      }}>
                        {u.enabled ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                        {u.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span
                        title={u.mfa_enabled ? 'Two-factor authentication enabled' : 'Two-factor authentication not enabled'}
                        style={{ display: 'inline-flex', alignItems: 'center', color: u.mfa_enabled ? 'var(--success-color)' : 'var(--border-strong)' }}
                      >
                        <Smartphone size={16} />
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      {u.last_login_at ? u.last_login_at.replace('T', ' ').split('.')[0] : 'Never'}
                    </td>
                    <td style={{ padding: '14px 16px', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      {u.role === 'app_admin' && (
                        <Button
                          variant="ghost" size="sm" icon={Server}
                          title={`Manage app access (${(u.app_ids || []).length} app${(u.app_ids || []).length === 1 ? '' : 's'})`}
                          onClick={() => setAppAccessTarget(u)}
                        />
                      )}
                      <Button
                        variant="ghost" size="sm" icon={KeyRound}
                        title="Reset password"
                        onClick={() => setResetTarget(u)}
                      />
                      {u.mfa_enabled && (
                        <Button
                          variant="ghost" size="sm" icon={Smartphone}
                          title="Force-disable 2FA (account recovery)"
                          disabled={busyId === u.id}
                          onClick={() => handleForceDisableMfa(u)}
                        />
                      )}
                      <Button
                        variant="ghost" size="sm" icon={Power}
                        title={u.enabled ? 'Disable user' : 'Enable user'}
                        disabled={isSelf || busyId === u.id}
                        onClick={() => handleToggleEnabled(u)}
                      />
                      <Button
                        variant="ghost" size="sm" icon={Trash2}
                        title="Delete user"
                        disabled={isSelf || busyId === u.id}
                        onClick={() => handleDelete(u)}
                        style={{ color: isSelf ? undefined : 'var(--danger-color)' }}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Pagination page={page} totalPages={totalPages} total={total} itemLabel="users" onPrev={goToPrev} onNext={goToNext} />

      <AnimatePresence>
        {showCreate && (
          <CreateUserModal onClose={() => setShowCreate(false)} onCreated={fetchUsers} showToast={showToast} />
        )}
        {resetTarget && (
          <ResetPasswordModal user={resetTarget} onClose={() => setResetTarget(null)} showToast={showToast} />
        )}
        {appAccessTarget && (
          <AppAccessModal user={appAccessTarget} onClose={() => setAppAccessTarget(null)} onSaved={fetchUsers} showToast={showToast} />
        )}
      </AnimatePresence>

      <Toast toast={toast} />
    </div>
  );
}
