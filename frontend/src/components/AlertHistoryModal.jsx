import { useState, useEffect } from 'react';
import { getAlertHistory, acknowledgeAlert, getAlertStats } from '../services/api';
import { formatLocalTime } from '../utils/helpers';

export default function AlertHistoryModal({ isOpen, onClose }) {
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const fetchHistory = async () => {
    try {
      const hist = await getAlertHistory(100, 0);
      setHistory(hist);
      const st = await getAlertStats(7);
      setStats(st);
    } catch (err) {
      console.error("Error loading alert history:", err);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  const handleAck = async (id) => {
    try {
      await acknowledgeAlert(id);
      fetchHistory();
    } catch (err) {
      alert("Failed to acknowledge: " + err.message);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 5, 9, 0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9999 }}>
      <div className="modal-content" style={{ background: 'var(--bg-secondary)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-color)', width: '900px', maxHeight: '85vh', display: 'flex', flexDirection: 'column', gap: '20px', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--accent-color)', fontFamily: 'var(--font-display)' }}>Triggered Alert History Logs</h3>
          <button style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '18px', cursor: 'pointer' }} onClick={onClose}>X</button>
        </div>

        {/* Stats */}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' }}>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Total Alerts (7d)</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>{stats.total_alerts}</div>
            </div>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Critical Alerts</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--danger-color)' }}>{stats.alerts_by_severity?.critical || 0}</div>
            </div>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Dispatched Notifications</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--success-color)' }}>{stats.alerts_by_status?.sent || 0}</div>
            </div>
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Throttled events</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--warning-color)' }}>{stats.alerts_by_status?.throttled || 0}</div>
            </div>
          </div>
        )}

        <div style={{ overflowX: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>
                <th style={{ padding: '12px' }}>Time</th>
                <th style={{ padding: '12px' }}>Rule</th>
                <th style={{ padding: '12px' }}>Event</th>
                <th style={{ padding: '12px' }}>Severity</th>
                <th style={{ padding: '12px' }}>Message</th>
                <th style={{ padding: '12px' }}>Status</th>
                <th style={{ padding: '12px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.length > 0 ? (
                history.map((alert) => (
                  <tr key={alert.id} style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                    <td style={{ padding: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{formatLocalTime(alert.created_at)}</td>
                    <td style={{ padding: '12px', fontWeight: 600 }}>{alert.rule_name}</td>
                    <td style={{ padding: '12px' }}><span className="badge-purple">{alert.event_type}</span></td>
                    <td style={{ padding: '12px' }}>
                      <span style={{
                        padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase',
                        background: alert.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                        color: alert.severity === 'critical' ? 'var(--danger-color)' : 'var(--warning-color)',
                        border: alert.severity === 'critical' ? '1px solid rgba(255, 59, 92, 0.2)' : '1px solid rgba(255, 149, 0, 0.2)'
                      }}>{alert.severity}</span>
                    </td>
                    <td style={{ padding: '12px', maxWidth: '240px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{alert.message}</td>
                    <td style={{ padding: '12px' }}>
                      <span style={{
                        padding: '2px 6px', borderRadius: '10px', fontSize: '10px',
                        background: alert.status === 'sent' ? 'var(--success-bg)' : alert.status === 'throttled' ? 'var(--warning-bg)' : 'var(--danger-bg)',
                        color: alert.status === 'sent' ? 'var(--success-color)' : alert.status === 'throttled' ? 'var(--warning-color)' : 'var(--danger-color)',
                        border: alert.status === 'sent' ? '1px solid rgba(0, 255, 157, 0.2)' : alert.status === 'throttled' ? '1px solid rgba(255, 149, 0, 0.2)' : '1px solid rgba(255, 59, 92, 0.2)'
                      }}>{alert.status}</span>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button className="action-btn-inspect" style={{ padding: '4px 8px', fontSize: '11px' }} onClick={() => setSelectedAlert(alert)}>View</button>
                        {alert.status !== 'acknowledged' && (
                          <button className="modal-btn primary" style={{ padding: '4px 8px', fontSize: '11px', boxShadow: 'none' }} onClick={() => handleAck(alert.id)}>Ack</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-secondary)' }}>No alerts triggered.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Details View */}
      {selectedAlert && (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 5, 9, 0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 10000 }}>
          <div className="modal-content" style={{ background: 'var(--bg-secondary)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-color)', width: '500px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--accent-color)' }}>Alert Details: {selectedAlert.rule_name}</h3>
              <button style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '16px', cursor: 'pointer' }} onClick={() => setSelectedAlert(null)}>X</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', color: 'var(--text-primary)' }}>
              <p><strong>Message:</strong> {selectedAlert.message}</p>
              <div><strong>Raw Payload:</strong></div>
              <pre style={{ background: 'var(--bg-void)', padding: '12px', borderRadius: '6px', overflowY: 'auto', maxHeight: '160px', fontSize: '11px', color: 'var(--success-color)', border: '1px solid var(--border-color)' }}>{JSON.stringify(selectedAlert.event_data, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
