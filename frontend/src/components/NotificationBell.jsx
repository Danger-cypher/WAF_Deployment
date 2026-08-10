import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell, Wifi, WifiOff } from 'lucide-react';
import { getAlertHistory, acknowledgeAlert, getMyNotificationPreferences, getLiveStreamWsUrl } from '../services/api';
import { formatLocalTime } from '../utils/helpers';

// How long we'll go without a live WS connection before quietly falling
// back to polling, so notifications keep working even if a proxy in front
// of the app doesn't support WebSocket upgrades.
const FALLBACK_POLL_MS = 60000;
const WS_RECONNECT_MS = 5000;

export default function NotificationBell({ onOpenHistory, onOpenSettings }) {
  const [history, setHistory] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isOpen, setIsOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const dropdownRef = useRef(null);
  const prefsRef = useRef({ muted_severities: [], muted_event_types: [] });
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  const isMuted = useCallback((alert) => {
    const prefs = prefsRef.current;
    return prefs.muted_severities.includes(alert.severity)
      || prefs.muted_event_types.includes(alert.event_type);
  }, []);

  const fetchUnread = useCallback(async () => {
    try {
      const hist = await getAlertHistory(10, 0);
      const visible = hist.filter(h => !isMuted(h));
      const unread = visible.filter(h => h.status !== 'acknowledged');
      setHistory(visible.slice(0, 5)); // show latest 5
      setUnreadCount(unread.length);
    } catch (err) {
      console.error("Error fetching unread notifications:", err);
    }
  }, [isMuted]);

  // Load mute preferences once, then fetch the initial baseline.
  useEffect(() => {
    getMyNotificationPreferences()
      .then(prefs => { prefsRef.current = prefs; })
      .catch(err => console.error("Error fetching notification preferences:", err))
      .finally(fetchUnread);
  }, [fetchUnread]);

  // Live push over the shared WebSocket stream, with a reconnect loop and
  // a slow fallback poll in case the connection never comes up at all.
  useEffect(() => {
    let cancelled = false;
    let fallbackInterval = null;

    const connect = () => {
      if (cancelled) return;
      const ws = new WebSocket(getLiveStreamWsUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        if (cancelled) return;
        setWsConnected(true);
        if (fallbackInterval) {
          clearInterval(fallbackInterval);
          fallbackInterval = null;
        }
      };

      ws.onmessage = (event) => {
        let envelope;
        try {
          envelope = JSON.parse(event.data);
        } catch {
          return;
        }
        if (envelope?.type !== 'alert' || !envelope.data || isMuted(envelope.data)) return;

        setHistory(prev => [envelope.data, ...prev].slice(0, 5));
        setUnreadCount(prev => prev + 1);
      };

      const scheduleReconnect = () => {
        if (cancelled) return;
        setWsConnected(false);
        if (!fallbackInterval) {
          // Keep the bell accurate even while disconnected.
          fallbackInterval = setInterval(fetchUnread, FALLBACK_POLL_MS);
        }
        reconnectTimerRef.current = setTimeout(connect, WS_RECONNECT_MS);
      };

      ws.onclose = scheduleReconnect;
      ws.onerror = () => ws.close();
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (fallbackInterval) clearInterval(fallbackInterval);
      wsRef.current?.close();
    };
  }, [fetchUnread, isMuted]);

  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const handleAckAll = async () => {
    try {
      const unread = history.filter(h => h.status !== 'acknowledged');
      for (const alertItem of unread) {
        await acknowledgeAlert(alertItem.id);
      }
      fetchUnread();
    } catch (err) {
      alert("Failed to acknowledge notifications: " + err.message);
    }
  };

  const handleSingleAck = async (id, e) => {
    e.stopPropagation();
    try {
      await acknowledgeAlert(id);
      fetchUnread();
    } catch (err) {
      alert("Failed to acknowledge alert: " + err.message);
    }
  };



  return (
    <div ref={dropdownRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <button 
        onClick={() => setIsOpen(!isOpen)} 
        style={{
          background: 'none', border: 'none', color: unreadCount > 0 ? 'var(--accent-color)' : 'var(--text-secondary)',
          cursor: 'pointer', padding: '6px', borderRadius: '50%', position: 'relative', display: 'flex',
          alignItems: 'center', justifyContent: 'center', transition: 'all 0.2s',
          boxShadow: unreadCount > 0 ? '0 0 12px var(--accent-glow)' : 'none'
        }}
        className="hover-glow"
      >
        <Bell size={20} />
        {unreadCount > 0 && (
          <span style={{
            position: 'absolute', top: '0', right: '0', background: 'var(--danger-color)', color: '#fff',
            fontSize: '9px', fontWeight: 800, minWidth: '15px', height: '15px', borderRadius: '10px',
            display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '0 2px',
            border: '1px solid var(--bg-primary)', boxShadow: '0 0 8px var(--danger-glow)'
          }}>
            {unreadCount}
          </span>
        )}
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div 
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            style={{
              position: 'absolute', top: '38px', right: '0', width: '360px',
              background: 'var(--bg-secondary)', backdropFilter: 'blur(20px)',
              border: '1px solid var(--border-color)', borderRadius: '12px',
              boxShadow: 'var(--shadow-card)',
              zIndex: 9999, overflow: 'hidden'
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', borderBottom: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>Security Alerts</span>
                <span
                  title={wsConnected ? 'Live updates connected' : 'Reconnecting… falling back to periodic refresh'}
                  style={{ display: 'flex', alignItems: 'center', color: wsConnected ? 'var(--success-color)' : 'var(--text-secondary)' }}
                >
                  {wsConnected ? <Wifi size={12} /> : <WifiOff size={12} />}
                </span>
              </div>
              {unreadCount > 0 && (
                <button 
                  onClick={handleAckAll}
                  style={{ background: 'none', border: 'none', color: 'var(--accent-color)', fontSize: '12px', cursor: 'pointer', fontWeight: 600 }}
                >
                  Ack All
                </button>
              )}
            </div>

            {/* List */}
            <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
              {history.length > 0 ? (
                history.map(item => (
                  <div 
                    key={item.id} 
                    onClick={() => setSelectedAlert(item)}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0, 212, 255, 0.04)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = item.status !== 'acknowledged' ? 'rgba(0, 212, 255, 0.01)' : 'transparent'}
                    style={{
                      padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)',
                      cursor: 'pointer', transition: 'background 0.2s', display: 'flex', flexDirection: 'column', gap: '4px',
                      background: item.status !== 'acknowledged' ? 'rgba(0, 212, 255, 0.01)' : 'transparent'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>{item.rule_name}</span>
                      <span style={{
                        padding: '1px 6px', borderRadius: '3px', fontSize: '9px', fontWeight: 700, textTransform: 'uppercase',
                        background: item.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)',
                        color: item.severity === 'critical' ? 'var(--danger-color)' : 'var(--warning-color)',
                        border: item.severity === 'critical' ? '1px solid rgba(255, 59, 92, 0.2)' : '1px solid rgba(255, 149, 0, 0.2)'
                      }}>{item.severity}</span>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '12px', margin: 0, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{item.message}</p>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>{formatLocalTime(item.created_at)}</span>
                      {item.status !== 'acknowledged' && (
                        <button 
                          onClick={(e) => handleSingleAck(item.id, e)}
                          style={{
                            background: 'var(--accent-bg)', border: '1px solid var(--accent-border)',
                            color: 'var(--accent-color)', fontSize: '10px', padding: '2px 8px', borderRadius: '4px', cursor: 'pointer',
                            fontWeight: 600
                          }}
                        >
                          Acknowledge
                        </button>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>No warning alerts found.</div>
              )}
            </div>

            {/* Footer */}
            <div style={{
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1px', background: 'var(--border-color)',
              borderTop: '1px solid var(--border-color)', textAlign: 'center'
            }}>
              <button 
                onClick={() => { setIsOpen(false); onOpenHistory(); }}
                style={{
                  background: 'var(--bg-tertiary)', border: 'none', color: 'var(--text-secondary)', padding: '12px 0',
                  fontSize: '12px', cursor: 'pointer', fontWeight: 600, transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-color)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                View History Logs
              </button>
              <button 
                onClick={() => { setIsOpen(false); onOpenSettings(); }}
                style={{
                  background: 'var(--bg-tertiary)', border: 'none', color: 'var(--text-secondary)', padding: '12px 0',
                  fontSize: '12px', cursor: 'pointer', fontWeight: 600, transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-color)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                Alert Config
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Details View Modal */}
      {selectedAlert && (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 5, 9, 0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 100000 }}>
          <div className="modal-content" style={{ background: 'var(--bg-secondary)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-color)', width: '560px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--accent-color)', fontFamily: 'var(--font-display)' }}>Alert details: {selectedAlert.rule_name}</h3>
              <button style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: '18px', cursor: 'pointer' }} onClick={() => setSelectedAlert(null)}>X</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', color: 'var(--text-primary)' }}>
              <p><strong>Trigger message:</strong> {selectedAlert.message}</p>
              <p><strong>Severity:</strong> <span style={{ textTransform: 'uppercase', color: 'var(--accent-color)' }}>{selectedAlert.severity}</span></p>
              <p><strong>Dispatch Status:</strong> <code style={{ color: 'var(--success-color)' }}>{selectedAlert.status}</code></p>
              {selectedAlert.error_message && <p><strong>Dispatch error:</strong> <code style={{ color: 'var(--danger-color)' }}>{selectedAlert.error_message}</code></p>}
              <div><strong>Raw threat payload:</strong></div>
              <pre style={{ background: 'var(--bg-void)', padding: '12px', borderRadius: '6px', overflowY: 'auto', maxHeight: '180px', fontSize: '11px', color: 'var(--success-color)', border: '1px solid var(--border-color)' }}>{JSON.stringify(selectedAlert.event_data, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

