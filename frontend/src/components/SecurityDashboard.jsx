import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, AlertTriangle, Clock, Users, Activity, Lock, Eye, EyeOff, Server, TerminalSquare, Shield, Zap, Brain, Globe } from 'lucide-react';

/* ─── Security Statistics Card ───────────────────────────── */
function SecurityStatsCard({ title, value, subtext, icon: Icon, color }) {
  return (
    <motion.div
      className="security-stat-card"
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      style={{
        padding: '24px',
        background: 'rgba(0,0,0,0.2)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '12px',
        marginBottom: '16px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
        <div style={{
          width: '40px', height: '40px',
          borderRadius: '10px',
          background: `rgba(${color}, 0.15)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: `var(--${color}-color)`,
        }}>
          <Icon size={20} />
        </div>
        <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'rgba(255,255,255,0.7)' }}>
          {title}
        </h3>
      </div>
      <div style={{
        fontSize: '32px',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        color: 'var(--text-color)',
        lineHeight: 1,
        marginBottom: '4px',
      }}>
        {value}
      </div>
      {subtext && (
        <div style={{
          fontSize: '12px',
          color: 'rgba(255,255,255,0.5)',
          fontFamily: 'var(--font-mono)',
        }}>
          {subtext}
        </div>
      )}
    </motion.div>
  );
}

/* ─── Recent Security Events ─────────────────────────────── */
function RecentSecurityEvents({ events, loading }) {
  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '40px', color: 'rgba(255,255,255,0.5)' }}>
        Loading security events...
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '40px', color: 'rgba(255,255,255,0.5)' }}>
        <ShieldCheck size={40} style={{ marginBottom: '16px', opacity: 0.5 }} />
        <p>No recent security events</p>
      </div>
    );
  }

  return (
    <div style={{
      maxHeight: '400px',
      overflowY: 'auto',
      padding: '8px 0',
    }}>
      {events.map((event, i) => (
        <motion.div
          key={i}
          className="security-event-item"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.05 }}
          style={{
            padding: '12px 16px',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div style={{ flex: 1 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              marginBottom: '4px',
            }}>
              <span style={{
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '10px',
                fontWeight: 600,
                textTransform: 'uppercase',
                background: event.level === 'WARNING' ? 'rgba(255,59,92,0.15)' : 'rgba(0,212,255,0.15)',
                color: event.level === 'WARNING' ? 'var(--danger-color)' : 'var(--accent-color)',
              }}>
                {event.event_type}
              </span>
              <span style={{
                fontSize: '11px',
                color: 'rgba(255,255,255,0.6)',
                fontFamily: 'var(--font-mono)',
              }}>
                {new Date(event.timestamp).toLocaleString()}
              </span>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-color)' }}>
              {event.client_ip && (
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)' }}>
                  {event.client_ip}
                </span>
              )}
              {event.event_type === 'AUTH_ATTEMPT' && (
                <span> - {event.success ? 'Success' : 'Failed'} login for {event.username}</span>
              )}
              {event.event_type === 'RATE_LIMIT_TRIGGER' && (
                <span> - Rate limit exceeded ({event.attempts} attempts, blocked for {event.block_duration_seconds}s)</span>
              )}
            </div>
          </div>
          {event.event_type === 'AUTH_ATTEMPT' && !event.success && (
            <AlertTriangle size={16} color="var(--danger-color)" />
          )}
        </motion.div>
      ))}
    </div>
  );
}

/* ─── Security Dashboard Component ───────────────────────── */
export default function SecurityDashboard() {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSecurityData();
  }, []);

  const fetchSecurityData = async () => {
    try {
      const [statsRes, eventsRes] = await Promise.all([
        fetch('/api/security/statistics?hours=24'),
        fetch('/api/security/events?hours=24&limit=50'),
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData.events || []);
      }
    } catch (error) {
      console.error('Failed to fetch security data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="security-dashboard">
      <div className="dashboard-header">
        <h2>
          <Shield size={24} />
          <span>Security Audit Dashboard</span>
        </h2>
        <button
          onClick={fetchSecurityData}
          disabled={loading}
          style={{
            padding: '8px 16px',
            background: 'var(--accent-color)',
            border: 'none',
            borderRadius: '8px',
            color: '#000',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Activity size={16} />
          Refresh
        </button>
      </div>

      {loading && !stats && (
        <div style={{ textAlign: 'center', padding: '40px', color: 'rgba(255,255,255,0.5)' }}>
          Loading security metrics...
        </div>
      )}

      {stats && (
        <div className="security-stats-grid">
          <SecurityStatsCard
            title="Total Security Events"
            value={stats.total_events.toLocaleString()}
            subtext="Last 24 hours"
            icon={ShieldAlert}
            color="danger"
          />
          
          <SecurityStatsCard
            title="Unique IPs"
            value={stats.unique_ips.length.toLocaleString()}
            subtext="Distinct sources"
            icon={Users}
            color="accent"
          />

          {stats.by_type && (
            <>
              <SecurityStatsCard
                title="Auth Attempts"
                value={stats.by_type.AUTH_ATTEMPT?.toLocaleString() || '0'}
                subtext="Login attempts"
                icon={Lock}
                color={stats.by_type.AUTH_ATTEMPT > 10 ? 'danger' : 'success'}
              />
              
              <SecurityStatsCard
                title="Rate Limit Triggers"
                value={stats.by_type.RATE_LIMIT_TRIGGER?.toLocaleString() || '0'}
                subtext="Blocked attempts"
                icon={AlertTriangle}
                color="danger"
              />

              <SecurityStatsCard
                title="Input Validation Failures"
                value={stats.by_type.INPUT_VALIDATION_FAILURE?.toLocaleString() || '0'}
                subtext="Malicious requests"
                icon={Shield}
                color="orange"
              />
            </>
          )}
        </div>
      )}

      <div style={{
        marginTop: '24px',
        padding: '20px',
        background: 'rgba(0,0,0,0.2)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '12px',
      }}>
        <h3 style={{ margin: '0 0 16px', fontSize: '16px', fontWeight: 600 }}>
          Recent Security Events
        </h3>
        <RecentSecurityEvents events={events} loading={loading} />
      </div>

      {/* CSS styles */}
      <style>{`
        .security-dashboard {
          padding: 24px;
        }

        .dashboard-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
        }

        .dashboard-header h2 {
          display: flex;
          align-items: center;
          gap: 12px;
          margin: 0;
          font-size: 24px;
          font-weight: 700;
          color: var(--text-color);
        }

        .dashboard-header h2 svg {
          color: var(--accent-color);
        }

        .security-stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
          margin-bottom: 24px;
        }

        .security-event-item:hover {
          background: rgba(255,255,255,0.02);
        }
      `}</style>
    </div>
  );
}
