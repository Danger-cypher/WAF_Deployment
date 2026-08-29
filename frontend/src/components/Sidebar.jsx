import React from 'react';
import { ChevronRight, ChevronLeft, Clock, LogOut } from 'lucide-react';
import { getNavGroups } from '../navigation';

export default function Sidebar({ activeTab, setActiveTab, handleLogout, userRole, collapsed, setCollapsed, recentThreats = 0 }) {
  const [currentTime, setCurrentTime] = React.useState(new Date());

  React.useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const isAdmin = userRole === 'admin';
  const navGroups = getNavGroups(isAdmin);

  const ToggleIcon = collapsed ? ChevronRight : ChevronLeft;

  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Brand */}
      <div className="sidebar-brand">
        <img
          src="/WAFlogo.ico"
          alt="WAF Logo"
          style={{ height: collapsed ? '26px' : '34px', width: collapsed ? '26px' : '34px', objectFit: 'contain', flexShrink: 0 }}
          className="brand-icon"
        />
        {!collapsed && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', minWidth: 0 }}>
            <span className="brand-text">CyberSentinel</span>
            <span className="sidebar-brand-subtitle">WAF ENGINE · v2.0</span>
          </div>
        )}
        <div
          onClick={() => setCollapsed(!collapsed)}
          className="sidebar-toggle"
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          <ToggleIcon size={12} />
        </div>
      </div>

      {/* Navigation Groups */}
      <div className="nav-menu nav-menu-scroll">
        {navGroups.map((group) => (
          <div key={group.label}>
            {!collapsed && (
              <div className="sidebar-section-label">{group.label}</div>
            )}
            {group.items.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.id}
                  className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(item.id)}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon size={16} />
                  <span>{item.label}</span>
                  {/* Threat count badge */}
                  {item.hasBadge && recentThreats > 0 && !collapsed && (
                    <span className="nav-badge">{recentThreats > 99 ? '99+' : recentThreats}</span>
                  )}
                  {/* Admin-only amber badge */}
                  {item.adminOnly && !collapsed && (
                    <span style={{
                      fontSize: '9px', fontWeight: 700, padding: '1px 5px',
                      borderRadius: '4px', background: 'rgba(245,158,11,0.15)',
                      color: 'var(--warning-color)', border: '1px solid rgba(245,158,11,0.25)',
                      fontFamily: 'var(--font-mono)', letterSpacing: '0.5px',
                      marginLeft: 'auto', flexShrink: 0
                    }}>ADM</span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>


      {/* Footer */}
      <div className="sidebar-footer">
        {!collapsed && (
          <div style={{ padding: '6px 20px 2px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Clock size={11} color="var(--chart-axis)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              {currentTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
          </div>
        )}
        <div className="nav-item" onClick={handleLogout} title={collapsed ? 'Logout' : undefined}>
          <LogOut size={16} />
          <span>Logout</span>
        </div>
      </div>
    </div>
  );
}
