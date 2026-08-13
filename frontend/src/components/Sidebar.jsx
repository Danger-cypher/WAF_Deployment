import React from 'react';
import {
  LayoutDashboard, Activity, ShieldCheck, ShieldAlert, AlertTriangle, Brain, FileText,
  Globe, BarChart2, Bell, Code, Users, Settings as SettingsIcon, ChevronRight, ChevronLeft,
  Clock, LogOut,
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, handleLogout, userRole, collapsed, setCollapsed, recentThreats = 0 }) {
  const [currentTime, setCurrentTime] = React.useState(new Date());

  React.useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const isAdmin = userRole === 'admin';

  const navGroups = [
    {
      label: 'MONITORING',
      items: [
        { id: 'overview',  label: 'Overview',        icon: LayoutDashboard },
        { id: 'events',    label: 'Security Events',  icon: Activity, badge: recentThreats > 0 ? recentThreats : null },
      ]
    },
    {
      label: 'PROTECTION',
      items: [
        { id: 'protection',      label: 'Protection Status', icon: ShieldCheck },
        { id: 'false_positives', label: 'False Positives',   icon: ShieldAlert },
        { id: 'exceptions',      label: 'Exceptions',        icon: AlertTriangle },
      ]
    },
    {
      label: 'ANALYSIS',
      items: [
        { id: 'ml_engine',      label: 'AI / ML Engine',    icon: Brain },
        { id: 'rules',          label: 'WAF Rules',          icon: FileText },
        { id: 'api_protection', label: 'API Protection',     icon: Globe },
        { id: 'reports',        label: 'Security Reports',   icon: BarChart2 },
      ]
    },
    {
      label: 'SYSTEM',
      items: [
        { id: 'integrations',    label: 'Alerts & Integrations', icon: Bell },
        ...(isAdmin ? [
          { id: 'virtual_patching', label: 'Virtual Patching', icon: Code, adminOnly: true },
          { id: 'users',            label: 'User Management',  icon: Users, adminOnly: true },
          { id: 'settings',         label: 'Settings',          icon: SettingsIcon, adminOnly: true },
        ] : []),
      ]
    }
  ];

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
                  {item.badge && !collapsed && (
                    <span className="nav-badge">{item.badge > 99 ? '99+' : item.badge}</span>
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
