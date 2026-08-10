import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck } from 'lucide-react';
import {
  getCurrentUser, logoutUser, markFalsePositive, updateFalsePositiveStatus, createExclusion,
} from './services/api';

import Login from './components/Login';
import Sidebar from './components/Sidebar';
import NotificationBell from './components/NotificationBell';
import AlertHistoryModal from './components/AlertHistoryModal';
import SetupWizard from './components/SetupWizard';
import ProtectedAppWizard from './components/ProtectedAppWizard';
import SecurityReports from './components/SecurityReports';
import UserManagement from './components/UserManagement';
import Profile from './components/Profile';

import ThreatAnalytics from './pages/Overview';
import ProtectionSection from './pages/ProtectionSection';
import LiveLogs from './pages/Events';
import MLAnalytics from './pages/MLEngine';
import FalsePositives, { FlagFpModal } from './pages/FalsePositives';
import Exceptions, { CreateExceptionModal } from './pages/Exceptions';
import Rules from './pages/Rules';
import ApiProtection from './pages/ApiProtection';
import AlertsIntegrations from './pages/AlertsIntegrations';
import CustomRulesEditor from './pages/VirtualPatching';
import Settings from './pages/Settings';

import './index.css';

const TAB_ROUTES = {
  overview:         '/dashboard',
  protection:       '/protection',
  events:           '/events',
  ml_engine:        '/ml-engine',
  // Former Advanced sub-tabs — now direct routes
  false_positives:  '/false-positives',
  exceptions:       '/exceptions',
  rules:            '/rules',
  api_protection:   '/api-protection',
  reports:          '/reports',
  integrations:     '/integrations',
  virtual_patching: '/virtual-patching',
  users:            '/users',
  settings:         '/settings',
};
const ROUTE_TABS = Object.fromEntries(
  Object.entries(TAB_ROUTES).map(([tab, path]) => [path, tab])
);
function getTabFromPath() {
  const path = window.location.pathname;
  return ROUTE_TABS[path] || 'overview';
}

function App() {
  const [activeTab, setActiveTabState] = useState(getTabFromPath());
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState(null);
  const [username, setUsername] = useState(null);
  const [showProfile, setShowProfile] = useState(false);
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [, setSetupComplete] = useState(false);
  const [showAppWizard, setShowAppWizard] = useState(false);
  const [editingApp, setEditingApp] = useState(null);
  const [appsRefreshKey, setAppsRefreshKey] = useState(0);
  const [logToFlag, setLogToFlag] = useState(null);
  const [isFpModalOpen, setIsFpModalOpen] = useState(false);
  const [logToExclude, setLogToExclude] = useState(null);
  const [isExceptionModalOpen, setIsExceptionModalOpen] = useState(false);
  const [globalSuccessMsg, setGlobalSuccessMsg] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isAlertHistoryModalOpen, setIsAlertHistoryModalOpen] = useState(false);
  const [, setAdvancedInitialTab] = useState('false_positives');

  // Wrapper that syncs tab state + URL together
  const setActiveTab = (tabId) => {
    const path = TAB_ROUTES[tabId] || '/dashboard';
    window.history.pushState({ tab: tabId }, '', path);
    setActiveTabState(tabId);
    if (tabId !== 'advanced') {
      setAdvancedInitialTab('false_positives');
    }
  };

  // Handle browser back/forward buttons
  useEffect(() => {
    const onPopState = (e) => {
      const tab = (e.state && e.state.tab) || getTabFromPath();
      setActiveTabState(tab);
    };
    window.addEventListener('popstate', onPopState);
    // Replace the current history entry with proper state so back works from page 1
    window.history.replaceState(
      { tab: activeTab },
      '',
      TAB_ROUTES[activeTab] || '/dashboard'
    );
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const handleTriggerMarkFp = (log) => {
    setLogToFlag(log);
    setIsFpModalOpen(true);
  };

  const handleTriggerCreateException = (log) => {
    setLogToExclude(log);
    setIsExceptionModalOpen(true);
  };

  const handleSaveFalsePositive = async (logId, note) => {
    try {
      await markFalsePositive(logId, note);
      setGlobalSuccessMsg("Log entry marked as False Positive!");
      setTimeout(() => setGlobalSuccessMsg(''), 3000);
    } catch (err) {
      console.error("Failed to flag false positive", err);
      alert(err.message || "Failed to mark false positive entry.");
    }
  };

  const handleSaveException = async (payload) => {
    try {
      await createExclusion(payload);
      setGlobalSuccessMsg("Exception policy created & WAF synchronized!");
      setTimeout(() => setGlobalSuccessMsg(''), 3000);

      if (payload.false_positive_id) {
        await updateFalsePositiveStatus(payload.false_positive_id, 'Resolved');
      }
    } catch (err) {
      console.error("Failed to apply WAF exception", err);
      alert(err.message || "Failed to commit exclusion rule.");
    }
  };

  const handleLogout = async () => {
    try {
      await logoutUser();
    } catch {
      console.warn("Logout request failed or already logged out");
    }
    window.history.pushState({}, '', '/');
    setIsAuthenticated(false);
    setUserRole(null);
    setUsername(null);
  };

  useEffect(() => {
    const handleUnauthorized = () => {
      handleLogout();
    };
    window.addEventListener('waf-unauthorized', handleUnauthorized);

    let timer = null;

    getCurrentUser()
      .then(user => {
        timer = setTimeout(() => {
          setIsAuthenticated(true);
          setUserRole(user.role || 'analyst');
          setUsername(user.username || 'user');
          
          // Check if this is first-time setup
          const setupCompleteFlag = localStorage.getItem('waf_setup_complete');
          if (!setupCompleteFlag) {
            setShowSetupWizard(true);
          } else {
            setSetupComplete(true);
          }
        }, 0);
      })
      .catch(() => {
        timer = setTimeout(() => {
          handleLogout();
        }, 0);
      });

    return () => {
      window.removeEventListener('waf-unauthorized', handleUnauthorized);
      if (timer) clearTimeout(timer);
    };
  }, []);

  useEffect(() => {
    if (activeTab === 'settings' && userRole === 'analyst') {
      const timer = setTimeout(() => {
        setActiveTab('analytics');
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [activeTab, userRole]);

  if (!isAuthenticated) {
    return (
      <Login
        setAuth={setIsAuthenticated}
        onLoginSuccess={(user) => {
          // Set role immediately from login response so Settings tab
          // appears without requiring a page reload.
          setUserRole(user.role || 'analyst');
          setUsername(user.username || 'user');
        }}
      />
    );
  }


  // Show setup wizard for first-time users
  if (showSetupWizard) {
    return (
      <SetupWizard 
        onComplete={(setupData) => {
          setShowSetupWizard(false);
          setSetupComplete(true);
          console.log('Setup completed with data:', setupData);
        }}
      />
    );
  }

  return (
    <>
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} handleLogout={handleLogout} userRole={userRole} collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />
      <div className={`main-content ${sidebarCollapsed ? 'expanded' : ''}`}>
        {/* SIEM Professional Top Bar */}
        <div className="siem-topbar">
          <div className="siem-topbar-left">
            <span className="siem-breadcrumb-sep">■</span>
            <span className="siem-breadcrumb">
              {activeTab === 'overview' && 'Security Overview'}
              {activeTab === 'protection' && 'Protection Status'}
              {activeTab === 'events' && 'Security Events'}
              {activeTab === 'ml_engine' && 'AI / ML Engine'}
              {activeTab === 'false_positives' && 'False Positives'}
              {activeTab === 'exceptions' && 'WAF Exceptions'}
              {activeTab === 'rules' && 'WAF Rules & CRS'}
              {activeTab === 'api_protection' && 'API Protection'}
              {activeTab === 'reports' && 'Security Reports'}
              {activeTab === 'integrations' && 'Alerts & Integrations'}
              {activeTab === 'virtual_patching' && 'Virtual Patching'}
              {activeTab === 'users' && 'User Management'}
              {activeTab === 'settings' && 'System Settings'}
            </span>
          </div>
          <div className="siem-topbar-right">
            {/* WAF Active status badge */}
            <div className="siem-status-badge active">
              <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
              WAF Active
            </div>
            <NotificationBell
              userRole={userRole}
              onOpenHistory={() => setIsAlertHistoryModalOpen(true)}
              onOpenSettings={() => setActiveTab('integrations')}
            />
            <div
              className="user-profile-badge"
              onClick={() => setShowProfile(true)}
              title="View profile"
              style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', padding: '5px 12px', borderRadius: '20px', cursor: 'pointer' }}
            >
              <span style={{ fontSize: '12px', color: '#64748b', fontWeight: 500 }}>@{username}</span>
              <span style={{
                fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '10px', textTransform: 'uppercase',
                background: userRole === 'admin' ? 'rgba(244,63,94,0.15)' : 'rgba(99,102,241,0.15)',
                color: userRole === 'admin' ? '#fca5a5' : '#a5b4fc',
                border: userRole === 'admin' ? '1px solid rgba(244,63,94,0.3)' : '1px solid rgba(99,102,241,0.3)'
              }}>{userRole}</span>
            </div>
          </div>
        </div>
        {/* Scrollable page content area */}
        <div className="main-scroll-area">
        <motion.div
          style={{ flex: 1, minHeight: 0 }}
          key={activeTab}
          initial={{ opacity: 0, x: 15 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -15 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        >
          {/* Overview Tab */}
          {activeTab === 'overview' && <ThreatAnalytics key="overview" />}

          {/* Protection Status Tab */}
          {activeTab === 'protection' && (
            <ProtectionSection
              key="protection"
              appsRefreshKey={appsRefreshKey}
              onOpenWizard={(app) => { setEditingApp(app); setShowAppWizard(true); }}
            />
          )}
          
          {/* Security Events Tab */}
          {activeTab === 'events' && <LiveLogs key="events" onMarkFalsePositive={handleTriggerMarkFp} />}
          
          {/* AI/ML Engine Tab */}
          {activeTab === 'ml_engine' && <MLAnalytics key="ml_engine" />}

          {/* False Positives Tab */}
          {activeTab === 'false_positives' && (
            <FalsePositives key="false_positives" userRole={userRole} onCreateException={handleTriggerCreateException} />
          )}

          {/* Exceptions Tab */}
          {activeTab === 'exceptions' && <Exceptions key="exceptions" />}

          {/* WAF Rules Tab */}
          {activeTab === 'rules' && <Rules key="rules" userRole={userRole} />}

          {/* API Protection Tab */}
          {activeTab === 'api_protection' && <ApiProtection key="api_protection" />}

          {/* Security Reports Tab */}
          {activeTab === 'reports' && <SecurityReports key="reports" />}

          {/* Alerts & Integrations Tab */}
          {activeTab === 'integrations' && <AlertsIntegrations key="integrations" userRole={userRole} />}

          {/* Virtual Patching (Custom Rules) Tab - Admin only */}
          {activeTab === 'virtual_patching' && userRole === 'admin' && (
            <CustomRulesEditor key="virtual_patching" userRole={userRole} />
          )}

          {/* User Management Tab - Admin only */}
          {activeTab === 'users' && userRole === 'admin' && (
            <UserManagement key="users" currentUsername={username} />
          )}

          {/* Settings Tab - Admin only */}
          {activeTab === 'settings' && userRole === 'admin' && (
            <Settings key="settings" onLogout={handleLogout} />
          )}
        </motion.div>

        <AlertHistoryModal
          isOpen={isAlertHistoryModalOpen}
          onClose={() => setIsAlertHistoryModalOpen(false)}
          userRole={userRole}
        />

        <FlagFpModal
          isOpen={isFpModalOpen}
          log={logToFlag}
          onClose={() => {
            setIsFpModalOpen(false);
            setLogToFlag(null);
          }}
          onSubmit={handleSaveFalsePositive}
        />

        <CreateExceptionModal
          isOpen={isExceptionModalOpen}
          log={logToExclude}
          onClose={() => {
            setIsExceptionModalOpen(false);
            setLogToExclude(null);
          }}
          onSubmit={handleSaveException}
        />

        <ProtectedAppWizard
          isOpen={showAppWizard}
          onClose={() => {
            setShowAppWizard(false);
            setEditingApp(null);
          }}
          existingApp={editingApp}
          onComplete={() => {
            setShowAppWizard(false);
            setEditingApp(null);
            setAppsRefreshKey(prev => prev + 1);
          }}
        />

        <AnimatePresence>
          {showProfile && (
            <Profile onClose={() => setShowProfile(false)} />
          )}
        </AnimatePresence>

        <AnimatePresence>
          {globalSuccessMsg && (
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              style={{
                position: 'fixed', top: '24px', right: '24px', background: '#10b981', color: '#000',
                padding: '12px 24px', borderRadius: '8px', zIndex: 10000, fontWeight: 600, display: 'flex', gap: '8px', alignItems: 'center',
                boxShadow: '0 10px 15px -3px rgba(16, 185, 129, 0.4)'
              }}
            >
              <ShieldCheck size={18} />
              <span>{globalSuccessMsg}</span>
            </motion.div>
          )}
        </AnimatePresence>

      </div>{/* end main-scroll-area */}
      </div>{/* end main-content */}
    </div>{/* end app-container */}

    {/* App-wide fixed footer */}
    <footer className="app-footer">
      <div className="footer-left">
        <img src="/Virtual_logo.png" alt="Virtual Galaxy" className="footer-logo" />
        <div className="footer-divider" />
        <span>Information Technology Services Management</span>
      </div>
      <div className="footer-center">
        <span>© 2026 Virtual Galaxy Ltd. All Rights Reserved.</span>
      </div>
      <div className="footer-right">
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--accent-color)' }}>v2.0.0-2026</span>
        <div className="footer-divider" />
        <a href="#support">Support</a>
        <div className="footer-divider" />
        <a href="#privacy">Privacy Policy</a>
      </div>
    </footer>
    </>
  );
}

export default App;
