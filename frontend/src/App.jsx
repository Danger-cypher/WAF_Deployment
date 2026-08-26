import { useState, useEffect, Suspense, lazy } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, Activity } from 'lucide-react';
import {
  getCurrentUser, logoutUser, markFalsePositive, updateFalsePositiveStatus, createExclusion,
} from './services/api';

import Login from './components/Login';
import SsoCallback from './components/SsoCallback';
import Sidebar from './components/Sidebar';
import NotificationBell from './components/NotificationBell';
import AccountMenu from './components/AccountMenu';

import './index.css';

// Code-split everything except core chrome (Login/Sidebar/NotificationBell/
// AccountMenu render on every authenticated screen) and the tabs/modals
// below, which only cost a network round-trip once the user actually
// reaches them instead of bloating the initial bundle.
const AlertHistoryModal = lazy(() => import('./components/AlertHistoryModal'));
const SetupWizard = lazy(() => import('./components/SetupWizard'));
const ProtectedAppWizard = lazy(() => import('./components/ProtectedAppWizard'));
const SecurityReports = lazy(() => import('./components/SecurityReports'));
const UserManagement = lazy(() => import('./components/UserManagement'));
const Profile = lazy(() => import('./components/Profile'));

const ThreatAnalytics = lazy(() => import('./pages/Overview'));
const ProtectionSection = lazy(() => import('./pages/ProtectionSection'));
const LiveLogs = lazy(() => import('./pages/Events'));
const MLAnalytics = lazy(() => import('./pages/MLEngine'));
const FalsePositives = lazy(() => import('./pages/FalsePositives'));
const FlagFpModal = lazy(() => import('./pages/FalsePositives').then((m) => ({ default: m.FlagFpModal })));
const Exceptions = lazy(() => import('./pages/Exceptions'));
const CreateExceptionModal = lazy(() => import('./pages/Exceptions').then((m) => ({ default: m.CreateExceptionModal })));
const Rules = lazy(() => import('./pages/Rules'));
const ApiProtection = lazy(() => import('./pages/ApiProtection'));
const AlertsIntegrations = lazy(() => import('./pages/AlertsIntegrations'));
const CustomRulesEditor = lazy(() => import('./pages/VirtualPatching'));
const Settings = lazy(() => import('./pages/Settings'));

function TabLoadingFallback() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: 'var(--text-secondary)', gap: '12px' }}>
      <Activity className="animate-spin" size={24} color="var(--accent-color)" />
      <span>Loading...</span>
    </div>
  );
}

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
    // SsoCallback owns auth on this route — it hasn't exchanged the token
    // yet, so getCurrentUser() below would 401 and its handleLogout()
    // would clobber the URL (and the token still in the hash) before the
    // exchange gets a chance to run.
    if (window.location.pathname === '/auth/sso') return;

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

  if (window.location.pathname === '/auth/sso') {
    return (
      <SsoCallback
        setAuth={setIsAuthenticated}
        onLoginSuccess={(user) => {
          setUserRole(user.role || 'analyst');
          setUsername(user.username || 'user');
        }}
      />
    );
  }

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
      <Suspense fallback={<TabLoadingFallback />}>
        <SetupWizard
          onComplete={() => {
            setShowSetupWizard(false);
            setSetupComplete(true);
          }}
        />
      </Suspense>
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
            <AccountMenu
              username={username}
              userRole={userRole}
              onOpenProfile={() => setShowProfile(true)}
              onLogout={handleLogout}
            />
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
        <Suspense fallback={<TabLoadingFallback />}>
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
        </Suspense>
        </motion.div>

        {isAlertHistoryModalOpen && (
          <Suspense fallback={null}>
            <AlertHistoryModal
              isOpen={isAlertHistoryModalOpen}
              onClose={() => setIsAlertHistoryModalOpen(false)}
              userRole={userRole}
            />
          </Suspense>
        )}

        {isFpModalOpen && (
          <Suspense fallback={null}>
            <FlagFpModal
              isOpen={isFpModalOpen}
              log={logToFlag}
              onClose={() => {
                setIsFpModalOpen(false);
                setLogToFlag(null);
              }}
              onSubmit={handleSaveFalsePositive}
            />
          </Suspense>
        )}

        {isExceptionModalOpen && (
          <Suspense fallback={null}>
            <CreateExceptionModal
              isOpen={isExceptionModalOpen}
              log={logToExclude}
              onClose={() => {
                setIsExceptionModalOpen(false);
                setLogToExclude(null);
              }}
              onSubmit={handleSaveException}
            />
          </Suspense>
        )}

        {showAppWizard && (
          <Suspense fallback={null}>
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
          </Suspense>
        )}

        <AnimatePresence>
          {showProfile && (
            <Suspense fallback={null}>
              <Profile onClose={() => setShowProfile(false)} />
            </Suspense>
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
