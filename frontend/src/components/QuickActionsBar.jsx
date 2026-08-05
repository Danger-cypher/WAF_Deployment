import { Plus, Shield, RefreshCw, Activity } from 'lucide-react';

// QuickActionsBar renders only contextual actions relevant to the active tab.
// WAF Active status pill is shown ONLY on the overview/dashboard tab.
// The entire bar hides itself when there are no actions to show.
const QuickActionsBar = ({ activeTab, onAddApp, onViewBlocks, onRefresh }) => {
  const hasAddApp    = activeTab === 'protection' && !!onAddApp;
  const hasBlocks    = activeTab === 'events' && !!onViewBlocks;
  const hasRefresh   = !!onRefresh;
  const showWafPill  = activeTab === 'overview';

  // Nothing to show — don't render the bar at all
  if (!hasAddApp && !hasBlocks && !hasRefresh && !showWafPill) return null;

  return (
    <div className="quick-actions-bar">
      <div className="quick-actions-container">

        {/* Add Application — Protection tab only */}
        {hasAddApp && (
          <button
            className="quick-action-btn primary"
            onClick={onAddApp}
            title="Add a new protected application"
          >
            <Plus size={16} />
            <span>Add Application</span>
          </button>
        )}

        {/* View Blocked Threats — Events tab only */}
        {hasBlocks && (
          <button
            className="quick-action-btn secondary"
            onClick={onViewBlocks}
            title="View blocked threats"
          >
            <Shield size={16} />
            <span>View Blocked Threats</span>
          </button>
        )}

        {/* Manual refresh — only if handler is provided */}
        {hasRefresh && (
          <button
            className="quick-action-btn secondary"
            onClick={onRefresh}
            title="Refresh data"
          >
            <RefreshCw size={16} />
            <span>Refresh</span>
          </button>
        )}

        {/* WAF Active status — Dashboard only, compact pill on the right */}
        {showWafPill && (
          <div
            className="quick-action-status"
            style={{ marginLeft: 'auto' }}
            title="CyberSentinel WAF Engine is running and enforcing policies"
          >
            <Activity size={13} style={{ color: '#10b981' }} />
            <div className="pulse-dot" style={{ marginLeft: '4px', marginRight: '4px' }} />
            <span>WAF Active</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default QuickActionsBar;
