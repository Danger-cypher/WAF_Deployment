import { Shield, Activity, Clock, Search, AlertTriangle, CheckCircle, Zap } from 'lucide-react';

export const NoTrafficEmptyState = ({ onTestWaf, onViewApps }) => (
  <div className="empty-state-container">
    <div className="empty-state-content">
      <div className="empty-state-icon pulse-slow">
        <Shield size={64} color="#14b8a6" />
      </div>
      <h2 className="empty-state-title">CyberSentinel is Protecting Your Application</h2>
      <p className="empty-state-description">
        Your WAF is active and monitoring traffic. Once requests start flowing through your application, 
        you'll see real-time analytics and security events here.
      </p>
      
      <div className="empty-state-status">
        <div className="status-item-large">
          <div className="pulse-dot"></div>
          <span>WAF Engine: Active</span>
        </div>
        <div className="status-item-large">
          <div className="pulse-dot"></div>
          <span>AI/ML Detection: Online</span>
        </div>
        <div className="status-item-large">
          <div className="pulse-dot"></div>
          <span>Monitoring: Enabled</span>
        </div>
      </div>

      <div className="empty-state-actions">
        {onViewApps && (
          <button className="empty-state-btn primary" onClick={onViewApps}>
            <Shield size={18} />
            View Protected Apps
          </button>
        )}
        {onTestWaf && (
          <button className="empty-state-btn secondary" onClick={onTestWaf}>
            <Zap size={18} />
            Test WAF Protection
          </button>
        )}
      </div>

      <div className="empty-state-info">
        <Clock size={14} />
        <span>Waiting for first requests...</span>
      </div>
    </div>
  </div>
);

export const NoLogsEmptyState = () => (
  <div className="empty-state-container compact">
    <div className="empty-state-content">
      <div className="empty-state-icon">
        <CheckCircle size={48} color="#10b981" />
      </div>
      <h3 className="empty-state-title">No Security Events Detected</h3>
      <p className="empty-state-description">
        Great news! No malicious traffic has been blocked yet. Your application is secure.
      </p>
      <div className="empty-state-info">
        <Activity size={14} />
        <span>Monitoring all incoming requests</span>
      </div>
    </div>
  </div>
);

export const NoSearchResultsEmptyState = ({ searchTerm, onClear }) => (
  <div className="empty-state-container compact">
    <div className="empty-state-content">
      <div className="empty-state-icon">
        <Search size={48} color="#6b7280" />
      </div>
      <h3 className="empty-state-title">No Results Found</h3>
      <p className="empty-state-description">
        No events match your search criteria: <strong>"{searchTerm}"</strong>
      </p>
      {onClear && (
        <button className="empty-state-btn secondary" onClick={onClear}>
          Clear Filters
        </button>
      )}
    </div>
  </div>
);

export const NoFalsePositivesEmptyState = () => (
  <div className="empty-state-container compact">
    <div className="empty-state-content">
      <div className="empty-state-icon">
        <CheckCircle size={48} color="#10b981" />
      </div>
      <h3 className="empty-state-title">No False Positives Reported</h3>
      <p className="empty-state-description">
        When legitimate requests are incorrectly blocked, you can mark them as false positives here for WAF tuning.
      </p>
      <div className="empty-state-info">
        <AlertTriangle size={14} />
        <span>WAF rules are well-tuned for your traffic patterns</span>
      </div>
    </div>
  </div>
);

export const NoExceptionsEmptyState = () => (
  <div className="empty-state-container compact">
    <div className="empty-state-content">
      <div className="empty-state-icon">
        <Shield size={48} color="#14b8a6" />
      </div>
      <h3 className="empty-state-title">No Exception Rules Active</h3>
      <p className="empty-state-description">
        Exception rules allow you to selectively bypass WAF filters for specific endpoints or parameters. 
        Create exceptions from false positive reports.
      </p>
    </div>
  </div>
);

export const NoMLEventsEmptyState = () => (
  <div className="empty-state-container compact">
    <div className="empty-state-content">
      <div className="empty-state-icon pulse-slow">
        <Activity size={48} color="#6366f1" />
      </div>
      <h3 className="empty-state-title">AI/ML Engine Initializing</h3>
      <p className="empty-state-description">
        The machine learning threat detection engine is active and analyzing traffic patterns. 
        Evaluation results will appear here once requests are processed.
      </p>
      <div className="empty-state-status">
        <div className="status-item-large">
          <div className="pulse-dot"></div>
          <span>XGBoost Classifier: Ready</span>
        </div>
        <div className="status-item-large">
          <div className="pulse-dot"></div>
          <span>Isolation Forest: Ready</span>
        </div>
      </div>
    </div>
  </div>
);
