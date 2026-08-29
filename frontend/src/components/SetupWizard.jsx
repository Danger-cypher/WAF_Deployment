import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Server, Bell, CheckCircle, AlertTriangle, ChevronRight, Zap } from 'lucide-react';

const SetupWizard = ({ onComplete }) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [setupData, setSetupData] = useState({
    appName: '',
    appUrl: '',
    protectionLevel: 1,
    enableProtection: true,
    alertEmail: '',
    alertSeverity: 'High'
  });

  const steps = [
    { id: 1, title: 'Protect Your Application', icon: Server },
    { id: 2, title: 'Choose Protection Level', icon: Shield },
    { id: 3, title: 'Configure Alerts', icon: Bell },
    { id: 4, title: "You're Protected!", icon: CheckCircle }
  ];

  const handleNext = () => {
    if (currentStep < 4) {
      setCurrentStep(currentStep + 1);
    } else {
      // Save setup data to localStorage
      localStorage.setItem('waf_setup_complete', 'true');
      localStorage.setItem('waf_setup_data', JSON.stringify(setupData));
      onComplete(setupData);
    }
  };

  const handleSkip = () => {
    localStorage.setItem('waf_setup_complete', 'true');
    onComplete(null);
  };

  const canProceed = () => {
    switch (currentStep) {
      case 1:
        return setupData.appName.trim() && setupData.appUrl.trim();
      case 2:
        return setupData.protectionLevel;
      case 3:
        return true; // Email is optional
      case 4:
        return true;
      default:
        return false;
    }
  };

  return (
    <div className="setup-wizard-overlay">
      <div className="setup-wizard-container">
        
        {/* Header with Progress */}
        <div className="setup-wizard-header">
          <div className="setup-wizard-logo">
            <img src="/Cybersentinel.png" alt="CyberSentinel" style={{ maxHeight: '50px' }} />
          </div>
          <div className="setup-wizard-progress">
            {steps.map((step, index) => (
              <div key={step.id} className="progress-step-wrapper">
                <div className={`progress-step ${currentStep >= step.id ? 'active' : ''} ${currentStep > step.id ? 'completed' : ''}`}>
                  {currentStep > step.id ? (
                    <CheckCircle size={20} />
                  ) : (
                    <span>{step.id}</span>
                  )}
                </div>
                <span className="progress-label">{step.title}</span>
                {index < steps.length - 1 && (
                  <div className={`progress-line ${currentStep > step.id ? 'completed' : ''}`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="setup-wizard-body">
          <AnimatePresence mode="wait">
            
            {/* Step 1: Application Setup */}
            {currentStep === 1 && (
              <motion.div
                key="step1"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="setup-step"
              >
                <div className="step-icon-wrapper">
                  <Server size={48} color="var(--teal-color)" />
                </div>
                <h2>Protect Your Application</h2>
                <p className="step-description">
                  Tell us about the application you want to protect with CyberSentinel WAF
                </p>

                <div className="setup-form">
                  <div className="form-group">
                    <label htmlFor="appName">Application Name</label>
                    <input
                      id="appName"
                      type="text"
                      className="setup-input"
                      placeholder="e.g., My Production API"
                      value={setupData.appName}
                      onChange={(e) => setSetupData({ ...setupData, appName: e.target.value })}
                      autoFocus
                    />
                  </div>

                  <div className="form-group">
                    <label htmlFor="appUrl">Application URL or Domain</label>
                    <input
                      id="appUrl"
                      type="text"
                      className="setup-input"
                      placeholder="e.g., api.example.com or https://example.com"
                      value={setupData.appUrl}
                      onChange={(e) => setSetupData({ ...setupData, appUrl: e.target.value })}
                    />
                  </div>

                  <div className="setup-toggle-wrapper">
                    <div className="toggle-label-group">
                      <Zap size={18} color={setupData.enableProtection ? 'var(--success-color)' : 'var(--text-secondary)'} />
                      <span>Enable Protection Immediately</span>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={setupData.enableProtection}
                      aria-label="Enable Protection Immediately"
                      className={`toggle-switch ${setupData.enableProtection ? 'active' : ''}`}
                      onClick={() => setSetupData({ ...setupData, enableProtection: !setupData.enableProtection })}
                    >
                      <div className="toggle-knob"></div>
                    </button>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Step 2: Protection Level */}
            {currentStep === 2 && (
              <motion.div
                key="step2"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="setup-step"
              >
                <div className="step-icon-wrapper">
                  <Shield size={48} color="var(--teal-color)" />
                </div>
                <h2>Choose Protection Level</h2>
                <p className="step-description">
                  Select how strict you want the firewall to be. You can adjust this anytime.
                </p>

                <div className="protection-level-cards">
                  {[
                    {
                      level: 1,
                      name: 'Balanced',
                      badge: 'Recommended',
                      description: 'Standard protection with minimal false positives',
                      features: ['Core OWASP rules', 'SQL Injection blocking', 'XSS protection', 'Best for most applications']
                    },
                    {
                      level: 2,
                      name: 'Strict',
                      badge: 'Advanced',
                      description: 'Enhanced security with additional rules',
                      features: ['All Balanced features', 'Advanced payload detection', 'Scanner blocking', 'Recommended for APIs']
                    },
                    {
                      level: 3,
                      name: 'Maximum',
                      badge: 'Expert',
                      description: 'Highest security, may require tuning',
                      features: ['All Strict features', 'Extreme filtering', 'Zero-day protection', 'Best for sensitive data']
                    }
                  ].map((option) => (
                    <div
                      key={option.level}
                      className={`protection-card ${setupData.protectionLevel === option.level ? 'selected' : ''}`}
                      onClick={() => setSetupData({ ...setupData, protectionLevel: option.level })}
                    >
                      {option.level === 1 && (
                        <div className="recommended-badge">
                          <CheckCircle size={14} />
                          <span>{option.badge}</span>
                        </div>
                      )}
                      <div className="protection-card-header">
                        <h3>{option.name}</h3>
                        <span className="protection-level-badge">Level {option.level}</span>
                      </div>
                      <p className="protection-card-desc">{option.description}</p>
                      <ul className="protection-features">
                        {option.features.map((feature, idx) => (
                          <li key={idx}>
                            <CheckCircle size={14} />
                            <span>{feature}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}

            {/* Step 3: Alert Configuration */}
            {currentStep === 3 && (
              <motion.div
                key="step3"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="setup-step"
              >
                <div className="step-icon-wrapper">
                  <Bell size={48} color="var(--teal-color)" />
                </div>
                <h2>Configure Alerts</h2>
                <p className="step-description">
                  Get notified when critical security events occur (optional)
                </p>

                <div className="setup-form">
                  <div className="form-group">
                    <label htmlFor="alertEmail">
                      Notification Email <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>(Optional)</span>
                    </label>
                    <input
                      id="alertEmail"
                      type="email"
                      className="setup-input"
                      placeholder="security@example.com"
                      value={setupData.alertEmail}
                      onChange={(e) => setSetupData({ ...setupData, alertEmail: e.target.value })}
                    />
                  </div>

                  <div className="form-group">
                    <label htmlFor="alertSeverity">Minimum Alert Severity</label>
                    <select
                      id="alertSeverity"
                      className="setup-input"
                      value={setupData.alertSeverity}
                      onChange={(e) => setSetupData({ ...setupData, alertSeverity: e.target.value })}
                    >
                      <option value="Critical">Critical Only</option>
                      <option value="High">High & Critical</option>
                      <option value="Medium">Medium, High & Critical</option>
                      <option value="Low">All Threats</option>
                    </select>
                  </div>

                  <div className="info-box">
                    <AlertTriangle size={16} color="var(--warning-color)" />
                    <span>You can configure additional notification channels (Slack, Telegram) later in the Advanced settings.</span>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Step 4: Completion */}
            {currentStep === 4 && (
              <motion.div
                key="step4"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="setup-step setup-complete"
              >
                <motion.div
                  className="success-icon-wrapper"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
                >
                  <CheckCircle size={64} color="var(--success-color)" />
                </motion.div>
                
                <h2>You're Protected!</h2>
                <p className="step-description">
                  CyberSentinel WAF is now actively protecting <strong>{setupData.appName}</strong>
                </p>

                <div className="completion-summary">
                  <div className="summary-item">
                    <span className="summary-label">Application:</span>
                    <span className="summary-value">{setupData.appName}</span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-label">URL:</span>
                    <span className="summary-value">{setupData.appUrl}</span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-label">Protection Level:</span>
                    <span className="summary-value">
                      Level {setupData.protectionLevel} - {setupData.protectionLevel === 1 ? 'Balanced' : setupData.protectionLevel === 2 ? 'Strict' : 'Maximum'}
                    </span>
                  </div>
                  <div className="summary-item">
                    <span className="summary-label">Status:</span>
                    <span className="summary-value status-active">
                      <span className="status-dot"></span>
                      ACTIVE
                    </span>
                  </div>
                </div>

                <div className="completion-features">
                  <h3>What's Protecting Your Application:</h3>
                  <div className="feature-grid">
                    <div className="feature-item">
                      <CheckCircle size={16} color="var(--success-color)" />
                      <span>OWASP Core Rule Set v4.0</span>
                    </div>
                    <div className="feature-item">
                      <CheckCircle size={16} color="var(--success-color)" />
                      <span>AI/ML Threat Detection</span>
                    </div>
                    <div className="feature-item">
                      <CheckCircle size={16} color="var(--success-color)" />
                      <span>Real-time Attack Blocking</span>
                    </div>
                    <div className="feature-item">
                      <CheckCircle size={16} color="var(--success-color)" />
                      <span>24/7 Traffic Monitoring</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

          </AnimatePresence>
        </div>

        {/* Footer with Actions */}
        <div className="setup-wizard-footer">
          {currentStep < 4 ? (
            <>
              <button className="setup-btn secondary" onClick={handleSkip}>
                Skip Setup
              </button>
              <button 
                className="setup-btn primary" 
                onClick={handleNext}
                disabled={!canProceed()}
              >
                {currentStep === 3 ? 'Complete Setup' : 'Continue'}
                <ChevronRight size={18} />
              </button>
            </>
          ) : (
            <button className="setup-btn primary full" onClick={handleNext}>
              <Zap size={18} />
              View Dashboard
            </button>
          )}
        </div>

      </div>
    </div>
  );
};

export default SetupWizard;
