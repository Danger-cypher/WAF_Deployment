import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Server, Lock, Globe, CheckCircle, AlertTriangle, ChevronRight, Copy, Check, ExternalLink, RefreshCw } from 'lucide-react';

const ProtectedAppWizard = ({ isOpen, onClose, onComplete, existingApp = null }) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployStage, setDeployStage] = useState(''); // 'saving' | 'provisioning' | 'done'
  const [dnsStatus, setDnsStatus] = useState('pending'); // pending, checking, success, failed
  const [copied, setCopied] = useState(false);
  
  const [formData, setFormData] = useState({
    appName: '',
    publicDomain: '',
    backendHost: '',
    backendPort: '80',
    backendProtocol: 'http',
    sslOption: 'letsencrypt',
    protectionLevel: 1,
    customCert: null,
    customKey: null,
    rateLimitRps: '50',
    burstTolerance: '100'
  });

  const [wafServerIP, setWafServerIP] = useState('Loading...');

  useEffect(() => {
    if (isOpen && existingApp) {
      setFormData({
        appName: existingApp.name || '',
        publicDomain: existingApp.domain || '',
        backendHost: existingApp.backend_host || '',
        backendPort: existingApp.backend_port || '80',
        backendProtocol: existingApp.backend_protocol || 'http',
        sslOption: existingApp.ssl_option || 'letsencrypt',
        protectionLevel: existingApp.protection_level || 1,
        customCert: null,
        customKey: null,
        rateLimitRps: existingApp.rate_limit_rps || '50',
        burstTolerance: existingApp.burst_tolerance || '100'
      });
    }
  }, [isOpen, existingApp]);

  useEffect(() => {
    if (isOpen) {
      // Fetch WAF server public IP
      fetch(`${window.location.protocol}//${window.location.host}/api/system/waf-ip`, {
        credentials: 'include'
      })
        .then(res => res.json())
        .then(data => setWafServerIP(data.public_ip || data.server_ip || 'N/A'))
        .catch(() => setWafServerIP(window.location.hostname));
    }
  }, [isOpen]);

  const steps = [
    { id: 1, title: 'Application Details', icon: Globe },
    { id: 2, title: 'Backend Configuration', icon: Server },
    { id: 3, title: 'SSL/TLS Setup', icon: Lock },
    { id: 4, title: 'DNS Configuration', icon: Globe },
    { id: 5, title: 'Verify & Deploy', icon: CheckCircle }
  ];

  const handleNext = () => {
    if (currentStep < 5) {
      setCurrentStep(currentStep + 1);
    } else {
      handleSubmit();
    }
  };

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSubmit = async () => {
    setIsDeploying(true);
    setDeployStage('saving');
    try {
      const url = existingApp 
        ? `${window.location.protocol}//${window.location.host}/api/apps/${existingApp.id}`
        : `${window.location.protocol}//${window.location.host}/api/apps`;
        
      const payload = {
        name: formData.appName,
        domain: formData.publicDomain,
        upstream_host: formData.backendHost,
        upstream_port: parseInt(formData.backendPort, 10),
        protocol: formData.backendProtocol,
        is_active: 1,
        rate_limit_rps: parseInt(formData.rateLimitRps, 10),
        burst_tolerance: parseInt(formData.burstTolerance, 10),
        // Wire SSL option to backend
        ssl_option: formData.sslOption === 'none' ? 'self-signed' : formData.sslOption,
      };

      const response = await fetch(url, {
        method: existingApp ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(err.detail || 'Failed to configure protected app');
      }

      const result = await response.json();
      const appId = result.id;

      // --- Post-save: SSL provisioning ---
      if (formData.sslOption === 'letsencrypt' && formData.publicDomain && formData.publicDomain !== '_') {
        setDeployStage('provisioning');
        try {
          const sslResp = await fetch(
            `${window.location.protocol}//${window.location.host}/api/apps/${appId}/provision-ssl`,
            { method: 'POST', credentials: 'include' }
          );
          if (!sslResp.ok) {
            const sslErr = await sslResp.json().catch(() => ({ detail: 'SSL provisioning failed' }));
            // Non-fatal: app is deployed, just cert provisioning failed
            console.warn('Let\'s Encrypt provisioning failed:', sslErr.detail);
          }
        } catch (sslError) {
          console.warn('Let\'s Encrypt provisioning error:', sslError);
        }
      } else if (formData.sslOption === 'custom' && formData.customCert && formData.customKey) {
        setDeployStage('provisioning');
        try {
          const fd = new FormData();
          fd.append('cert_file', formData.customCert);
          fd.append('key_file', formData.customKey);
          const uploadResp = await fetch(
            `${window.location.protocol}//${window.location.host}/api/apps/${appId}/upload-cert`,
            { method: 'POST', credentials: 'include', body: fd }
          );
          if (!uploadResp.ok) {
            const upErr = await uploadResp.json().catch(() => ({ detail: 'Cert upload failed' }));
            console.warn('Custom cert upload failed:', upErr.detail);
          }
        } catch (uploadError) {
          console.warn('Custom cert upload error:', uploadError);
        }
      }

      setDeployStage('done');
      onComplete(result);
      onClose();
    } catch (error) {
      console.error('Error configuring app:', error);
      alert('Failed to configure protected application: ' + error.message);
    } finally {
      setIsDeploying(false);
      setDeployStage('');
    }
  };

  const handleVerifyDNS = async () => {
    setIsVerifying(true);
    setDnsStatus('checking');
    
    try {
      const response = await fetch(`${window.location.protocol}//${window.location.host}/api/system/verify-dns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ domain: formData.publicDomain })
      });

      const result = await response.json();
      
      if (result.points_to_waf) {
        setDnsStatus('success');
      } else {
        setDnsStatus('failed');
      }
    } catch (error) {
      console.error('DNS verification error:', error);
      setDnsStatus('failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const canProceed = () => {
    switch (currentStep) {
      case 1:
        return formData.appName.trim() && formData.publicDomain.trim();
      case 2:
        return formData.backendHost.trim() && formData.backendPort.trim();
      case 3:
        return formData.sslOption;
      case 4:
        return true; // DNS config is informational
      case 5:
        return true;
      default:
        return false;
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="protected-app-wizard" onClick={(e) => e.stopPropagation()}>
        
        {/* Header */}
        <div className="wizard-header">
          <div className="wizard-title">
            <Shield size={24} color="#14b8a6" />
            <span>{existingApp ? 'Edit' : 'Add'} Protected Application</span>
          </div>
          
          {/* Progress Steps */}
          <div className="wizard-steps">
            {steps.map((step, index) => (
              <div key={step.id} className="step-indicator-wrapper">
                <div className={`step-indicator ${currentStep >= step.id ? 'active' : ''} ${currentStep > step.id ? 'completed' : ''}`}>
                  {currentStep > step.id ? (
                    <CheckCircle size={16} />
                  ) : (
                    <span>{step.id}</span>
                  )}
                </div>
                <span className="step-label">{step.title}</span>
                {index < steps.length - 1 && (
                  <div className={`step-line ${currentStep > step.id ? 'completed' : ''}`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Body */}
        <div className="wizard-body">
          <AnimatePresence mode="wait">
            
            {/* Step 1: Application Details */}
            {currentStep === 1 && (
              <motion.div
                key="step1"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="wizard-step-content"
              >
                <div className="step-icon">
                  <Globe size={48} color="#14b8a6" />
                </div>
                <h2>What application do you want to protect?</h2>
                <p className="step-description">
                  Enter the public domain that users will access. This is the domain that needs DNS configuration.
                </p>

                <div className="form-group">
                  <label>Application Name</label>
                  <input
                    type="text"
                    className="wizard-input"
                    placeholder="e.g., Production API"
                    value={formData.appName}
                    onChange={(e) => setFormData({ ...formData, appName: e.target.value })}
                  />
                  <span className="input-hint">A friendly name to identify this application</span>
                </div>

                <div className="form-group">
                  <label>Public Domain</label>
                  <input
                    type="text"
                    className="wizard-input"
                    placeholder="e.g., api.example.com"
                    value={formData.publicDomain}
                    onChange={(e) => setFormData({ ...formData, publicDomain: e.target.value })}
                  />
                  <span className="input-hint">The domain users will access (must be configured in DNS)</span>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label>Rate Limit (Req/s)</label>
                    <input
                      type="number"
                      className="wizard-input"
                      placeholder="50"
                      value={formData.rateLimitRps}
                      onChange={(e) => setFormData({ ...formData, rateLimitRps: e.target.value })}
                    />
                  </div>

                  <div className="form-group">
                    <label>Burst Tolerance</label>
                    <input
                      type="number"
                      className="wizard-input"
                      placeholder="100"
                      value={formData.burstTolerance}
                      onChange={(e) => setFormData({ ...formData, burstTolerance: e.target.value })}
                    />
                  </div>
                </div>
              </motion.div>
            )}

            {/* Step 2: Backend Configuration */}
            {currentStep === 2 && (
              <motion.div
                key="step2"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="wizard-step-content"
              >
                <div className="step-icon">
                  <Server size={48} color="#14b8a6" />
                </div>
                <h2>Where is your application currently hosted?</h2>
                <p className="step-description">
                  The WAF will forward inspected traffic to this backend server. This is your origin server.
                </p>

                <div className="form-group">
                  <label>Backend Server IP or Hostname</label>
                  <input
                    type="text"
                    className="wizard-input"
                    placeholder="e.g., 192.168.1.100 or backend.internal"
                    value={formData.backendHost}
                    onChange={(e) => setFormData({ ...formData, backendHost: e.target.value })}
                  />
                  <span className="input-hint">The actual server where your application runs</span>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label>Backend Port</label>
                    <input
                      type="number"
                      className="wizard-input"
                      placeholder="80"
                      value={formData.backendPort}
                      onChange={(e) => setFormData({ ...formData, backendPort: e.target.value })}
                    />
                  </div>

                  <div className="form-group">
                    <label>Backend Protocol</label>
                    <select
                      className="wizard-input"
                      value={formData.backendProtocol}
                      onChange={(e) => setFormData({ ...formData, backendProtocol: e.target.value })}
                    >
                      <option value="http">HTTP</option>
                      <option value="https">HTTPS</option>
                    </select>
                  </div>
                </div>

                <div className="info-box">
                  <AlertTriangle size={16} />
                  <span>
                    Traffic flow: User → WAF ({wafServerIP}) → Backend ({formData.backendProtocol}://{formData.backendHost}:{formData.backendPort})
                  </span>
                </div>
              </motion.div>
            )}

            {/* Step 3: SSL/TLS Setup */}
            {currentStep === 3 && (
              <motion.div
                key="step3"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="wizard-step-content"
              >
                <div className="step-icon">
                  <Lock size={48} color="#14b8a6" />
                </div>
                <h2>How should we secure the connection?</h2>
                <p className="step-description">
                  Choose how to handle SSL/TLS certificates for encrypted HTTPS traffic.
                </p>

                <div className="ssl-options">
                  <div
                    className={`ssl-option ${formData.sslOption === 'letsencrypt' ? 'selected' : ''}`}
                    onClick={() => setFormData({ ...formData, sslOption: 'letsencrypt' })}
                  >
                    <div className="option-header">
                      <Lock size={20} />
                      <span className="option-title">Let's Encrypt (Recommended)</span>
                      {formData.sslOption === 'letsencrypt' && <CheckCircle size={18} color="#10b981" />}
                    </div>
                    <p className="option-desc">Automatic certificate generation and renewal. Free and secure.</p>
                    <ul className="option-features">
                      <li>✓ Automatic renewal every 90 days</li>
                      <li>✓ Industry-standard encryption</li>
                      <li>✓ Zero configuration required</li>
                    </ul>
                  </div>

                  <div
                    className={`ssl-option ${formData.sslOption === 'custom' ? 'selected' : ''}`}
                    onClick={() => setFormData({ ...formData, sslOption: 'custom' })}
                  >
                    <div className="option-header">
                      <Lock size={20} />
                      <span className="option-title">Custom Certificate</span>
                      {formData.sslOption === 'custom' && <CheckCircle size={18} color="#10b981" />}
                    </div>
                    <p className="option-desc">Upload your own SSL certificate and private key.</p>
                    {formData.sslOption === 'custom' && (
                      <div className="upload-section">
                        <label className="upload-label">
                          <input type="file" accept=".crt,.pem" onChange={(e) => setFormData({ ...formData, customCert: e.target.files[0] })} />
                          Certificate File (.crt, .pem)
                        </label>
                        <label className="upload-label">
                          <input type="file" accept=".key,.pem" onChange={(e) => setFormData({ ...formData, customKey: e.target.files[0] })} />
                          Private Key (.key, .pem)
                        </label>
                      </div>
                    )}
                  </div>

                  <div
                    className={`ssl-option ${formData.sslOption === 'none' ? 'selected' : ''}`}
                    onClick={() => setFormData({ ...formData, sslOption: 'none' })}
                  >
                    <div className="option-header">
                      <AlertTriangle size={20} color="#f59e0b" />
                      <span className="option-title">HTTP Only (Not Secure)</span>
                      {formData.sslOption === 'none' && <CheckCircle size={18} color="#10b981" />}
                    </div>
                    <p className="option-desc">No encryption. Only use for internal testing.</p>
                    <div className="warning-box">
                      <AlertTriangle size={14} />
                      <span>Not recommended for production environments</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Step 4: DNS Configuration */}
            {currentStep === 4 && (
              <motion.div
                key="step4"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="wizard-step-content"
              >
                <div className="step-icon">
                  <Globe size={48} color="#f59e0b" />
                </div>
                <h2>⚠️ REQUIRED: Update Your DNS Records</h2>
                <p className="step-description">
                  For the WAF to protect your application, you must point your domain's DNS to the WAF server.
                </p>

                {/* Visual Diagram */}
                <div className="dns-diagram">
                  <div className="diagram-section">
                    <div className="diagram-label">BEFORE (Not Protected)</div>
                    <div className="flow-box">
                      <div className="flow-item">User</div>
                      <ChevronRight size={16} />
                      <div className="flow-item">{formData.publicDomain}</div>
                      <ChevronRight size={16} />
                      <div className="flow-item">App Server</div>
                      <div className="flow-badge danger">❌ No WAF</div>
                    </div>
                  </div>

                  <div className="diagram-section">
                    <div className="diagram-label">AFTER (Protected)</div>
                    <div className="flow-box">
                      <div className="flow-item">User</div>
                      <ChevronRight size={16} />
                      <div className="flow-item highlight">{formData.publicDomain}<br/><small>(DNS: {wafServerIP})</small></div>
                      <ChevronRight size={16} />
                      <div className="flow-item success">WAF</div>
                      <ChevronRight size={16} />
                      <div className="flow-item">Backend</div>
                      <div className="flow-badge success">✅ Protected</div>
                    </div>
                  </div>
                </div>

                {/* DNS Configuration Details */}
                <div className="dns-config-box">
                  <div className="config-header">
                    <span>DNS Record Configuration</span>
                    <button
                      className="copy-btn"
                      onClick={() => copyToClipboard(`Type: A\nName: ${formData.publicDomain.split('.')[0]}\nValue: ${wafServerIP}\nTTL: 300`)}
                    >
                      {copied ? <Check size={14} /> : <Copy size={14} />}
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <div className="config-table">
                    <div className="config-row">
                      <span className="config-label">Type:</span>
                      <span className="config-value">A</span>
                    </div>
                    <div className="config-row">
                      <span className="config-label">Name:</span>
                      <span className="config-value">{formData.publicDomain.split('.')[0]}</span>
                    </div>
                    <div className="config-row">
                      <span className="config-label">Value:</span>
                      <span className="config-value highlight">{wafServerIP}</span>
                    </div>
                    <div className="config-row">
                      <span className="config-label">TTL:</span>
                      <span className="config-value">300 (5 minutes)</span>
                    </div>
                  </div>
                </div>

                {/* Steps to Update DNS */}
                <div className="dns-steps">
                  <h4>Steps to Update DNS:</h4>
                  <ol>
                    <li>Log into your DNS provider (Cloudflare, GoDaddy, Namecheap, Route53, etc.)</li>
                    <li>Find DNS settings for <strong>{formData.publicDomain.split('.').slice(-2).join('.')}</strong></li>
                    <li>Edit or create an <strong>A record</strong> for <strong>{formData.publicDomain.split('.')[0]}</strong></li>
                    <li>Set the value to: <strong>{wafServerIP}</strong></li>
                    <li>Save changes and wait 5-30 minutes for propagation</li>
                  </ol>
                </div>

                <div className="info-box">
                  <AlertTriangle size={16} />
                  <span>
                    DNS propagation can take 5-30 minutes. You can verify the configuration in the next step.
                  </span>
                </div>

                <a
                  href="https://www.whatsmydns.net/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="external-link"
                >
                  <ExternalLink size={14} />
                  Check DNS Propagation Status
                </a>
              </motion.div>
            )}

            {/* Step 5: Verify & Deploy */}
            {currentStep === 5 && (
              <motion.div
                key="step5"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="wizard-step-content"
              >
                <div className="step-icon">
                  <CheckCircle size={48} color="#10b981" />
                </div>
                <h2>Verify Configuration & Deploy</h2>
                <p className="step-description">
                  Review your configuration and verify DNS is pointing to the WAF server.
                </p>

                {/* Configuration Summary */}
                <div className="config-summary">
                  <h4>📋 Configuration Summary</h4>
                  <div className="summary-grid">
                    <div className="summary-item">
                      <span className="summary-label">Application:</span>
                      <span className="summary-value">{formData.appName}</span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">Public Domain:</span>
                      <span className="summary-value">{formData.publicDomain}</span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">WAF Entry Point:</span>
                      <span className="summary-value">{wafServerIP}:443 (HTTPS)</span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">Backend Origin:</span>
                      <span className="summary-value">{formData.backendProtocol}://{formData.backendHost}:{formData.backendPort}</span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">SSL/TLS:</span>
                      <span className="summary-value">
                        {formData.sslOption === 'letsencrypt' ? 'Let\'s Encrypt (Auto)' : 
                         formData.sslOption === 'custom' ? 'Custom Certificate' : 
                         'HTTP Only'}
                      </span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">Protection Level:</span>
                      <span className="summary-value">Level {formData.protectionLevel}</span>
                    </div>
                  </div>
                </div>

                {/* DNS Verification */}
                <div className="verification-box">
                  <h4>🔍 DNS Verification</h4>
                  <div className="verification-status">
                    <span>Status:</span>
                    {dnsStatus === 'pending' && <span className="status-badge pending">⏳ Not Checked</span>}
                    {dnsStatus === 'checking' && <span className="status-badge checking">🔄 Checking...</span>}
                    {dnsStatus === 'success' && <span className="status-badge success">✅ DNS Configured</span>}
                    {dnsStatus === 'failed' && <span className="status-badge failed">❌ Not Pointing to WAF</span>}
                  </div>
                  
                  <button
                    className="verify-btn"
                    onClick={handleVerifyDNS}
                    disabled={isVerifying}
                  >
                    {isVerifying ? (
                      <>
                        <RefreshCw size={16} className="animate-spin" />
                        Verifying DNS...
                      </>
                    ) : (
                      <>
                        <RefreshCw size={16} />
                        Verify DNS Configuration
                      </>
                    )}
                  </button>

                  {dnsStatus === 'failed' && (
                    <div className="warning-box" style={{ marginTop: '12px' }}>
                      <AlertTriangle size={14} />
                      <span>
                        DNS is not pointing to the WAF yet. Go back to Step 4 to review DNS configuration, 
                        or proceed anyway if you'll configure DNS later.
                      </span>
                    </div>
                  )}

                  {dnsStatus === 'success' && (
                    <div className="success-box" style={{ marginTop: '12px' }}>
                      <CheckCircle size={14} />
                      <span>
                        Great! DNS is correctly pointing to the WAF. Your application will be protected once deployed.
                      </span>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

          </AnimatePresence>
        </div>

        {/* Footer */}
        <div className="wizard-footer">
          <button className="wizard-btn secondary" onClick={currentStep === 1 ? onClose : handleBack} disabled={isDeploying}>
            {currentStep === 1 ? 'Cancel' : 'Back'}
          </button>
          <button
            className="wizard-btn primary"
            onClick={handleNext}
            disabled={!canProceed() || isDeploying}
          >
            {currentStep === 5 ? (
              isDeploying ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  {deployStage === 'provisioning' ? 'Provisioning SSL...' : 'Deploying...'}
                </>
              ) : 'Deploy Protection'
            ) : 'Continue'}
            {currentStep < 5 && !isDeploying && <ChevronRight size={16} />}
          </button>
        </div>

      </div>
    </div>
  );
};

export default ProtectedAppWizard;
