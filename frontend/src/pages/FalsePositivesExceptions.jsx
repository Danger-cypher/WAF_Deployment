import { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, AlertTriangle } from 'lucide-react';
import FalsePositives from './FalsePositives';
import Exceptions from './Exceptions';

/**
 * Wraps two previously-separate top-level tabs as sub-tabs of one page —
 * same shell pattern ProtectionSection.jsx already uses for Virtual Hosts /
 * DDoS & Bot Shield. Reviewing a false positive and checking whether an
 * exception already exists for it are the same workflow in practice; they
 * don't need two separate sidebar destinations. Neither child component was
 * changed — each still owns its own data fetching, filters, and modals, so
 * switching sub-tabs here behaves exactly as switching top-level tabs did
 * before (conditional rendering unmounts the one leaving, mounts the one
 * arriving fresh).
 */
export default function FalsePositivesExceptions({ userRole, onCreateException }) {
  const [activeSubTab, setActiveSubTab] = useState('false_positives');

  const subTabs = [
    {
      id: 'false_positives',
      label: 'False Positives',
      icon: ShieldAlert,
      description: 'Requests the WAF blocked that were actually legitimate — review, note, and tune',
    },
    {
      id: 'exceptions',
      label: 'Exceptions',
      icon: AlertTriangle,
      description: 'Active bypass rules created from reviewed false positives',
    },
  ];

  const activeTabMeta = subTabs.find((t) => t.id === activeSubTab);
  const ActiveIcon = activeTabMeta?.icon;

  return (
    <div className="advanced-section">
      {/* Section Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '20px',
        paddingBottom: '16px',
        borderBottom: '1px solid var(--border-color)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {ActiveIcon && (
            <div style={{
              width: '36px', height: '36px', borderRadius: '10px',
              background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <ActiveIcon size={18} color="var(--sev-low)" />
            </div>
          )}
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
              {activeTabMeta?.label}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              {activeTabMeta?.description}
            </div>
          </div>
        </div>
      </div>

      {/* Sub-navigation */}
      <div className="subtabs-container" style={{ marginBottom: '24px' }}>
        {subTabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`subtab-btn ${activeSubTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveSubTab(tab.id)}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Content */}
      <motion.div
        key={activeSubTab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
      >
        {activeSubTab === 'false_positives' && (
          <FalsePositives userRole={userRole} onCreateException={onCreateException} />
        )}
        {activeSubTab === 'exceptions' && <Exceptions />}
      </motion.div>
    </div>
  );
}
