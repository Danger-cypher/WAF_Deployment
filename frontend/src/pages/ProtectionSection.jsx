import { useState } from 'react';
import { motion } from 'framer-motion';
import { Server, ShieldAlert } from 'lucide-react';
import ProtectedApps from '../components/ProtectedApps';
import DdosBotMitigation from '../components/DdosBotMitigation';

export default function ProtectionSection({ appsRefreshKey, onOpenWizard }) {
  const [activeSubTab, setActiveSubTab] = useState('apps');

  const subTabs = [
    {
      id: 'apps',
      label: 'Virtual Hosts',
      icon: Server,
      description: 'Manage reverse-proxy protected applications and SSL termination',
      statusColor: '#10b981',
    },
    {
      id: 'ddos',
      label: 'DDoS & Bot Shield',
      icon: ShieldAlert,
      description: 'Layer-7 rate limiting, bot mitigation and live traffic analytics',
      statusColor: '#f59e0b',
    },
  ];

  const activeTabMeta = subTabs.find(t => t.id === activeSubTab);
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
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {ActiveIcon && (
            <div style={{
              width: '36px', height: '36px', borderRadius: '10px',
              background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <ActiveIcon size={18} color="#3b82f6" />
            </div>
          )}
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#f4f4f5', lineHeight: 1.2 }}>
              {activeTabMeta?.label}
            </div>
            <div style={{ fontSize: '12px', color: '#71717a', marginTop: '2px' }}>
              {activeTabMeta?.description}
            </div>
          </div>
        </div>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '4px 10px', borderRadius: '20px',
          background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
          fontSize: '11px', fontWeight: 600, color: '#34d399',
        }}>
          <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
          ACTIVE ENFORCEMENT
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
        {activeSubTab === 'apps' && (
          <ProtectedApps
            key={appsRefreshKey}
            onOpenWizard={onOpenWizard}
          />
        )}
        {activeSubTab === 'ddos' && <DdosBotMitigation />}
      </motion.div>
    </div>
  );
}
