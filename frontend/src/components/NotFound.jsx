import React from 'react';
import { AlertCircle, ArrowLeft } from 'lucide-react';

const NotFound = ({ onReturnDashboard }) => {
  const currentPath = window.location.pathname;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '60vh',
        padding: '24px',
      }}
    >
      <div
        style={{
          background: 'var(--surface-color, #131b2e)',
          border: '1px solid var(--border-color, #1e293b)',
          borderRadius: '12px',
          padding: '40px 32px',
          maxWidth: '480px',
          width: '100%',
          textAlign: 'center',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'rgba(239, 68, 68, 0.12)',
            color: '#ef4444',
            marginBottom: '20px',
          }}
        >
          <AlertCircle size={32} />
        </div>

        <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '8px', color: 'var(--text-primary, #f3f4f6)' }}>
          404 - Page Not Found
        </h2>

        <p style={{ color: 'var(--text-secondary, #9ca3af)', fontSize: '14px', marginBottom: '16px', lineHeight: 1.5 }}>
          The requested URL path was not found on this management console:
        </p>

        <div
          style={{
            background: 'var(--bg-void, #080d19)',
            border: '1px solid var(--border-color, #1e293b)',
            padding: '8px 14px',
            borderRadius: '6px',
            fontFamily: 'monospace',
            fontSize: '13px',
            color: '#f87171',
            wordBreak: 'break-all',
            marginBottom: '24px',
          }}
        >
          {currentPath}
        </div>

        <button
          onClick={onReturnDashboard}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            padding: '10px 20px',
            borderRadius: '8px',
            background: 'var(--accent-color, #3b82f6)',
            color: '#ffffff',
            border: 'none',
            fontSize: '14px',
            fontWeight: '500',
            cursor: 'pointer',
            transition: 'background 0.2s',
          }}
        >
          <ArrowLeft size={16} />
          Return to Dashboard
        </button>
      </div>
    </div>
  );
};

export default NotFound;
