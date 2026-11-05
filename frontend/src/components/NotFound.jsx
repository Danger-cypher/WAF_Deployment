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
            background: 'var(--danger-bg)',
            color: 'var(--danger-color)',
            marginBottom: '20px',
          }}
        >
          <AlertCircle size={32} />
        </div>

        <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '8px', color: 'var(--text-primary)' }}>
          404 - Page Not Found
        </h2>

        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '16px', lineHeight: 1.5 }}>
          The requested URL path was not found on this management console:
        </p>

        <div
          style={{
            background: 'var(--bg-void)',
            border: '1px solid var(--border-color)',
            padding: '8px 14px',
            borderRadius: 'var(--radius-sm)',
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
            color: 'var(--danger-color)',
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
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent-color)',
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
