import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Download, Printer, AlertTriangle,
  ShieldCheck, Activity, FileJson, RefreshCw
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import {
  getStats, getAttackTypes, getTopIPs, getHealth, getSecurityStatistics,
  getWafSettings, getHardeningSettings, getLogSettings, getProtectedApps,
} from '../services/api';

const ATTACK_CHART_COLORS = [
  'var(--danger-color)', 'var(--sev-high)', 'var(--warning-color)',
  'var(--accent-color)', 'var(--ml-color)', 'var(--cyan-color)',
  'var(--pink-color)', 'var(--text-secondary)',
];

// Maps each compliance-table row to the specific control it actually
// corresponds to in a named framework, rather than leaving the "Compliance"
// label pointing at nothing external. Deliberately not exhaustive — only
// rows that genuinely map to a real control get a citation; a row with no
// entry here (e.g. "Active Protected Virtual Hosts", a coverage metric, not
// a pass/fail control) renders without one rather than forcing a citation
// that doesn't actually apply. Citations reference publicly published
// framework language for context only — see the disclaimer rendered under
// the table; this is not a certified compliance assessment.
const COMPLIANCE_MAPPINGS = {
  engineEnforcement: {
    framework: 'PCI-DSS v4.0',
    control: 'Req. 6.4.2',
    note: 'Automated technical solution that detects and prevents web-based attacks on public-facing web applications',
  },
  tlsHardening: {
    framework: 'PCI-DSS v4.0 / OWASP Top 10',
    control: 'Req. 4.2.1 / A02:2021',
    note: 'Strong cryptography for data in transit; Cryptographic Failures',
  },
  antiDefacement: {
    framework: 'OWASP Top 10 2021',
    control: 'A08:2021',
    note: 'Software and Data Integrity Failures',
  },
  adminAuditLogging: {
    framework: 'PCI-DSS v4.0 / OWASP Top 10',
    control: 'Req. 10.2.1 / A09:2021',
    note: 'Audit trails for individual user access to system components; Security Logging and Monitoring Failures',
  },
};

// Renders a compliance row's framework citation, or an explicit "not a
// mapped control" note for rows that are coverage metrics rather than
// pass/fail controls (see COMPLIANCE_MAPPINGS' comment above).
function MapsToCell({ mapping }) {
  if (!mapping) {
    return <td style={{ color: 'var(--text-secondary)', fontSize: '12px', fontStyle: 'italic' }}>Coverage metric — not a mapped control</td>;
  }
  return (
    <td>
      <div style={{ fontWeight: 600, fontSize: '12px' }}>{mapping.framework}</div>
      <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{mapping.control}</div>
    </td>
  );
}

// Segmented risk meter — shows all 4 severity levels (using the same
// severity color language as the rest of the dashboard: success/warning/
// sev-high/danger), with the level matching reportData.riskLevel picked
// out at full opacity so the reader sees both the exact rating and where
// it sits on the full spectrum at a glance, not just a single colored word.
const RISK_LEVELS = [
  { key: 'LOW', color: 'var(--success-color)' },
  { key: 'MEDIUM', color: 'var(--warning-color)' },
  { key: 'HIGH', color: 'var(--sev-high)' },
  { key: 'CRITICAL', color: 'var(--danger-color)' },
];

function RiskMeter({ level }) {
  return (
    <div className="report-risk-meter">
      {RISK_LEVELS.map((l) => (
        <div
          key={l.key}
          className={`report-risk-meter-segment${l.key === level ? ' active' : ''}`}
          style={{ background: l.color }}
          title={l.key}
        />
      ))}
    </div>
  );
}

// ============================================================================
// Two separate presentation layers over the SAME reportData object:
//
// ReportAppView   — always visible on screen. Uses the app's real theme
//                    tokens (.glass-panel, var(--text-primary) etc, with NO
//                    local color overrides) so it inherits dark/light theme
//                    automatically like every other dashboard page, and
//                    never renders a white document/page look.
// ReportPrintView — invisible on screen (display:none), revealed ONLY by
//                    the @media print rules below when the user actually
//                    prints/saves as PDF. This is the one styled as a fixed
//                    white "paper" A4 document with a letterhead, since
//                    that's appropriate for something handed to someone
//                    outside the dashboard — but it must never affect the
//                    normal application view, which is why it's a wholly
//                    separate component/DOM subtree rather than the same
//                    markup re-themed by a media query.
//
// Both read the same already-fetched reportData; neither fetches or
// transforms data on its own, so there is exactly one source of truth and
// no risk of the two views drifting out of sync on the numbers.
// ============================================================================

function AttackTypesTable({ attackTypes, tableClass }) {
  const totalDetections = attackTypes.reduce((sum, item) => sum + (item.count || 0), 0);
  return (
    <table className={tableClass}>
      <thead>
        <tr>
          <th>Violation Type / Category</th>
          <th style={{ textAlign: 'right' }}>Detections</th>
          <th style={{ textAlign: 'right' }}>Percentage</th>
        </tr>
      </thead>
      <tbody>
        {attackTypes.length > 0 ? (
          attackTypes.map((t, idx) => (
            <tr key={idx}>
              <td><strong>{t.attack_type || 'Unknown / Custom'}</strong></td>
              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{t.count}</td>
              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                {totalDetections > 0 ? ((t.count / totalDetections) * 100).toFixed(1) : '0.0'}%
              </td>
            </tr>
          ))
        ) : (
          <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No threat category data recorded.</td></tr>
        )}
      </tbody>
    </table>
  );
}

function TopIpsTable({ topIps, tableClass }) {
  return (
    <table className={tableClass}>
      <thead>
        <tr>
          <th>Source IP</th>
          <th>Origin Country</th>
          <th style={{ textAlign: 'right' }}>Total Hits</th>
        </tr>
      </thead>
      <tbody>
        {topIps.length > 0 ? (
          topIps.map((ip, idx) => (
            <tr key={idx}>
              <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)' }}>{ip.ip || ip.client_ip || ip.source_ip || 'Unknown'}</td>
              <td>{ip.country || 'Internal'}</td>
              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{ip.count}</td>
            </tr>
          ))
        ) : (
          <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No attacking source IP data recorded.</td></tr>
        )}
      </tbody>
    </table>
  );
}

function ComplianceTable({ data, tableClass }) {
  return (
    <>
      <table className={tableClass}>
        <thead>
          <tr>
            <th>Compliance Check / Standard</th>
            <th>Maps To</th>
            <th style={{ textAlign: 'right' }}>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>CyberSentinel Engine Enforcement</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.engineEnforcement} />
            {(() => {
              const on = data.compliance.engineEnforcement;
              if (on == null) return <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontWeight: 600 }}>UNABLE TO VERIFY</td>;
              return on === 'On'
                ? <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 600 }}>ENFORCING</td>
                : <td style={{ textAlign: 'right', color: 'var(--danger-color)', fontWeight: 600 }}>NOT ENFORCING</td>;
            })()}
          </tr>
          <tr>
            <td>SSL/TLS Dynamic Cipher Hardening (HSTS)</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.tlsHardening} />
            {(() => {
              const on = data.compliance.tlsHardening;
              if (on == null) return <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontWeight: 600 }}>UNABLE TO VERIFY</td>;
              return on
                ? <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 600 }}>ENABLED</td>
                : <td style={{ textAlign: 'right', color: 'var(--sev-high)', fontWeight: 600 }}>DISABLED</td>;
            })()}
          </tr>
          <tr>
            <td>Dynamic Web Anti-Defacement Integrity Check</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.antiDefacement} />
            <td style={{
              textAlign: 'right', fontWeight: 600,
              color: data.health.antiDefacement === 'ACTIVE' ? 'var(--success-color)' : 'var(--text-secondary)',
            }}>{data.health.antiDefacement}</td>
          </tr>
          <tr>
            <td>Admin Authentication Logging & Audits</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.adminAuditLogging} />
            {(() => {
              const on = data.compliance.adminAuditLogging;
              if (on == null) return <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontWeight: 600 }}>UNABLE TO VERIFY</td>;
              return on
                ? <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 600 }}>ENFORCED</td>
                : <td style={{ textAlign: 'right', color: 'var(--danger-color)', fontWeight: 600 }}>DISABLED</td>;
            })()}
          </tr>
          <tr>
            <td>Active Protected Virtual Hosts</td>
            <MapsToCell mapping={null} />
            <td style={{ textAlign: 'right', fontWeight: 600 }}>
              {data.compliance.activeProtectedHosts == null
                ? 'UNABLE TO VERIFY'
                : `${data.compliance.activeProtectedHosts} / ${data.compliance.totalProtectedHosts} ACTIVE`}
            </td>
          </tr>
        </tbody>
      </table>
      <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '10px', lineHeight: 1.5 }}>
        Control citations reference publicly published framework language for context only, based on this
        system's current configuration state. This is <strong>not</strong> a certified compliance
        assessment — consult a qualified auditor for official certification against any named standard.
      </p>
    </>
  );
}

function AuditEventsTable({ audit, tableClass }) {
  return (
    <table className={tableClass}>
      <thead>
        <tr>
          <th>Audit Event Type</th>
          <th style={{ textAlign: 'right' }}>Event Count</th>
        </tr>
      </thead>
      <tbody>
        {Object.keys(audit.by_type).length > 0 ? (
          Object.entries(audit.by_type).map(([key, val]) => (
            <tr key={key}>
              <td><strong>{key}</strong></td>
              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{val}</td>
            </tr>
          ))
        ) : (
          <tr><td colSpan="2" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No audit occurrences logged.</td></tr>
        )}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// ReportAppView — native dashboard presentation
// ---------------------------------------------------------------------------
function ReportAppView({ data, reportType }) {
  return (
    <div className="report-app-view">
      <div className="glass-panel report-app-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <span className="report-app-badge">SECURITY REPORT</span>
            <h1 className="report-app-title">
              {reportType === 'executive' && 'WAF Executive Summary'}
              {reportType === 'threat' && 'Detailed Threat Analysis'}
              {reportType === 'compliance' && 'System Audit & Compliance'}
            </h1>
            <div className="report-app-meta">
              <span><strong>Timeframe</strong> {data.timeframe}</span>
              <span className="report-app-meta-sep">•</span>
              <span><strong>Generated</strong> {data.generatedAt}</span>
              <span className="report-app-meta-sep">•</span>
              <span><strong>Report ID</strong> {data.reportId}</span>
            </div>
          </div>
          <div className="report-app-risk">
            <div className="report-app-risk-label">Overall Risk</div>
            <div className="report-app-risk-value" style={{ color: data.riskColor }}>{data.riskLevel}</div>
            <RiskMeter level={data.riskLevel} />
          </div>
        </div>
      </div>

      <div className="glass-panel report-app-narrative">
        <h3><Activity size={15} /> Executive Narrative</h3>
        <p>{data.narrativeSummary}</p>
      </div>

      <div className="report-app-stat-grid">
        <div className="glass-panel report-app-stat-card">
          <span className="report-app-stat-label">Total HTTP Requests</span>
          <span className="report-app-stat-value">{data.metrics.totalRequests.toLocaleString()}</span>
          <span className="report-app-stat-sub">Analyzed by WAF Engine</span>
        </div>
        <div className="glass-panel report-app-stat-card">
          <span className="report-app-stat-label">Blocked Violations</span>
          <span className="report-app-stat-value" style={{ color: 'var(--danger-color)' }}>{data.metrics.totalBlocked.toLocaleString()}</span>
          <span className="report-app-stat-sub">Malicious Payloads Dropped</span>
        </div>
        <div className="glass-panel report-app-stat-card">
          <span className="report-app-stat-label">Attack Percentage</span>
          <span className="report-app-stat-value" style={{ color: 'var(--warning-color)' }}>{data.metrics.blockRate}%</span>
          <span className="report-app-stat-sub">Violations to traffic ratio</span>
        </div>
      </div>

      {reportType === 'executive' && (
        <div className="report-app-grid">
          <div className="glass-panel report-app-section" style={{ '--section-accent': 'var(--danger-color)' }}>
            <h3>Violation Category Breakdown</h3>
            {data.attackTypes.length > 0 && (
              <div style={{ height: '220px', width: '100%', marginBottom: '12px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={data.attackTypes} cx="50%" cy="50%" innerRadius={45} outerRadius={78} paddingAngle={2} dataKey="count" nameKey="attack_type" strokeWidth={0}>
                      {data.attackTypes.map((entry, index) => (
                        <Cell key={index} fill={ATTACK_CHART_COLORS[index % ATTACK_CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{ background: 'var(--chart-tooltip-bg)', border: '1px solid var(--surface-strong)', borderRadius: '8px', fontSize: '12px' }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}
            <div className="report-app-table-wrapper">
              <AttackTypesTable attackTypes={data.attackTypes} tableClass="report-app-table" />
            </div>
          </div>
          <div className="glass-panel report-app-section" style={{ '--section-accent': 'var(--danger-color)' }}>
            <h3>Top Attack Originators</h3>
            <div className="report-app-table-wrapper">
              <TopIpsTable topIps={data.topIps} tableClass="report-app-table" />
            </div>
          </div>
        </div>
      )}

      {reportType === 'threat' && (
        <div className="report-app-grid">
          <div className="glass-panel report-app-section" style={{ gridColumn: '1 / -1', '--section-accent': 'var(--danger-color)' }}>
            <h3>Threat Intelligence & Signatures</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Signature-based detections and CyberSentinel Engine Core Rule Set (CRS) triggers recorded for this timeframe.
            </p>
            <div className="report-app-stat-grid" style={{ marginBottom: '20px' }}>
              <div className="report-app-mini-stat">
                <span className="report-app-stat-label">SQL Injection Attacks</span>
                <span className="report-app-stat-value" style={{ fontSize: '22px' }}>{data.metrics.sqlInjections}</span>
                <span className="report-app-stat-sub">Signature database matches</span>
              </div>
              <div className="report-app-mini-stat">
                <span className="report-app-stat-label">Cross-Site Scripting (XSS)</span>
                <span className="report-app-stat-value" style={{ fontSize: '22px' }}>{data.metrics.xssAttacks}</span>
                <span className="report-app-stat-sub">Browser payloads filtered</span>
              </div>
              <div className="report-app-mini-stat">
                <span className="report-app-stat-label">Primary Attack Vector</span>
                <span className="report-app-stat-value" style={{ fontSize: '18px', color: 'var(--accent-color)' }}>{data.metrics.topAttackType}</span>
                <span className="report-app-stat-sub">Most frequent category</span>
              </div>
            </div>
            <h3>Top Threat Originators</h3>
            <div className="report-app-table-wrapper">
              <TopIpsTable topIps={data.topIps} tableClass="report-app-table" />
            </div>
          </div>
        </div>
      )}

      {reportType === 'compliance' && (
        <div className="report-app-grid">
          <div className="glass-panel report-app-section" style={{ '--section-accent': 'var(--accent-color)' }}>
            <h3>System Configuration & Compliance</h3>
            <div className="report-app-table-wrapper">
              <ComplianceTable data={data} tableClass="report-app-table" />
            </div>
          </div>
          <div className="glass-panel report-app-section" style={{ '--section-accent': 'var(--warning-color)' }}>
            <h3>Security Audit Event Types</h3>
            <div className="report-app-table-wrapper">
              <AuditEventsTable audit={data.audit} tableClass="report-app-table" />
            </div>
          </div>
        </div>
      )}

      <div className="glass-panel report-app-footer">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          <div>
            <div className="report-app-footer-label">GATEWAY NODE STATUS</div>
            <div
              className="report-app-footer-value"
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                color: data.health.status === 'HEALTHY' ? 'var(--success-color)' : 'var(--sev-high)',
              }}
            >
              <ShieldCheck size={14} />
              <span>{data.health.status}</span>
            </div>
          </div>
          <div>
            <div className="report-app-footer-label">WAF CORE ENGINE</div>
            <div className="report-app-footer-value">{data.health.engine}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ReportPrintView — formal A4 document, hidden on screen, revealed only by
// @media print. Never visible as part of the normal application UI.
// ---------------------------------------------------------------------------
function ReportPrintView({ data, reportType }) {
  return (
    <div className="report-print-view">
      <div className="report-print-sheet">
        <div className="print-footer">
          CyberSentinel WAF — {data.reportId} — Confidential — Internal Use Only
        </div>

        <div className="report-print-letterhead">
          <div className="report-print-letterhead-brand">
            <div className="report-print-letterhead-mark">CS</div>
            <div>
              <div className="report-print-letterhead-name">CyberSentinel</div>
              <div className="report-print-letterhead-tagline">Web Application Firewall</div>
            </div>
          </div>
          <div className="report-print-letterhead-classification">Confidential — Internal Use Only</div>
        </div>

        <div className="report-print-header-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
            <div>
              <span className="report-print-badge">SECURITY REPORT</span>
              <h1 className="report-print-title">
                {reportType === 'executive' && 'WAF Executive Summary'}
                {reportType === 'threat' && 'Detailed Threat Analysis'}
                {reportType === 'compliance' && 'System Audit & Compliance'}
              </h1>
              <div className="report-print-meta">
                <span><strong>Timeframe</strong> {data.timeframe}</span>
                <span className="report-print-meta-sep">•</span>
                <span><strong>Generated</strong> {data.generatedAt}</span>
                <span className="report-print-meta-sep">•</span>
                <span><strong>Report ID</strong> {data.reportId}</span>
              </div>
            </div>
            <div className="report-print-risk-badge">
              <div className="report-print-risk-label">Overall Risk</div>
              <div className="report-print-risk-value" style={{ color: data.riskColor }}>{data.riskLevel}</div>
              <RiskMeter level={data.riskLevel} />
            </div>
          </div>
        </div>

        <div className="report-print-section" style={{ marginBottom: '20px' }}>
          <h3>Executive Narrative</h3>
          <p style={{ fontSize: '13px', lineHeight: 1.7 }}>{data.narrativeSummary}</p>
        </div>

        <div className="report-print-grid-3">
          <div className="report-print-metric-card">
            <span className="report-print-metric-label">Total HTTP Requests</span>
            <span className="report-print-metric-value">{data.metrics.totalRequests.toLocaleString()}</span>
            <span className="report-print-metric-sub">Analyzed by WAF Engine</span>
          </div>
          <div className="report-print-metric-card">
            <span className="report-print-metric-label">Blocked Violations</span>
            <span className="report-print-metric-value" style={{ color: 'var(--danger-color)' }}>{data.metrics.totalBlocked.toLocaleString()}</span>
            <span className="report-print-metric-sub">Malicious Payloads Dropped</span>
          </div>
          <div className="report-print-metric-card">
            <span className="report-print-metric-label">Attack Percentage</span>
            <span className="report-print-metric-value" style={{ color: 'var(--warning-color)' }}>{data.metrics.blockRate}%</span>
            <span className="report-print-metric-sub">Violations to traffic ratio</span>
          </div>
        </div>

        {reportType === 'executive' && (
          <div className="report-print-sections-layout">
            <div className="report-print-section" style={{ '--section-accent': 'var(--danger-color)' }}>
              <h3>Violation Category Breakdown</h3>
              <div className="report-print-table-wrapper">
                <AttackTypesTable attackTypes={data.attackTypes} tableClass="report-print-table" />
              </div>
            </div>
            <div className="report-print-section" style={{ '--section-accent': 'var(--danger-color)' }}>
              <h3>Top Attack Originators</h3>
              <div className="report-print-table-wrapper">
                <TopIpsTable topIps={data.topIps} tableClass="report-print-table" />
              </div>
            </div>
          </div>
        )}

        {reportType === 'threat' && (
          <div className="report-print-sections-layout">
            <div className="report-print-section" style={{ gridColumn: 'span 2', '--section-accent': 'var(--danger-color)' }}>
              <h3>Threat Intelligence & Signatures</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                Signature-based detections and CyberSentinel Engine Core Rule Set (CRS) triggers recorded for this timeframe.
              </p>
              <div className="report-print-grid-3" style={{ margin: '0 0 20px 0' }}>
                <div className="report-print-metric-card">
                  <span className="report-print-metric-label">SQL Injection Attacks</span>
                  <span className="report-print-metric-value" style={{ fontSize: '22px' }}>{data.metrics.sqlInjections}</span>
                  <span className="report-print-metric-sub">Signature database matches</span>
                </div>
                <div className="report-print-metric-card">
                  <span className="report-print-metric-label">Cross-Site Scripting (XSS)</span>
                  <span className="report-print-metric-value" style={{ fontSize: '22px' }}>{data.metrics.xssAttacks}</span>
                  <span className="report-print-metric-sub">Browser payloads filtered</span>
                </div>
                <div className="report-print-metric-card">
                  <span className="report-print-metric-label">Primary Attack Vector</span>
                  <span className="report-print-metric-value" style={{ fontSize: '18px', color: 'var(--accent-color)' }}>{data.metrics.topAttackType}</span>
                  <span className="report-print-metric-sub">Most frequent category</span>
                </div>
              </div>
              <h3 style={{ marginTop: '24px' }}>Top Threat Originators</h3>
              <div className="report-print-table-wrapper">
                <TopIpsTable topIps={data.topIps} tableClass="report-print-table" />
              </div>
            </div>
          </div>
        )}

        {reportType === 'compliance' && (
          <div className="report-print-sections-layout">
            <div className="report-print-section" style={{ '--section-accent': 'var(--accent-color)' }}>
              <h3>System Configuration & Compliance</h3>
              <div className="report-print-table-wrapper">
                <ComplianceTable data={data} tableClass="report-print-table" />
              </div>
            </div>
            <div className="report-print-section" style={{ '--section-accent': 'var(--warning-color)' }}>
              <h3>Security Audit Event Types</h3>
              <div className="report-print-table-wrapper">
                <AuditEventsTable audit={data.audit} tableClass="report-print-table" />
              </div>
            </div>
          </div>
        )}

        <div className="report-print-footer-card">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
            <div>
              <div className="report-print-summary-label">GATEWAY NODE STATUS</div>
              <div
                className="report-print-summary-value"
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px',
                  color: data.health.status === 'HEALTHY' ? 'var(--success-color)' : 'var(--sev-high)',
                }}
              >
                <ShieldCheck size={14} />
                <span>{data.health.status}</span>
              </div>
            </div>
            <div>
              <div className="report-print-summary-label">WAF CORE ENGINE</div>
              <div className="report-print-summary-value">{data.health.engine}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function SecurityReports() {
  const [timeframe, setTimeframe] = useState('24h'); // '24h', '7d', '30d'
  const [reportType, setReportType] = useState('executive'); // 'executive', 'threat', 'compliance'
  const [loading, setLoading] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState('');
  const reportRef = useRef(null);

  const generateReport = async () => {
    setLoading(true);
    setError('');
    try {
      const hours = timeframe === '24h' ? 24 : timeframe === '7d' ? 168 : 720;
      // Fetch data from existing API endpoints
      const [stats, attackTypes, topIps, health, auditStatsRes] = await Promise.all([
        getStats(hours),
        getAttackTypes(hours),
        getTopIPs(hours),
        getHealth(),
        getSecurityStatistics(hours)
      ]);

      // Compliance-table data comes from admin-only settings endpoints —
      // fetched separately (not in the Promise.all above) so a non-admin
      // analyst viewing this page still gets the rest of the report instead
      // of the whole thing failing on a 403. `null` on failure means "could
      // not verify," which the compliance table renders honestly instead of
      // defaulting to a fake green checkmark.
      let wafSettings = null, hardeningSettings = null, logSettings = null, protectedApps = null;
      try {
        [wafSettings, hardeningSettings, logSettings, protectedApps] = await Promise.all([
          getWafSettings(), getHardeningSettings(), getLogSettings(), getProtectedApps(),
        ]);
      } catch (complianceErr) {
        console.warn('Could not load compliance settings (may require admin role):', complianceErr);
      }

      // Process and structure the data nicely for the report
      const totalRequests = stats?.total_requests || 0;
      const totalBlocked = stats?.total_blocked || 0;
      const blockRate = totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(2) : '0.00';
      
      // Determine overall risk rating. blockRate is already a ratio (blocked/
      // total requests) so it's timeframe-independent, but the absolute
      // totalBlocked thresholds below were calibrated for a 24h window — used
      // as-is against a 30d report they'd flag a perfectly normal month
      // (250 blocks over 30 days ≈ 8/day) as the same "HIGH" severity as
      // 250 blocks in a single day. Normalize to a blocked-per-day rate
      // before comparing against the (24h-calibrated) thresholds.
      const blockedPerDay = totalBlocked / (hours / 24);
      let riskLevel = 'LOW';
      let riskColor = 'var(--success-color)'; // green
      if (blockedPerDay > 1000 || parseFloat(blockRate) > 10.0) {
        riskLevel = 'CRITICAL';
        riskColor = 'var(--danger-color)'; // red
      } else if (blockedPerDay > 200 || parseFloat(blockRate) > 3.0) {
        riskLevel = 'HIGH';
        riskColor = 'var(--sev-high)'; // orange
      } else if (blockedPerDay > 20 || parseFloat(blockRate) > 0.5) {
        riskLevel = 'MEDIUM';
        riskColor = 'var(--ml-color)'; // purple
      }

      // Auto-generated narrative summary — plain-language framing of the
      // numeric metrics above, since a page of raw tables/counters with no
      // prose reads as a data dump rather than a report an executive or
      // auditor can skim in 15 seconds.
      const topAttack = attackTypes?.length
        ? [...attackTypes].sort((a, b) => (b.count || 0) - (a.count || 0))[0]
        : null;
      const topSourceIp = topIps?.length ? topIps[0] : null;
      const narrativeSummary = [
        `During the selected ${timeframe === '24h' ? 'last 24 hours' : timeframe === '7d' ? 'last 7 days' : 'last 30 days'}, the CyberSentinel WAF Engine inspected ${totalRequests.toLocaleString()} HTTP requests and blocked ${totalBlocked.toLocaleString()} as malicious (${blockRate}% of total traffic).`,
        topAttack
          ? `The most frequently detected violation category was "${topAttack.attack_type || 'Unknown / Custom'}" with ${topAttack.count.toLocaleString()} detections.`
          : `No categorized violations were recorded in this window.`,
        topSourceIp
          ? `The most active single source of malicious traffic was ${topSourceIp.ip || topSourceIp.client_ip || topSourceIp.source_ip || 'an unidentified IP'}${topSourceIp.country ? ` (${topSourceIp.country})` : ''}, responsible for ${(topSourceIp.count || 0).toLocaleString()} flagged requests.`
          : ``,
        `Based on blocked-traffic volume and violation rate, this reporting period is assessed as ${riskLevel} risk.`,
      ].filter(Boolean).join(' ');

      const generatedAtDate = new Date();
      // Report ID: deterministic-enough to be a real reference number (not
      // random per re-render) — timestamp + timeframe + report type — so an
      // analyst citing "report CSR-..." in an incident ticket is citing
      // something reproducible, not a throwaway value.
      const reportId = `CSR-${generatedAtDate.getTime().toString(36).toUpperCase()}-${timeframe.toUpperCase()}`;

      setReportData({
        reportId,
        narrativeSummary,
        generatedAt: generatedAtDate.toLocaleString(),
        timeframe: timeframe === '24h' ? 'Last 24 Hours' : timeframe === '7d' ? 'Last 7 Days' : 'Last 30 Days',
        riskLevel,
        riskColor,
        metrics: {
          totalRequests,
          totalBlocked,
          blockRate,
          // stats?.total_unique_ips ?? topIps?.length ?? 0 — a legitimate 0
          // (no unique IPs seen) must not fall through to the topIps-length
          // fallback the way `||` would treat it as missing.
          uniqueIps: stats?.total_unique_ips ?? topIps?.length ?? 0,
          sqlInjections: stats?.sqli_count || 0,
          xssAttacks: stats?.xss_count || 0,
          topAttackType: stats?.top_attack_type || '-'
        },
        attackTypes: attackTypes || [],
        topIps: topIps?.slice(0, 5) || [],
        health: {
          // A missing/failed health check must not default to "HEALTHY" —
          // that's the one outcome that's provably wrong when the check
          // itself couldn't run.
          status: health?.status || 'UNKNOWN',
          engine: 'CyberSentinel Engine v2.0',
          antiDefacement: health?.anti_defacement?.status || 'UNKNOWN'
        },
        // Real system state for the Compliance report — `null` fields mean
        // "could not verify" (see the try/catch above), rendered as a
        // distinct neutral status rather than silently reported as passing.
        compliance: {
          engineEnforcement: wafSettings?.secRuleEngine ?? null, // 'On' | 'Off'
          tlsHardening: hardeningSettings ? !!hardeningSettings.hsts_enabled : null,
          adminAuditLogging: logSettings ? !!logSettings.auditEnabled : null,
          activeProtectedHosts: protectedApps
            ? protectedApps.filter((a) => a.is_active).length
            : null,
          totalProtectedHosts: protectedApps ? protectedApps.length : null,
        },
        audit: auditStatsRes || {
          total_events: 0,
          by_type: {}
        }
      });
    } catch (err) {
      console.error('Failed to generate security report:', err);
      setError('Failed to fetch structured report data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Generate on initial load
  useEffect(() => {
    generateReport();
  }, [timeframe]);

  const handlePrint = () => {
    window.print();
  };

  const handleExportCSV = () => {
    // Forward directly to the backend CSV export link, scoped to the
    // currently selected report timeframe (previously always exported the
    // full, unfiltered log history regardless of what was on screen).
    const hours = timeframe === '24h' ? 24 : timeframe === '7d' ? 168 : 720;
    window.location.href = `${window.location.protocol}//${window.location.host}/api/stats/export/csv?hours=${hours}`;
  };

  const handleExportJSON = () => {
    if (!reportData) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `waf_security_report_${timeframe}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="security-reports-tab">
      
      {/* Report controls (hidden when printing) */}
      <div className="report-controls-panel no-print">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Select Timeframe</span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button 
              className={`report-btn ${timeframe === '24h' ? 'active' : ''}`}
              onClick={() => setTimeframe('24h')}
            >
              24 Hours
            </button>
            <button 
              className={`report-btn ${timeframe === '7d' ? 'active' : ''}`}
              onClick={() => setTimeframe('7d')}
            >
              7 Days
            </button>
            <button 
              className={`report-btn ${timeframe === '30d' ? 'active' : ''}`}
              onClick={() => setTimeframe('30d')}
            >
              30 Days
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Report Template</span>
          <select 
            className="report-select"
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
          >
            <option value="executive">Executive Summary Report</option>
            <option value="threat">Threat Intelligence Report</option>
            <option value="compliance">System Audit & Compliance</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', marginLeft: 'auto' }}>
          <button 
            className="report-action-btn primary"
            onClick={generateReport}
            disabled={loading}
          >
            {loading ? <RefreshCw size={14} className="animate-spin" /> : <Activity size={14} />}
            <span>Re-Generate</span>
          </button>
          
          <button 
            className="report-action-btn secondary"
            onClick={handlePrint}
            disabled={!reportData || loading}
          >
            <Printer size={14} />
            <span>Print / Save PDF</span>
          </button>

          <button 
            className="report-action-btn secondary"
            onClick={handleExportCSV}
            disabled={!reportData || loading}
          >
            <Download size={14} />
            <span>Export CSV</span>
          </button>

          <button 
            className="report-action-btn secondary"
            onClick={handleExportJSON}
            disabled={!reportData || loading}
          >
            <FileJson size={14} />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="report-error no-print">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Structured report preview sheet */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '100px 0', color: 'var(--text-secondary)' }} className="no-print">
          <Activity size={36} className="animate-spin" style={{ color: 'var(--accent-color)', marginBottom: '16px' }} />
          <div>Compiling structured report data...</div>
        </div>
      )}

      {reportData && !loading && (
        <motion.div
          ref={reportRef}
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <ReportAppView data={reportData} reportType={reportType} />
          <ReportPrintView data={reportData} reportType={reportType} />
        </motion.div>
      )}

      <style>{`
        .security-reports-tab {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .report-controls-panel {
          background: var(--surface-subtle);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          border: 1px solid var(--surface-strong);
          border-radius: 12px;
          padding: 20px 24px;
          display: flex;
          align-items: center;
          gap: 24px;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        }

        .report-btn {
          padding: 8px 18px;
          background: transparent;
          border: 1px solid transparent;
          border-radius: 6px;
          color: var(--text-secondary);
          font-weight: 600;
          font-size: 13px;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        .report-btn.active {
          background: rgba(79, 70, 229, 0.1);
          border-color: rgba(79, 70, 229, 0.3);
          color: var(--accent-color);
          box-shadow: 0 0 12px rgba(79, 70, 229, 0.15);
        }

        .report-btn:hover:not(.active) {
          background: var(--surface-hover);
          color: var(--text-primary);
        }

        .report-select {
          padding: 8px 36px 8px 16px;
          background: var(--surface-subtle);
          border: 1px solid var(--border-strong);
          border-radius: 6px;
          color: var(--text-primary);
          font-size: 13px;
          font-weight: 600;
          outline: none;
          cursor: pointer;
          min-width: 240px;
          transition: all 0.2s ease;
          appearance: none;
          background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23a1a1aa' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
          background-repeat: no-repeat;
          background-position: right 12px center;
          background-size: 14px;
        }

        .report-select:focus, .report-select:hover {
          border-color: var(--accent-color);
          background-color: rgba(79, 70, 229, 0.05);
        }

        .report-action-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 9px 18px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
          border: 1px solid transparent;
        }

        .report-action-btn.primary {
          background: var(--accent-color);
          color: #fff;
          box-shadow: 0 4px 14px rgba(79, 70, 229, 0.25);
          border: none;
        }

        .report-action-btn.primary:hover:not(:disabled) {
          box-shadow: 0 6px 20px rgba(79, 70, 229, 0.4);
          transform: translateY(-1px);
        }

        .report-action-btn.secondary {
          background: var(--surface-subtle);
          border-color: var(--border-strong);
          color: var(--text-secondary);
        }

        .report-action-btn.secondary:hover:not(:disabled) {
          background: var(--surface-strong);
          border-color: var(--border-strong);
          color: var(--text-primary);
          transform: translateY(-1px);
        }

        .report-action-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
          transform: none !important;
          box-shadow: none !important;
        }

        .report-error {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 12px 16px;
          background: rgba(255,59,92,0.08);
          border: 1px solid rgba(255,59,92,0.2);
          border-radius: 8px;
          font-size: 13px;
          color: var(--danger-color);
        }

        /* Shared risk meter — plain colors via inline style, not theme
           tokens, so it looks identical (and correctly semantic) in both
           the app view and the print view without needing its own variant. */
        .report-risk-meter {
          display: flex;
          gap: 3px;
          margin-top: 10px;
          min-width: 140px;
        }

        .report-risk-meter-segment {
          flex: 1;
          height: 6px;
          border-radius: 3px;
          opacity: 0.22;
        }

        .report-risk-meter-segment.active {
          opacity: 1;
          box-shadow: 0 0 0 1px rgba(0,0,0,0.15) inset;
        }

        /* ===================================================================
           APPLICATION VIEW — native CyberSentinel dashboard presentation.
           Uses .glass-panel and the app's real theme variables throughout;
           deliberately defines NO color overrides of its own, so dark/light
           theme switching works exactly like every other page for free.
           =================================================================== */
        .report-app-view {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .report-app-header { padding: 24px; }

        .report-app-badge {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.06em;
          padding: 3px 9px;
          border-radius: 4px;
          background: var(--accent-bg, rgba(129,140,248,0.12));
          color: var(--accent-color);
          border: 1px solid var(--accent-border, rgba(129,140,248,0.3));
          text-transform: uppercase;
        }

        .report-app-title {
          margin: 10px 0 6px;
          font-size: 24px;
          font-weight: 700;
          font-family: var(--font-display);
          letter-spacing: -0.02em;
          color: var(--text-primary);
        }

        .report-app-meta {
          font-size: 12px;
          color: var(--text-secondary);
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }

        .report-app-meta strong {
          color: var(--text-primary);
          font-weight: 600;
          margin-right: 4px;
        }

        .report-app-meta-sep { color: var(--border-strong); }

        .report-app-risk {
          text-align: right;
          padding: 14px 22px;
          border-radius: 10px;
          background: var(--surface-subtle);
          border: 1px solid var(--border-color, var(--surface-strong));
          flex-shrink: 0;
        }

        .report-app-risk-label {
          font-size: 10px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.06em;
        }

        .report-app-risk-value {
          font-size: 22px;
          font-weight: 800;
          letter-spacing: 0.02em;
        }

        .report-app-narrative { padding: 22px 24px; }

        .report-app-narrative h3 {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 14px;
          font-weight: 700;
          color: var(--text-primary);
          margin: 0 0 12px 0;
        }

        .report-app-narrative p {
          font-size: 13px;
          line-height: 1.7;
          color: var(--text-primary);
          margin: 0;
        }

        .report-app-stat-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 16px;
        }

        .report-app-stat-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .report-app-mini-stat {
          background: var(--surface-subtle);
          border: 1px solid var(--border-subtle, var(--surface-hover));
          border-radius: 8px;
          padding: 16px 18px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .report-app-stat-label {
          font-size: 11px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .report-app-stat-value {
          font-size: 26px;
          font-weight: 800;
          color: var(--text-primary);
          font-family: var(--font-mono);
        }

        .report-app-stat-sub {
          font-size: 12px;
          color: var(--text-muted);
        }

        .report-app-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
          gap: 20px;
        }

        .report-app-section {
          padding: 22px 24px;
          border-left: 3px solid var(--section-accent, var(--accent-color));
        }

        .report-app-section h3 {
          font-size: 14px;
          font-weight: 700;
          color: var(--text-primary);
          margin: 0 0 14px 0;
          padding-bottom: 10px;
          border-bottom: 1px solid var(--border-subtle, var(--surface-hover));
        }

        .report-app-table-wrapper { overflow-x: auto; }

        .report-app-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 12.5px;
        }

        .report-app-table th {
          text-align: left;
          padding: 8px 10px;
          color: var(--text-secondary);
          font-weight: 700;
          border-bottom: 1px solid var(--surface-strong);
          font-size: 10.5px;
          text-transform: uppercase;
          letter-spacing: 0.04em;
        }

        .report-app-table td {
          padding: 9px 10px;
          border-bottom: 1px solid var(--border-subtle, var(--surface-hover));
          color: var(--text-primary);
        }

        .report-app-table tbody tr:hover td {
          background: var(--surface-subtle);
        }

        .report-app-footer { padding: 20px 24px; }

        .report-app-footer-label {
          font-size: 9px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 4px;
        }

        .report-app-footer-value {
          font-size: 12px;
          font-weight: 600;
          color: var(--text-primary);
        }

        /* ===================================================================
           PRINT / SAVE-AS-PDF VIEW — a fixed white "paper" A4 document.
           Hidden on screen (display:none) unconditionally; only @media
           print below reveals it, and only for this subtree — the
           application view above is hidden in print instead, so the two
           never render at the same time in either context.
           =================================================================== */
        .report-print-view {
          display: none;
        }

        .print-footer { display: none; }

        @page {
          size: A4;
          /* Bottom margin reserves room for the fixed footer so it can't
             overlap the last line of content on each printed page. */
          margin: 14mm 14mm 22mm 14mm;
        }

        @media print {
          html, body {
            background: #fff !important;
          }

          /* Real, current layout chrome that must never appear in a
             printout — .siem-topbar is this app's actual top-bar class
             (App.jsx); .report-app-view is the on-screen dashboard
             presentation, which is swapped out for .report-print-view
             below rather than printed as-is. */
          .sidebar, .siem-topbar, .subtabs-container, .no-print, .app-footer,
          .report-app-view {
            display: none !important;
          }

          .report-print-view {
            display: block !important;
          }

          .main-content {
            padding: 0 !important;
            margin: 0 !important;
            width: 100% !important;
          }

          .print-footer {
            display: block !important;
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            text-align: center;
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.03em;
            color: #52525b;
            border-top: 1px solid #ddd;
            padding-top: 6px;
          }

          .report-print-sections-layout {
            grid-template-columns: 1fr;
          }

          .report-print-grid-3 {
            grid-template-columns: repeat(3, 1fr);
          }

          /* overflow-x:auto (screen: horizontal scroll) has nothing to
             scroll on paper — it just clips content past the page edge.
             Let a wide table wrap/shrink instead of losing columns. */
          .report-print-table-wrapper {
            overflow-x: visible;
          }

          .report-print-table {
            font-size: 11px;
          }

          .report-risk-meter-segment,
          .report-print-table tbody tr:nth-child(even) td,
          .report-print-section {
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
          }
        }

        /* Paper palette — fixed regardless of the app's dark/light theme,
           scoped to .report-print-sheet only. Exact hex values from this
           app's own light-theme tokens (index.css :root[data-theme="light"])
           so the printed report's severity/risk colors are literally the
           same palette as the rest of the dashboard, just rendered on
           paper instead of glass. */
        .report-print-sheet {
          --text-primary:     #18181f;
          --text-secondary:   #52525b;
          --text-muted:       #8b8b96;
          --danger-color:     #e11d48;
          --warning-color:    #b45309;
          --success-color:    #059669;
          --sev-high:         #c2410c;
          --sev-medium:       #a16207;
          --sev-low:          #1d4ed8;
          --accent-color:     #4f46e5;
          --accent-bg:        #eef2ff;
          --accent-border:    #c7d2fe;
          --surface-subtle:   #f8f9fb;
          --surface-hover:    #eef0f3;
          --surface-strong:   #e4e4e7;
          --border-color:     #e4e4e7;
          --border-subtle:    #ececf0;
          --border-strong:    #d4d4d8;
          --inset-bg:         #f8f9fb;
          --bg-surface:       #ffffff;
          --shadow-card:      0 1px 2px rgba(16,16,24,0.04);
          --chart-tooltip-bg: #ffffff;
          --cyan-color:       #0e7490;
          --ml-color:         #6d28d9;
          --pink-color:       #be185d;

          background: var(--bg-surface);
          color: var(--text-primary);
          max-width: 920px;
          margin: 0 auto;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          padding: 48px 56px 40px;
          box-shadow: 0 12px 32px rgba(16,16,24,0.16), 0 2px 6px rgba(16,16,24,0.08);
          font-family: var(--font-display);
          line-height: 1.6;
        }

        .report-print-sheet h1,
        .report-print-sheet h2,
        .report-print-sheet h3 {
          font-family: var(--font-display);
          color: var(--text-primary);
        }

        .report-print-letterhead {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-bottom: 20px;
          margin-bottom: 20px;
          border-bottom: 3px solid var(--text-primary);
        }

        .report-print-letterhead-brand {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .report-print-letterhead-mark {
          width: 36px;
          height: 36px;
          border-radius: 8px;
          background: var(--text-primary);
          color: #fff;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 800;
          font-size: 14px;
          letter-spacing: 0.5px;
          flex-shrink: 0;
        }

        .report-print-letterhead-name {
          font-size: 16px;
          font-weight: 800;
          letter-spacing: -0.01em;
          color: var(--text-primary);
        }

        .report-print-letterhead-tagline {
          font-size: 11px;
          color: var(--text-secondary);
          font-weight: 500;
        }

        .report-print-letterhead-classification {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--text-secondary);
          padding: 4px 10px;
          border: 1px solid var(--border-strong);
          border-radius: 4px;
        }

        .report-print-header-card {
          padding-bottom: 28px;
          margin-bottom: 28px;
          border-bottom: 1px solid var(--border-color);
          page-break-inside: avoid;
        }

        .report-print-badge {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.06em;
          padding: 3px 9px;
          border-radius: 4px;
          background: var(--accent-bg);
          color: var(--accent-color);
          border: 1px solid var(--accent-border);
          text-transform: uppercase;
        }

        .report-print-title {
          margin: 10px 0 6px;
          font-size: 26px;
          font-weight: 700;
          letter-spacing: -0.02em;
        }

        .report-print-meta {
          font-size: 12px;
          color: var(--text-secondary);
          margin-top: 6px;
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }

        .report-print-meta strong {
          color: var(--text-primary);
          font-weight: 600;
          margin-right: 4px;
        }

        .report-print-meta-sep { color: var(--border-strong); }

        .report-print-risk-badge {
          text-align: right;
          padding: 14px 22px;
          border-radius: 8px;
          background: var(--surface-subtle);
          border: 1px solid var(--border-color);
          flex-shrink: 0;
        }

        .report-print-risk-label {
          font-size: 10px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.06em;
        }

        .report-print-risk-value {
          font-size: 22px;
          font-weight: 800;
          letter-spacing: 0.02em;
        }

        .report-print-grid-3 {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 16px;
          margin-bottom: 24px;
        }

        .report-print-metric-card {
          background: var(--surface-subtle);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 18px 20px;
          display: flex;
          flex-direction: column;
          gap: 4px;
          page-break-inside: avoid;
        }

        .report-print-metric-label {
          font-size: 11px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .report-print-metric-value {
          font-size: 26px;
          font-weight: 800;
          color: var(--text-primary);
          font-family: var(--font-mono);
        }

        .report-print-metric-sub {
          font-size: 12px;
          color: var(--text-muted);
        }

        .report-print-sections-layout {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
          gap: 20px;
          margin-bottom: 24px;
        }

        .report-print-section {
          background: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-left: 3px solid var(--section-accent, var(--accent-color));
          border-radius: 6px;
          padding: 22px 24px;
          page-break-inside: avoid;
        }

        .report-print-section h3 {
          font-size: 14px;
          font-weight: 700;
          margin: 0 0 14px 0;
          padding-bottom: 10px;
          border-bottom: 1px solid var(--border-color);
        }

        .report-print-table-wrapper { overflow-x: auto; }

        .report-print-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 12.5px;
        }

        .report-print-table th {
          text-align: left;
          padding: 8px 10px;
          color: var(--text-secondary);
          font-weight: 700;
          border-bottom: 2px solid var(--border-strong);
          font-size: 10.5px;
          text-transform: uppercase;
          letter-spacing: 0.04em;
        }

        .report-print-table td {
          padding: 9px 10px;
          border-bottom: 1px solid var(--border-subtle);
          color: var(--text-primary);
        }

        .report-print-table tr {
          page-break-inside: avoid;
        }

        .report-print-table tbody tr:nth-child(even) td {
          background: var(--surface-subtle);
        }

        .report-print-footer-card {
          margin-top: 8px;
          padding: 18px 22px;
          background: var(--surface-subtle);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          page-break-inside: avoid;
        }

        .report-print-summary-label {
          font-size: 9px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 4px;
        }

        .report-print-summary-value {
          font-size: 12px;
          font-weight: 600;
          color: var(--text-primary);
        }
      `}</style>
    </div>
  );
}
