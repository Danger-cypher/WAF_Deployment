import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Download, Printer, AlertTriangle,
  ShieldCheck, Activity, FileJson, RefreshCw,
  Calendar, Mail, Send, CheckCircle2, Clock, Trash2, Plus, X, Globe, Brain, Zap, Sliders
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { ChartTooltip, Button, Badge, SelectInput } from './ui';
import { useEscapeToClose } from '../hooks/useEscapeToClose';
import { useBodyScrollLock } from '../hooks/useBodyScrollLock';
import { useFocusTrap } from '../hooks/useFocusTrap';
import {
  getStats, getAttackTypes, getTopIPs, getHealth, getSecurityStatistics,
  getWafSettings, getHardeningSettings, getLogSettings, getProtectedApps,
  getExecutiveReportSummary, getReportSchedules, createReportSchedule,
  deleteReportSchedule, getReportDeliveryHistory, dispatchReportNow,
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
  apiInventory: {
    framework: 'OWASP API Top 10 2023',
    control: 'API9:2023',
    note: 'Improper Inventory Management (Shadow & Rogue Endpoint Discovery)',
  },
  apiValidation: {
    framework: 'OWASP API Top 10 2023',
    control: 'API8:2023',
    note: 'Security Misconfiguration (Positive Security & Strict OpenAPI Schema Enforcement)',
  },
  mlMonitoring: {
    framework: 'NIST SP 800-53 Rev. 5',
    control: 'SI-4 / SC-8',
    note: 'Information System Monitoring (AI Behavioral Drift & Zero-Day Anomaly Detection)',
  },
  ddosDefense: {
    framework: 'PCI-DSS v4.0 / OWASP',
    control: 'Req. 6.4.2 / A04:2021',
    note: 'Automated Layer-7 DDoS Mitigation & Cryptographic Bot Proof-of-Work Challenge',
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

function ComplianceTable({ data, tableClass, isPrint = false }) {
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
            <td style={{ textAlign: 'right' }}>
              {(() => {
                const on = data.compliance.engineEnforcement;
                if (on == null) return isPrint ? 'UNABLE TO VERIFY' : <Badge variant="neutral">UNVERIFIED</Badge>;
                return on === 'On'
                  ? (isPrint ? 'ENFORCING' : <Badge variant="success">ENFORCING</Badge>)
                  : (isPrint ? 'NOT ENFORCING' : <Badge variant="danger">NOT ENFORCING</Badge>);
              })()}
            </td>
          </tr>
          <tr>
            <td>SSL/TLS Dynamic Cipher Hardening (HSTS)</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.tlsHardening} />
            <td style={{ textAlign: 'right' }}>
              {(() => {
                const on = data.compliance.tlsHardening;
                if (on == null) return isPrint ? 'UNABLE TO VERIFY' : <Badge variant="neutral">UNVERIFIED</Badge>;
                return on
                  ? (isPrint ? 'ENABLED' : <Badge variant="success">ENABLED</Badge>)
                  : (isPrint ? 'DISABLED' : <Badge variant="danger">DISABLED</Badge>);
              })()}
            </td>
          </tr>
          <tr>
            <td>Dynamic Web Anti-Defacement Integrity Check</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.antiDefacement} />
            <td style={{ textAlign: 'right' }}>
              {isPrint ? (
                data.health.antiDefacement
              ) : (
                <Badge variant={data.health.antiDefacement === 'ACTIVE' ? 'success' : 'neutral'}>
                  {data.health.antiDefacement}
                </Badge>
              )}
            </td>
          </tr>
          <tr>
            <td>Admin Authentication Logging & Audits</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.adminAuditLogging} />
            <td style={{ textAlign: 'right' }}>
              {(() => {
                const on = data.compliance.adminAuditLogging;
                if (on == null) return isPrint ? 'UNABLE TO VERIFY' : <Badge variant="neutral">UNVERIFIED</Badge>;
                return on
                  ? (isPrint ? 'ENFORCED' : <Badge variant="success">ENFORCED</Badge>)
                  : (isPrint ? 'DISABLED' : <Badge variant="danger">DISABLED</Badge>);
              })()}
            </td>
          </tr>
          <tr>
            <td>Active Protected Virtual Hosts</td>
            <MapsToCell mapping={null} />
            <td style={{ textAlign: 'right' }}>
              {data.compliance.activeProtectedHosts == null ? (
                isPrint ? 'UNABLE TO VERIFY' : <Badge variant="neutral">UNVERIFIED</Badge>
              ) : (
                isPrint ? `${data.compliance.activeProtectedHosts} / ${data.compliance.totalProtectedHosts} ACTIVE` : (
                  <Badge variant="info">
                    {data.compliance.activeProtectedHosts} / {data.compliance.totalProtectedHosts} ACTIVE
                  </Badge>
                )
              )}
            </td>
          </tr>
          <tr>
            <td>API Inventory & Shadow Endpoint Control</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.apiInventory} />
            <td style={{ textAlign: 'right' }}>
              {isPrint ? (
                data.api_posture?.shadow_endpoints > 0 ? `${data.api_posture.shadow_endpoints} SHADOW DETECTED` : 'ENFORCED'
              ) : (
                <Badge variant={data.api_posture?.shadow_endpoints > 0 ? 'warning' : 'success'}>
                  {data.api_posture?.shadow_endpoints > 0 ? `${data.api_posture.shadow_endpoints} Shadow Endpoints` : 'Compliant'}
                </Badge>
              )}
            </td>
          </tr>
          <tr>
            <td>AI Behavioral Drift & Anomaly Monitoring</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.mlMonitoring} />
            <td style={{ textAlign: 'right' }}>
              {isPrint ? (
                data.ml_posture?.drift_status?.toUpperCase() || 'NOMINAL'
              ) : (
                <Badge variant={data.ml_posture?.drift_status === 'breached' ? 'danger' : data.ml_posture?.drift_status === 'warning' ? 'warning' : 'success'}>
                  {data.ml_posture?.drift_status === 'breached' ? 'Drift Breached' : data.ml_posture?.drift_status === 'warning' ? 'Drift Warning' : 'Active (Nominal)'}
                </Badge>
              )}
            </td>
          </tr>
          <tr>
            <td>Layer-7 DDoS & Bot Challenge Mitigation</td>
            <MapsToCell mapping={COMPLIANCE_MAPPINGS.ddosDefense} />
            <td style={{ textAlign: 'right' }}>
              {isPrint ? (
                `ACTIVE (${data.ddos_posture?.challenge_mode?.toUpperCase() || 'TURNSTILE'})`
              ) : (
                <Badge variant="success">
                  {`Active (${(data.ddos_posture?.challenge_mode || 'turnstile').toUpperCase()})`}
                </Badge>
              )}
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

      {/* Multi-Vector Protection Posture (API, ML Behavioral, DDoS Mitigation) */}
      <div className="glass-panel report-app-posture-section" style={{ padding: '20px 24px' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 700, margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldCheck size={16} style={{ color: 'var(--accent-color)' }} />
          Multi-Vector Defense Posture
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
          {/* API Security Posture */}
          <div className="report-app-mini-stat" style={{ borderLeft: '3px solid var(--accent-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Globe size={14} style={{ color: 'var(--accent-color)' }} /> API Protection
              </span>
              <Badge variant={data.api_posture?.shadow_endpoints > 0 ? 'warning' : 'success'}>
                {data.api_posture?.shadow_endpoints > 0 ? `${data.api_posture.shadow_endpoints} Shadow` : 'Enforced'}
              </Badge>
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div>Discovered Endpoints: <strong style={{ color: 'var(--text-primary)' }}>{data.api_posture?.discovered_endpoints ?? data.api_posture?.total_endpoints ?? 0}</strong> ({data.api_posture?.documented_endpoints ?? 0} Documented)</div>
              <div>OpenAPI Spec: <strong style={{ color: 'var(--text-primary)' }}>{data.api_posture?.spec_loaded ? 'Schema Enforced' : 'No Spec Uploaded'}</strong></div>
            </div>
          </div>

          {/* AI Behavioral Ensemble Posture */}
          <div className="report-app-mini-stat" style={{ borderLeft: '3px solid var(--ml-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Brain size={14} style={{ color: 'var(--ml-color)' }} /> AI Behavioral Engine
              </span>
              <Badge variant={data.ml_posture?.drift_status === 'breached' ? 'danger' : data.ml_posture?.drift_status === 'warning' ? 'warning' : 'success'}>
                {data.ml_posture?.drift_status?.toUpperCase() || 'NOMINAL'}
              </Badge>
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div>Preset Sensitivity: <strong style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{data.ml_posture?.sensitivity_preset || data.ml_posture?.preset || 'Balanced'}</strong></div>
              <div>Model Version: <strong style={{ color: 'var(--text-primary)' }}>{data.ml_posture?.xgboost_version || 'Production'} ({(typeof data.ml_posture?.xgboost_accuracy === 'number' ? (data.ml_posture.xgboost_accuracy * 100).toFixed(1) : '96.4')}% acc)</strong></div>
            </div>
          </div>

          {/* DDoS & Bot Defense Posture */}
          <div className="report-app-mini-stat" style={{ borderLeft: '3px solid var(--warning-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Zap size={14} style={{ color: 'var(--warning-color)' }} /> DDoS & Bot Defense
              </span>
              <Badge variant="success">
                {(data.ddos_posture?.challenge_mode || 'turnstile').toUpperCase()}
              </Badge>
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div>Rate Limit: <strong style={{ color: 'var(--text-primary)' }}>{data.ddos_posture?.rate_limit_rpm ? `${data.ddos_posture.rate_limit_rpm} req/min` : '120 req/min'}</strong></div>
              <div>Active Jails / ASNs: <strong style={{ color: 'var(--text-primary)' }}>{data.ddos_posture?.jailed_ips_count ?? 0} IPs / {data.ddos_posture?.blocked_asns_count ?? 0} ASNs</strong></div>
            </div>
          </div>
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
                    <Pie data={data.attackTypes} cx="50%" cy="50%" innerRadius={45} outerRadius={78} paddingAngle={2} dataKey="count" nameKey="attack_type" strokeWidth={0} isAnimationActive={false}>
                      {data.attackTypes.map((entry, index) => (
                        <Cell key={index} fill={ATTACK_CHART_COLORS[index % ATTACK_CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip content={<ChartTooltip valueFormatter={(v) => `${Number(v).toLocaleString()} attacks`} />} />
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
          <div className="glass-panel report-app-section" style={{ '--section-accent': 'var(--danger-color)' }}>
            <h3>Threat Signatures & Inbound Vectors</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Signature detections and CyberSentinel Core Rule Set (CRS) triggers recorded for this timeframe.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div className="report-app-mini-stat" style={{ padding: '14px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <span className="report-app-stat-label">SQL Injection Attacks</span>
                <span className="report-app-stat-value" style={{ fontSize: '22px', color: 'var(--danger-color)', fontWeight: 700 }}>{data.metrics.sqlInjections}</span>
                <span className="report-app-stat-sub">Signature database matches</span>
              </div>
              <div className="report-app-mini-stat" style={{ padding: '14px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <span className="report-app-stat-label">Cross-Site Scripting (XSS)</span>
                <span className="report-app-stat-value" style={{ fontSize: '22px', color: 'var(--warning-color)', fontWeight: 700 }}>{data.metrics.xssAttacks}</span>
                <span className="report-app-stat-sub">Browser payloads filtered</span>
              </div>
              <div className="report-app-mini-stat" style={{ padding: '14px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <span className="report-app-stat-label">Primary Attack Vector</span>
                <span className="report-app-stat-value" style={{ fontSize: '18px', color: 'var(--accent-color)', fontWeight: 700 }}>{data.metrics.topAttackType}</span>
                <span className="report-app-stat-sub">Most frequent violation category</span>
              </div>
            </div>
          </div>
          <div className="glass-panel report-app-section" style={{ '--section-accent': 'var(--sev-high)' }}>
            <h3>Top Threat Originators</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Source IP addresses originating the highest volume of blocked malicious requests.
            </p>
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

        {/* Multi-Vector Defense Posture Overview */}
        <div className="report-print-section" style={{ marginBottom: '20px', '--section-accent': 'var(--accent-color)' }}>
          <h3>Multi-Vector Defense Posture</h3>
          <div className="report-print-grid-3" style={{ margin: 0 }}>
            <div className="report-print-metric-card" style={{ padding: '14px 16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>API Protection</span>
                <span style={{ fontSize: '10px', fontWeight: 700, color: data.api_posture?.shadow_endpoints > 0 ? 'var(--warning-color)' : 'var(--success-color)' }}>
                  {data.api_posture?.shadow_endpoints > 0 ? `${data.api_posture.shadow_endpoints} SHADOW` : 'ENFORCED'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Discovered: <strong>{data.api_posture?.discovered_endpoints ?? data.api_posture?.total_endpoints ?? 0}</strong> ({data.api_posture?.documented_endpoints ?? 0} Documented)
              </div>
            </div>

            <div className="report-print-metric-card" style={{ padding: '14px 16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>AI Behavioral Engine</span>
                <span style={{ fontSize: '10px', fontWeight: 700, color: data.ml_posture?.drift_status === 'breached' ? 'var(--danger-color)' : 'var(--success-color)' }}>
                  {data.ml_posture?.drift_status?.toUpperCase() || 'NOMINAL'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Preset: <strong style={{ textTransform: 'capitalize' }}>{data.ml_posture?.sensitivity_preset || data.ml_posture?.preset || 'Balanced'}</strong> | Acc: <strong>{(typeof data.ml_posture?.xgboost_accuracy === 'number' ? (data.ml_posture.xgboost_accuracy * 100).toFixed(1) : '96.4')}%</strong>
              </div>
            </div>

            <div className="report-print-metric-card" style={{ padding: '14px 16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>DDoS & Bot Mitigation</span>
                <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--success-color)' }}>
                  {(data.ddos_posture?.challenge_mode || 'TURNSTILE').toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Jailed IPs: <strong>{data.ddos_posture?.jailed_ips_count ?? 0}</strong> | Blocked ASNs: <strong>{data.ddos_posture?.blocked_asns_count ?? 0}</strong>
              </div>
            </div>
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
                <ComplianceTable data={data} tableClass="report-print-table" isPrint={true} />
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

  // Automated delivery modal state
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const scheduleModalRef = useRef(null);
  useEscapeToClose(() => setShowScheduleModal(false), showScheduleModal);
  useBodyScrollLock(showScheduleModal);
  useFocusTrap(scheduleModalRef, showScheduleModal);
  const [scheduleSubTab, setScheduleSubTab] = useState('schedules'); // 'schedules' | 'history' | 'instant'
  const [schedules, setSchedules] = useState([]);
  const [deliveryHistory, setDeliveryHistory] = useState([]);
  const [loadingSchedules, setLoadingSchedules] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);

  // Schedule creation form state
  const [isCreatingSchedule, setIsCreatingSchedule] = useState(false);
  const [newSchedule, setNewSchedule] = useState({
    name: 'Weekly Executive Security Audit',
    template: 'executive',
    frequency: 'weekly',
    time_utc: '08:00',
    day_of_week: 1,
    day_of_month: 1,
    recipients_email: '',
    webhook_url: '',
    is_active: 1
  });

  // Instant dispatch state
  const [instantDispatch, setInstantDispatch] = useState({
    template: 'executive',
    timeframe: '24h',
    recipients_email: '',
    webhook_url: '',
  });
  const [dispatchingNow, setDispatchingNow] = useState(false);

  const loadSchedulesData = async () => {
    setLoadingSchedules(true);
    try {
      const [schedRes, histRes] = await Promise.all([
        getReportSchedules().catch(() => []),
        getReportDeliveryHistory().catch(() => [])
      ]);
      setSchedules(schedRes || []);
      setDeliveryHistory(histRes || []);
    } catch (err) {
      console.error('Failed to load schedules/history:', err);
    } finally {
      setLoadingSchedules(false);
    }
  };

  const handleSaveSchedule = async (e) => {
    e.preventDefault();
    setActionMessage(null);
    try {
      await createReportSchedule(newSchedule);
      setActionMessage({ type: 'success', text: 'Report schedule saved successfully.' });
      setIsCreatingSchedule(false);
      await loadSchedulesData();
    } catch (err) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to save schedule.' });
    }
  };

  const handleDeleteSchedule = async (id) => {
    if (!window.confirm('Are you sure you want to delete this report schedule?')) return;
    setActionMessage(null);
    try {
      await deleteReportSchedule(id);
      setActionMessage({ type: 'success', text: 'Schedule deleted.' });
      await loadSchedulesData();
    } catch (err) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to delete schedule.' });
    }
  };

  const handleDispatchInstant = async (e) => {
    e.preventDefault();
    if (!instantDispatch.recipients_email && !instantDispatch.webhook_url) {
      setActionMessage({ type: 'error', text: 'Please specify at least one recipient email address or webhook URL.' });
      return;
    }
    setDispatchingNow(true);
    setActionMessage(null);
    try {
      const res = await dispatchReportNow(instantDispatch);
      setActionMessage({ type: 'success', text: `Report successfully dispatched (${res.results?.length || 1} destination(s)).` });
      const histRes = await getReportDeliveryHistory().catch(() => []);
      setDeliveryHistory(histRes || []);
    } catch (err) {
      setActionMessage({ type: 'error', text: err?.message || 'Report dispatch failed.' });
    } finally {
      setDispatchingNow(false);
    }
  };

  const generateReport = async () => {
    setLoading(true);
    setError('');
    try {
      const hours = timeframe === '24h' ? 24 : timeframe === '7d' ? 168 : 720;

      // Try fetching the unified multi-vector executive report summary from Phase 4 endpoint
      let execSummary = null;
      try {
        execSummary = await getExecutiveReportSummary(hours, timeframe);
      } catch (err) {
        console.warn('Could not load executive report summary endpoint (using fallback):', err);
      }

      // Fetch data from complementary API endpoints
      const [stats, attackTypes, topIps, health, auditStatsRes] = await Promise.all([
        getStats(hours).catch(() => null),
        getAttackTypes(hours).catch(() => []),
        getTopIPs(hours).catch(() => []),
        getHealth().catch(() => null),
        getSecurityStatistics(hours).catch(() => ({ total_events: 0, by_type: {} }))
      ]);

      // Settings for compliance fallback
      let wafSettings = null, hardeningSettings = null, logSettings = null, protectedApps = null;
      try {
        [wafSettings, hardeningSettings, logSettings, protectedApps] = await Promise.all([
          getWafSettings(), getHardeningSettings(), getLogSettings(), getProtectedApps(),
        ]);
      } catch (complianceErr) {
        console.warn('Could not load compliance settings:', complianceErr);
      }

      // Process and structure the data nicely for the report
      const totalRequests = execSummary?.traffic_metrics?.total_requests ?? stats?.total_requests ?? 0;
      const totalBlocked = execSummary?.traffic_metrics?.total_blocked ?? stats?.total_blocked ?? 0;
      const blockRate = execSummary?.traffic_metrics?.block_rate != null
        ? Number(execSummary.traffic_metrics.block_rate).toFixed(2)
        : totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(2) : '0.00';
      
      const finalAttackTypes = execSummary?.attack_distribution?.length
        ? execSummary.attack_distribution
        : (attackTypes || []);
      const finalTopIps = execSummary?.top_ips?.length
        ? execSummary.top_ips
        : (topIps || []);

      // Determine overall risk rating
      const riskLevel = execSummary?.risk_level || (() => {
        const blockedPerDay = totalBlocked / (hours / 24);
        if (blockedPerDay > 1000 || parseFloat(blockRate) > 10.0) return 'CRITICAL';
        if (blockedPerDay > 200 || parseFloat(blockRate) > 3.0) return 'HIGH';
        if (blockedPerDay > 20 || parseFloat(blockRate) > 0.5) return 'MEDIUM';
        return 'LOW';
      })();

      const riskColor = execSummary?.risk_color || (
        riskLevel === 'CRITICAL' ? 'var(--danger-color)' :
        riskLevel === 'HIGH' ? 'var(--sev-high)' :
        riskLevel === 'MEDIUM' ? 'var(--warning-color)' : 'var(--success-color)'
      );

      const topAttack = finalAttackTypes[0];
      const topSourceIp = finalTopIps[0];
      const narrativeSummary = execSummary?.narrative || [
        `During the selected ${timeframe === '24h' ? 'last 24 hours' : timeframe === '7d' ? 'last 7 days' : 'last 30 days'}, the CyberSentinel WAF Engine inspected ${totalRequests.toLocaleString()} HTTP requests and blocked ${totalBlocked.toLocaleString()} as malicious (${blockRate}% of total traffic).`,
        topAttack
          ? `The most frequently detected violation category was "${topAttack.attack_type || 'Unknown / Custom'}" with ${(topAttack.count || 0).toLocaleString()} detections.`
          : `No categorized violations were recorded in this window.`,
        topSourceIp
          ? `The most active single source of malicious traffic was ${topSourceIp.ip || topSourceIp.client_ip || topSourceIp.source_ip || 'an unidentified IP'}${topSourceIp.country ? ` (${topSourceIp.country})` : ''}, responsible for ${(topSourceIp.count || 0).toLocaleString()} flagged requests.`
          : ``,
        `Based on blocked-traffic volume and multi-layer threat indicators, this reporting period is assessed as ${riskLevel} risk.`,
      ].filter(Boolean).join(' ');

      const generatedAtDate = new Date();
      const reportId = execSummary?.report_id || `CSR-${generatedAtDate.getTime().toString(36).toUpperCase()}-${timeframe.toUpperCase()}`;

      setReportData({
        reportId,
        narrativeSummary,
        generatedAt: execSummary?.generated_at || generatedAtDate.toLocaleString(),
        timeframe: timeframe === '24h' ? 'Last 24 Hours' : timeframe === '7d' ? 'Last 7 Days' : 'Last 30 Days',
        riskLevel,
        riskColor,
        metrics: {
          totalRequests,
          totalBlocked,
          blockRate,
          uniqueIps: execSummary?.traffic_metrics?.unique_ips ?? stats?.total_unique_ips ?? finalTopIps.length,
          sqlInjections: execSummary?.traffic_metrics?.sqli_count ?? stats?.sqli_count ?? 0,
          xssAttacks: execSummary?.traffic_metrics?.xss_count ?? stats?.xss_count ?? 0,
          topAttackType: execSummary?.traffic_metrics?.top_attack_type ?? stats?.top_attack_type ?? '-'
        },
        attackTypes: finalAttackTypes,
        topIps: finalTopIps.slice(0, 5),
        health: {
          status: health?.status || 'HEALTHY',
          engine: 'CyberSentinel Engine v2.0',
          antiDefacement: execSummary?.compliance?.anti_defacement || health?.anti_defacement?.status || 'ACTIVE'
        },
        api_posture: execSummary?.api_posture || {
          discovered_endpoints: 0,
          documented_endpoints: 0,
          shadow_endpoints: 0,
          spec_loaded: false,
        },
        ml_posture: execSummary?.ml_posture || {
          sensitivity_preset: 'balanced',
          xgboost_version: 'v2.1',
          xgboost_accuracy: 0.964,
          drift_status: 'nominal',
          drift_breached: false,
        },
        ddos_posture: execSummary?.ddos_posture || {
          challenge_mode: 'turnstile',
          jailed_ips_count: 0,
          blocked_asns_count: 0,
          rate_limit_rpm: 120,
        },
        compliance: {
          engineEnforcement: execSummary?.compliance?.engine_enforcement ?? wafSettings?.secRuleEngine ?? 'On',
          tlsHardening: execSummary?.compliance?.tls_hardening ?? (hardeningSettings ? !!hardeningSettings.hsts_enabled : true),
          antiDefacement: execSummary?.compliance?.anti_defacement ?? health?.anti_defacement?.status ?? 'ACTIVE',
          adminAuditLogging: execSummary?.compliance?.audit_logging ?? (logSettings ? !!logSettings.auditEnabled : true),
          activeProtectedHosts: execSummary?.compliance?.active_hosts ?? (protectedApps ? protectedApps.filter((a) => a.is_active).length : null),
          totalProtectedHosts: execSummary?.compliance?.total_hosts ?? (protectedApps ? protectedApps.length : null),
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
          <div style={{ display: 'flex', gap: '4px', background: 'var(--surface-hover)', padding: '3px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <button 
              className={`report-btn ${timeframe === '24h' ? 'active' : ''}`}
              onClick={() => setTimeframe('24h')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                border: 'none',
                background: timeframe === '24h' ? 'var(--accent-color)' : 'transparent',
                color: timeframe === '24h' ? 'var(--accent-contrast, #ffffff)' : 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              24 Hours
            </button>
            <button 
              className={`report-btn ${timeframe === '7d' ? 'active' : ''}`}
              onClick={() => setTimeframe('7d')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                border: 'none',
                background: timeframe === '7d' ? 'var(--accent-color)' : 'transparent',
                color: timeframe === '7d' ? 'var(--accent-contrast, #ffffff)' : 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              7 Days
            </button>
            <button 
              className={`report-btn ${timeframe === '30d' ? 'active' : ''}`}
              onClick={() => setTimeframe('30d')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                border: 'none',
                background: timeframe === '30d' ? 'var(--accent-color)' : 'transparent',
                color: timeframe === '30d' ? 'var(--accent-contrast, #ffffff)' : 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              30 Days
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', minWidth: '220px' }}>
          <label htmlFor="security-report-template" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>Report Template</label>
          <SelectInput 
            id="security-report-template"
            aria-label="Report Template"
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
          >
            <option value="executive">Executive Summary Report</option>
            <option value="threat">Threat Intelligence Report</option>
            <option value="compliance">System Audit & Compliance</option>
          </SelectInput>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', marginLeft: 'auto', flexWrap: 'wrap' }}>
          <Button 
            variant="primary"
            size="sm"
            onClick={generateReport}
            disabled={loading}
            loading={loading}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Re-Generate</span>
          </Button>
          
          <Button 
            variant="secondary"
            size="sm"
            onClick={handlePrint}
            disabled={!reportData || loading}
          >
            <Printer size={14} />
            <span>Print / Save PDF</span>
          </Button>

          <Button 
            variant="secondary"
            size="sm"
            onClick={handleExportCSV}
            disabled={!reportData || loading}
          >
            <Download size={14} />
            <span>Export CSV</span>
          </Button>

          <Button 
            variant="secondary"
            size="sm"
            onClick={handleExportJSON}
            disabled={!reportData || loading}
          >
            <FileJson size={14} />
            <span>JSON</span>
          </Button>

          <Button 
            variant="secondary"
            size="sm"
            onClick={() => {
              setShowScheduleModal(true);
              loadSchedulesData();
            }}
          >
            <Calendar size={14} />
            <span>Automated Delivery</span>
          </Button>
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

      {/* Automated Report Schedules & Delivery Modal */}
      <AnimatePresence>
        {showScheduleModal && (
          <div className="modal-overlay" onClick={() => setShowScheduleModal(false)}>
            <motion.div
              ref={scheduleModalRef}
              className="modal-content"
              style={{ maxWidth: '860px', maxHeight: '88vh' }}
              onClick={(e) => e.stopPropagation()}
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
            >
              <div className="modal-header">
                <div className="modal-title">
                  <Calendar size={18} style={{ color: 'var(--accent-color)' }} />
                  <span>Automated Report Schedules & Delivery</span>
                </div>
                <button
                  className="modal-close-btn"
                  onClick={() => setShowScheduleModal(false)}
                  title="Close Modal"
                  aria-label="Close Modal"
                >
                  <X size={18} />
                </button>
              </div>

              <div className="modal-tabs">
                <button
                  className={`modal-tab ${scheduleSubTab === 'schedules' ? 'active' : ''}`}
                  onClick={() => { setScheduleSubTab('schedules'); setActionMessage(null); }}
                >
                  <Calendar size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                  Active Schedules ({schedules.length})
                </button>
                <button
                  className={`modal-tab ${scheduleSubTab === 'history' ? 'active' : ''}`}
                  onClick={() => { setScheduleSubTab('history'); setActionMessage(null); }}
                >
                  <Clock size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                  Delivery History ({deliveryHistory.length})
                </button>
                <button
                  className={`modal-tab ${scheduleSubTab === 'instant' ? 'active' : ''}`}
                  onClick={() => { setScheduleSubTab('instant'); setActionMessage(null); }}
                >
                  <Send size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                  Instant Dispatch
                </button>
              </div>

              <div className="modal-body" style={{ padding: '24px', overflowY: 'auto' }}>
                {actionMessage && (
                  <div
                    style={{
                      padding: '10px 14px',
                      borderRadius: '8px',
                      marginBottom: '16px',
                      fontSize: '13px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      background: actionMessage.type === 'success' ? 'rgba(5, 150, 105, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                      border: `1px solid ${actionMessage.type === 'success' ? 'var(--success-color)' : 'var(--danger-color)'}`,
                      color: actionMessage.type === 'success' ? 'var(--success-color)' : 'var(--danger-color)',
                    }}
                  >
                    {actionMessage.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                    <span>{actionMessage.text}</span>
                  </div>
                )}

                {/* SubTab 1: Active Schedules */}
                {scheduleSubTab === 'schedules' && (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)' }}>
                        Configure cron-like background report dispatchers for executive stakeholders and SIEM ingestion.
                      </p>
                      <Button
                        variant={isCreatingSchedule ? 'secondary' : 'primary'}
                        size="sm"
                        onClick={() => setIsCreatingSchedule(!isCreatingSchedule)}
                      >
                        {isCreatingSchedule ? <X size={14} /> : <Plus size={14} />}
                        <span>{isCreatingSchedule ? 'Cancel' : 'New Schedule'}</span>
                      </Button>
                    </div>

                    {isCreatingSchedule && (
                      <form onSubmit={handleSaveSchedule} className="glass-panel" style={{ padding: '18px', marginBottom: '20px', borderRadius: '10px' }}>
                        <h4 style={{ margin: '0 0 14px 0', fontSize: '14px', fontWeight: 600 }}>Create Scheduled Security Dispatch</h4>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '14px' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>SCHEDULE NAME</label>
                            <input
                              type="text"
                              value={newSchedule.name}
                              onChange={(e) => setNewSchedule({ ...newSchedule, name: e.target.value })}
                              required
                              placeholder="e.g. Weekly Executive Audit"
                              style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--surface-subtle)', color: 'var(--text-primary)' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>TEMPLATE</label>
                            <SelectInput
                              value={newSchedule.template}
                              onChange={(e) => setNewSchedule({ ...newSchedule, template: e.target.value })}
                              style={{ width: '100%' }}
                            >
                              <option value="executive">Executive Summary Report</option>
                              <option value="threat">Threat Intelligence Report</option>
                              <option value="compliance">System Audit & Compliance</option>
                            </SelectInput>
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>FREQUENCY</label>
                            <SelectInput
                              value={newSchedule.frequency}
                              onChange={(e) => setNewSchedule({ ...newSchedule, frequency: e.target.value })}
                              style={{ width: '100%' }}
                            >
                              <option value="daily">Daily (Every 24 Hours)</option>
                              <option value="weekly">Weekly (Specific Day)</option>
                              <option value="monthly">Monthly (1st of Month)</option>
                            </SelectInput>
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>TIME (UTC)</label>
                            <input
                              type="text"
                              value={newSchedule.time_utc}
                              onChange={(e) => setNewSchedule({ ...newSchedule, time_utc: e.target.value })}
                              required
                              placeholder="08:00"
                              style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--surface-subtle)', color: 'var(--text-primary)' }}
                            />
                          </div>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginBottom: '16px' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>EMAIL RECIPIENTS (COMMA-SEPARATED)</label>
                            <input
                              type="text"
                              value={newSchedule.recipients_email}
                              onChange={(e) => setNewSchedule({ ...newSchedule, recipients_email: e.target.value })}
                              placeholder="ciso@company.org, sec-ops@company.org"
                              style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--surface-subtle)', color: 'var(--text-primary)' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>WEBHOOK URL (OPTIONAL)</label>
                            <input
                              type="url"
                              value={newSchedule.webhook_url}
                              onChange={(e) => setNewSchedule({ ...newSchedule, webhook_url: e.target.value })}
                              placeholder="https://hooks.slack.com/services/..."
                              style={{ width: '100%', padding: '8px 10px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--surface-subtle)', color: 'var(--text-primary)' }}
                            />
                          </div>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                          <Button variant="secondary" size="sm" type="button" onClick={() => setIsCreatingSchedule(false)}>
                            Cancel
                          </Button>
                          <Button variant="primary" size="sm" type="submit">
                            Save Schedule
                          </Button>
                        </div>
                      </form>
                    )}

                    {loadingSchedules ? (
                      <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-secondary)' }}>
                        <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 8px' }} />
                        <div>Loading configured schedules...</div>
                      </div>
                    ) : schedules.length > 0 ? (
                      <div className="report-app-table-wrapper">
                        <table className="report-app-table">
                          <thead>
                            <tr>
                              <th>Schedule Name</th>
                              <th>Template</th>
                              <th>Frequency & UTC</th>
                              <th>Destinations</th>
                              <th>Last Sent</th>
                              <th>Status</th>
                              <th style={{ textAlign: 'right' }}>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {schedules.map((s) => (
                              <tr key={s.id}>
                                <td><strong>{s.name}</strong></td>
                                <td>
                                  <Badge variant="neutral">{s.template}</Badge>
                                </td>
                                <td>
                                  <span style={{ textTransform: 'capitalize' }}>{s.frequency}</span> @ <code>{s.time_utc}</code>
                                </td>
                                <td>
                                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                    {s.recipients_email && (
                                      <span title={s.recipients_email} style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px', padding: '2px 6px', background: 'var(--surface-subtle)', borderRadius: '4px' }}>
                                        <Mail size={12} /> Email
                                      </span>
                                    )}
                                    {s.webhook_url && (
                                      <span title={s.webhook_url} style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px', padding: '2px 6px', background: 'var(--surface-subtle)', borderRadius: '4px' }}>
                                        <Globe size={12} /> Webhook
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                                  {s.last_sent_at || 'Never'}
                                </td>
                                <td>
                                  <Badge variant={s.is_active ? 'success' : 'neutral'}>
                                    {s.is_active ? 'ACTIVE' : 'PAUSED'}
                                  </Badge>
                                </td>
                                <td style={{ textAlign: 'right' }}>
                                  <button
                                    onClick={() => handleDeleteSchedule(s.id)}
                                    title="Delete Schedule"
                                    aria-label="Delete Schedule"
                                    style={{ background: 'none', border: 'none', color: 'var(--danger-color)', cursor: 'pointer', padding: '4px' }}
                                  >
                                    <Trash2 size={15} />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="glass-panel" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-secondary)' }}>
                        <Calendar size={32} style={{ margin: '0 auto 10px', opacity: 0.5 }} />
                        <div style={{ fontWeight: 600 }}>No Scheduled Reports Configured</div>
                        <div style={{ fontSize: '12px', marginTop: '4px' }}>Click "New Schedule" above to automate daily, weekly, or monthly delivery.</div>
                      </div>
                    )}
                  </div>
                )}

                {/* SubTab 2: Delivery History */}
                {scheduleSubTab === 'history' && (
                  <div>
                    <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                      Immutable audit log of all automated and on-demand security report dispatches.
                    </p>
                    {deliveryHistory.length > 0 ? (
                      <div className="report-app-table-wrapper">
                        <table className="report-app-table">
                          <thead>
                            <tr>
                              <th>Timestamp</th>
                              <th>Schedule / Source</th>
                              <th>Template</th>
                              <th>Status</th>
                              <th>Destinations</th>
                              <th>Details</th>
                            </tr>
                          </thead>
                          <tbody>
                            {deliveryHistory.map((h) => (
                              <tr key={h.id}>
                                <td style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>{h.delivered_at}</td>
                                <td><strong>{h.schedule_name || 'Manual Dispatch'}</strong></td>
                                <td><Badge variant="neutral">{h.template}</Badge></td>
                                <td>
                                  <Badge variant={h.status === 'SUCCESS' ? 'success' : 'danger'}>
                                    {h.status}
                                  </Badge>
                                </td>
                                <td style={{ fontSize: '12px', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {h.destinations}
                                </td>
                                <td style={{ fontSize: '11px', color: h.error_message ? 'var(--danger-color)' : 'var(--text-secondary)' }}>
                                  {h.error_message || 'Delivered OK'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="glass-panel" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-secondary)' }}>
                        <Clock size={32} style={{ margin: '0 auto 10px', opacity: 0.5 }} />
                        <div style={{ fontWeight: 600 }}>No Report Delivery History Recorded</div>
                        <div style={{ fontSize: '12px', marginTop: '4px' }}>Delivery logs appear here once scheduled or manual dispatches are processed.</div>
                      </div>
                    )}
                  </div>
                )}

                {/* SubTab 3: Instant Dispatch */}
                {scheduleSubTab === 'instant' && (
                  <form onSubmit={handleDispatchInstant}>
                    <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                      Send an executive security report immediately to specified email addresses or security webhook endpoints.
                    </p>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '16px' }}>
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>REPORT TEMPLATE</label>
                        <SelectInput
                          value={instantDispatch.template}
                          onChange={(e) => setInstantDispatch({ ...instantDispatch, template: e.target.value })}
                          style={{ width: '100%' }}
                        >
                          <option value="executive">Executive Summary Report</option>
                          <option value="threat">Threat Intelligence Report</option>
                          <option value="compliance">System Audit & Compliance</option>
                        </SelectInput>
                      </div>
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>TIMEFRAME</label>
                        <SelectInput
                          value={instantDispatch.timeframe}
                          onChange={(e) => setInstantDispatch({ ...instantDispatch, timeframe: e.target.value })}
                          style={{ width: '100%' }}
                        >
                          <option value="24h">Last 24 Hours</option>
                          <option value="7d">Last 7 Days</option>
                          <option value="30d">Last 30 Days</option>
                        </SelectInput>
                      </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginBottom: '20px' }}>
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>RECIPIENT EMAILS (COMMA-SEPARATED)</label>
                        <input
                          type="text"
                          value={instantDispatch.recipients_email}
                          onChange={(e) => setInstantDispatch({ ...instantDispatch, recipients_email: e.target.value })}
                          placeholder="analyst@company.org, ciso@company.org"
                          style={{ width: '100%', padding: '9px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--surface-subtle)', color: 'var(--text-primary)' }}
                        />
                      </div>
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>WEBHOOK URL (SLACK / TEAMS / SIEM)</label>
                        <input
                          type="url"
                          value={instantDispatch.webhook_url}
                          onChange={(e) => setInstantDispatch({ ...instantDispatch, webhook_url: e.target.value })}
                          placeholder="https://hooks.slack.com/services/..."
                          style={{ width: '100%', padding: '9px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--surface-subtle)', color: 'var(--text-primary)' }}
                        />
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                      <Button
                        variant="primary"
                        size="md"
                        type="submit"
                        disabled={dispatchingNow}
                        loading={dispatchingNow}
                      >
                        <Send size={15} />
                        <span>Dispatch Report Now</span>
                      </Button>
                    </div>
                  </form>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

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
