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
          className="report-sheet-preview"
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          {/* Print only header */}
          <div className="print-header">
            <h2>CyberSentinel WAF Audit & Threat Report</h2>
            <div className="print-meta-grid">
              <div><strong>Report ID:</strong> {reportData.reportId}</div>
              <div><strong>Timeframe:</strong> {reportData.timeframe}</div>
              <div><strong>Generated At:</strong> {reportData.generatedAt}</div>
              <div><strong>Risk Rating:</strong> {reportData.riskLevel}</div>
              <div><strong>Status:</strong> {reportData.health.status}</div>
              <div><strong>Classification:</strong> Confidential — Internal Use Only</div>
            </div>
          </div>

          {/* Print-only footer — position:fixed repeats this on every printed
              page (Chrome/Firefox both honor this for @media print), which is
              the only reliable way to stamp page provenance: browsers don't
              expose CSS counter(page)/counter(pages) to page content, only to
              their own optional header/footer in the print dialog. */}
          <div className="print-footer">
            CyberSentinel WAF — {reportData.reportId} — Confidential
          </div>

          {/* Report Sheet Header Card */}
          <div className="report-header-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span className="report-badge">SECURITY REPORT</span>
                <h1 style={{ margin: '8px 0 4px', fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-display)' }}>
                  {reportType === 'executive' && 'WAF Executive Summary'}
                  {reportType === 'threat' && 'Detailed Threat Analysis'}
                  {reportType === 'compliance' && 'System Audit & Compliance'}
                </h1>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Timeframe: <strong>{reportData.timeframe}</strong> · Generated at: <strong>{reportData.generatedAt}</strong>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Report ID: <strong>{reportData.reportId}</strong> · Classification: <strong>Confidential — Internal Use Only</strong>
                </div>
              </div>

              <div style={{ 
                textAlign: 'right', 
                padding: '12px 20px', 
                borderRadius: '8px', 
                background: 'var(--surface-subtle)',
                border: '1px solid var(--border-color)'
              }}>
                <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>OVERALL RISK</div>
                <div style={{ fontSize: '20px', fontWeight: 800, color: reportData.riskColor, letterSpacing: '0.5px' }}>
                  {reportData.riskLevel}
                </div>
              </div>
            </div>
          </div>

          {/* Narrative Summary */}
          <div className="report-section-box" style={{ marginBottom: '20px' }}>
            <h3>Executive Narrative</h3>
            <p style={{ fontSize: '13px', lineHeight: 1.7, color: 'var(--text-primary)' }}>
              {reportData.narrativeSummary}
            </p>
          </div>

          {/* Executive Summary stats grid */}
          <div className="report-grid-3">
            <div className="report-metric-card">
              <span className="metric-label">Total HTTP Requests</span>
              <span className="metric-value">{reportData.metrics.totalRequests.toLocaleString()}</span>
              <span className="metric-sub">Analyzed by WAF Engine</span>
            </div>
            <div className="report-metric-card">
              <span className="metric-label">Blocked Violations</span>
              <span className="metric-value" style={{ color: 'var(--danger-color)' }}>
                {reportData.metrics.totalBlocked.toLocaleString()}
              </span>
              <span className="metric-sub">Malicious Payloads Dropped</span>
            </div>
            <div className="report-metric-card">
              <span className="metric-label">Attack Percentage</span>
              <span className="metric-value" style={{ color: 'var(--warning-color)' }}>
                {reportData.metrics.blockRate}%
              </span>
              <span className="metric-sub">Violations to traffic ratio</span>
            </div>
          </div>

          {/* Report Sections depending on Selected template */}
          {reportType === 'executive' && (
            <div className="report-sections-layout">
              {/* Category distribution */}
              <div className="report-section-box">
                <h3>Violation Category Breakdown</h3>
                {reportData.attackTypes.length > 0 && (
                  <div style={{ height: '200px', width: '100%', marginBottom: '12px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={reportData.attackTypes}
                          cx="50%" cy="50%"
                          innerRadius={40} outerRadius={70}
                          paddingAngle={2}
                          dataKey="count"
                          nameKey="attack_type"
                          strokeWidth={0}
                        >
                          {reportData.attackTypes.map((entry, index) => (
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
                <div className="report-table-wrapper">
                  <table className="report-table">
                    <thead>
                      <tr>
                        <th>Violation Type / Category</th>
                        <th style={{ textAlign: 'right' }}>Detections</th>
                        <th style={{ textAlign: 'right' }}>Percentage</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reportData.attackTypes.length > 0 ? (
                        (() => {
                          const totalDetections = reportData.attackTypes.reduce((sum, item) => sum + (item.count || 0), 0);
                          return reportData.attackTypes.map((t, idx) => (
                            <tr key={idx}>
                              <td><strong>{t.attack_type || 'Unknown / Custom'}</strong></td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{t.count}</td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                                {totalDetections > 0 ? ((t.count / totalDetections) * 100).toFixed(1) : '0.0'}%
                              </td>
                            </tr>
                          ));
                        })()
                      ) : (
                        <tr>
                          <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No threat category data recorded.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Top Attacking IPs */}
              <div className="report-section-box">
                <h3>Top Attack Originators</h3>
                <div className="report-table-wrapper">
                  <table className="report-table">
                    <thead>
                      <tr>
                        <th>Source IP</th>
                        <th>Origin Country</th>
                        <th style={{ textAlign: 'right' }}>Total Hits</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reportData.topIps.length > 0 ? (
                        reportData.topIps.map((ip, idx) => (
                          <tr key={idx}>
                            <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)' }}>{ip.ip || ip.client_ip || ip.source_ip || 'Unknown'}</td>
                            <td>{ip.country || 'Internal'}</td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{ip.count}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No attacking source IP data recorded.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {reportType === 'threat' && (
            <div className="report-sections-layout">
              {/* Detailed Threat Metrics */}
              <div className="report-section-box" style={{ gridColumn: 'span 2' }}>
                <h3>Threat Intelligence & Signatures</h3>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                  Signature-based detections and CyberSentinel Engine Core Rule Set (CRS) triggers recorded for this timeframe.
                </p>
                <div className="report-grid-3" style={{ margin: '0 0 20px 0', padding: 0, border: 'none', background: 'transparent' }}>
                  <div className="report-metric-card" style={{ background: 'var(--surface-subtle)' }}>
                    <span className="metric-label">SQL Injection Attacks</span>
                    <span className="metric-value" style={{ fontSize: '24px' }}>{reportData.metrics.sqlInjections}</span>
                    <span className="metric-sub">Signature database matches</span>
                  </div>
                  <div className="report-metric-card" style={{ background: 'var(--surface-subtle)' }}>
                    <span className="metric-label">Cross-Site Scripting (XSS)</span>
                    <span className="metric-value" style={{ fontSize: '24px' }}>{reportData.metrics.xssAttacks}</span>
                    <span className="metric-sub">Browser payloads filtered</span>
                  </div>
                  <div className="report-metric-card" style={{ background: 'var(--surface-subtle)' }}>
                    <span className="metric-label">Primary Attack Vector</span>
                    <span className="metric-value" style={{ fontSize: '20px', color: 'var(--accent-color)' }}>{reportData.metrics.topAttackType}</span>
                    <span className="metric-sub">Most frequent category</span>
                  </div>
                </div>

                <h3 style={{ marginTop: '24px' }}>Top Threat Originators</h3>
                <div className="report-table-wrapper">
                  <table className="report-table">
                    <thead>
                      <tr>
                        <th>Source IP</th>
                        <th>Origin Country</th>
                        <th style={{ textAlign: 'right' }}>Total Hits</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reportData.topIps.length > 0 ? (
                        reportData.topIps.map((ip, idx) => (
                          <tr key={idx}>
                            <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-color)' }}>{ip.ip || ip.client_ip || ip.source_ip || 'Unknown'}</td>
                            <td>{ip.country || 'Internal'}</td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{ip.count}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No attacking source IP data recorded.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {reportType === 'compliance' && (
            <div className="report-sections-layout">
              {/* Compliance checks */}
              <div className="report-section-box">
                <h3>System Configuration & Compliance</h3>
                <div className="report-table-wrapper">
                  <table className="report-table">
                    <thead>
                      <tr>
                        <th>Compliance Check / Standard</th>
                        <th style={{ textAlign: 'right' }}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>CyberSentinel Engine Enforcement</td>
                        {(() => {
                          const on = reportData.compliance.engineEnforcement;
                          if (on == null) return <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontWeight: 600 }}>UNABLE TO VERIFY</td>;
                          return on === 'On'
                            ? <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 600 }}>ENFORCING</td>
                            : <td style={{ textAlign: 'right', color: 'var(--danger-color)', fontWeight: 600 }}>NOT ENFORCING</td>;
                        })()}
                      </tr>
                      <tr>
                        <td>SSL/TLS Dynamic Cipher Hardening (HSTS)</td>
                        {(() => {
                          const on = reportData.compliance.tlsHardening;
                          if (on == null) return <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontWeight: 600 }}>UNABLE TO VERIFY</td>;
                          return on
                            ? <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 600 }}>ENABLED</td>
                            : <td style={{ textAlign: 'right', color: 'var(--sev-high)', fontWeight: 600 }}>DISABLED</td>;
                        })()}
                      </tr>
                      <tr>
                        <td>Dynamic Web Anti-Defacement Integrity Check</td>
                        <td style={{
                          textAlign: 'right', fontWeight: 600,
                          color: reportData.health.antiDefacement === 'ACTIVE' ? 'var(--success-color)' : 'var(--text-secondary)',
                        }}>{reportData.health.antiDefacement}</td>
                      </tr>
                      <tr>
                        <td>Admin Authentication Logging & Audits</td>
                        {(() => {
                          const on = reportData.compliance.adminAuditLogging;
                          if (on == null) return <td style={{ textAlign: 'right', color: 'var(--text-secondary)', fontWeight: 600 }}>UNABLE TO VERIFY</td>;
                          return on
                            ? <td style={{ textAlign: 'right', color: 'var(--success-color)', fontWeight: 600 }}>ENFORCED</td>
                            : <td style={{ textAlign: 'right', color: 'var(--danger-color)', fontWeight: 600 }}>DISABLED</td>;
                        })()}
                      </tr>
                      <tr>
                        <td>Active Protected Virtual Hosts</td>
                        <td style={{ textAlign: 'right', fontWeight: 600 }}>
                          {reportData.compliance.activeProtectedHosts == null
                            ? 'UNABLE TO VERIFY'
                            : `${reportData.compliance.activeProtectedHosts} / ${reportData.compliance.totalProtectedHosts} ACTIVE`}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Security Audit Events */}
              <div className="report-section-box">
                <h3>Security Audit Event Types</h3>
                <div className="report-table-wrapper">
                  <table className="report-table">
                    <thead>
                      <tr>
                        <th>Audit Event Type</th>
                        <th style={{ textAlign: 'right' }}>Event Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.keys(reportData.audit.by_type).length > 0 ? (
                        Object.entries(reportData.audit.by_type).map(([key, val]) => (
                          <tr key={key}>
                            <td><strong>{key}</strong></td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{val}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="2" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No audit occurrences logged.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Health & Engine Status footer card */}
          <div className="report-footer-card">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
              <div>
                <div className="summary-label">GATEWAY NODE STATUS</div>
                <div
                  className="summary-value"
                  style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    color: reportData.health.status === 'HEALTHY' ? 'var(--success-color)' : 'var(--sev-high)',
                  }}
                >
                  <ShieldCheck size={14} />
                  <span>{reportData.health.status}</span>
                </div>
              </div>
              <div>
                <div className="summary-label">WAF CORE ENGINE</div>
                <div className="summary-value">{reportData.health.engine}</div>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Styled block (scoped to component and custom printing rules) */}
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

        /* Report Preview Sheet */
        .report-sheet-preview {
          background: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-radius: 16px;
          padding: 40px;
          box-shadow: var(--shadow-card);
        }

        .report-header-card {
          border-bottom: 2px solid var(--border-color);
          padding-bottom: 24px;
          margin-bottom: 24px;
        }

        .report-badge {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 1px;
          padding: 2px 8px;
          border-radius: 4px;
          background: var(--accent-bg);
          color: var(--accent-color);
          border: 1px solid var(--accent-border);
        }

        .report-grid-3 {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 16px;
          margin-bottom: 24px;
        }

        .report-metric-card {
          background: var(--surface-subtle);
          border: 1px solid var(--surface-hover);
          border-radius: 8px;
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .metric-label {
          font-size: 11px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .metric-value {
          font-size: 28px;
          font-weight: 800;
          color: var(--text-primary);
          font-family: var(--font-mono);
        }

        .metric-sub {
          font-size: 12px;
          color: var(--text-muted);
        }

        .report-sections-layout {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
          gap: 20px;
          margin-bottom: 24px;
        }

        .report-section-box {
          background: var(--surface-subtle);
          border: 1px solid var(--border-subtle);
          border-radius: 12px;
          padding: 24px;
        }

        .report-section-box h3 {
          font-size: 15px;
          font-weight: 700;
          color: var(--text-primary);
          margin: 0 0 16px 0;
          border-bottom: 1px solid var(--surface-hover);
          padding-bottom: 10px;
        }

        .report-table-wrapper {
          overflow-x: auto;
        }

        .report-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
        }

        .report-table th {
          text-align: left;
          padding: 8px 12px;
          color: var(--text-secondary);
          font-weight: 600;
          border-bottom: 1px solid var(--surface-strong);
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .report-table td {
          padding: 10px 12px;
          border-bottom: 1px solid var(--border-subtle);
          color: var(--text-primary);
        }

        .report-table tr:hover td {
          background: var(--surface-subtle);
        }

        .report-footer-card {
          margin-top: 32px;
          padding: 20px 24px;
          background: var(--inset-bg);
          border: 1px solid var(--surface-hover);
          border-radius: 8px;
        }

        .summary-label {
          font-size: 9px;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 4px;
        }

        .summary-value {
          font-size: 12px;
          font-weight: 600;
          color: var(--text-primary);
        }

        .print-header {
          display: none;
        }

        .print-footer {
          display: none;
        }

        /* PDF / Print Optimization Styles */
        @media print {
          body {
            background: #fff !important;
            color: #000 !important;
          }
          
          /* Hide layout items */
          .sidebar, .page-header, .subtabs-container, .no-print, .app-footer {
            display: none !important;
          }

          .main-content {
            padding: 0 !important;
            margin: 0 !important;
            width: 100% !important;
          }

          .report-sheet-preview {
            background: #fff !important;
            color: #000 !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
            margin: 0 !important;
          }

          .print-header {
            display: block !important;
            margin-bottom: 30px;
            border-bottom: 2px solid #000;
            padding-bottom: 15px;
          }

          .print-header h2 {
            margin: 0 0 10px 0;
            font-size: 22px;
            color: #000;
          }

          .print-meta-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            font-size: 11px;
            color: #444;
          }

          .print-footer {
            display: block !important;
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            text-align: center;
            font-size: 9px;
            color: #666;
            border-top: 1px solid #ddd;
            padding-top: 6px;
          }

          .report-header-card {
            border-bottom: 1px solid #ddd !important;
          }

          .report-header-card h1 {
            color: #000 !important;
          }

          .report-metric-card {
            background: #f8f9fa !important;
            border: 1px solid #ddd !important;
            color: #000 !important;
          }

          .metric-value {
            color: #000 !important;
          }

          .report-section-box {
            background: #fff !important;
            border: 1px solid #ddd !important;
            color: #000 !important;
          }

          .report-section-box h3 {
            color: #000 !important;
            border-bottom: 1px solid #ddd !important;
          }

          .report-table th {
            color: #333 !important;
            border-bottom: 1px solid #ccc !important;
          }

          .report-table td {
            color: #000 !important;
            border-bottom: 1px solid #eee !important;
          }

          .report-footer-card {
            background: #f8f9fa !important;
            border: 1px solid #ddd !important;
            color: #000 !important;
          }

          .summary-value {
            color: #000 !important;
          }
        }
      `}</style>
    </div>
  );
}
