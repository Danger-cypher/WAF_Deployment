import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SecurityReports from './SecurityReports';
import * as api from '../services/api';

vi.mock('../services/api', () => ({
  getExecutiveReportSummary: vi.fn(),
  getStats: vi.fn(),
  getAttackTypes: vi.fn(),
  getTopIPs: vi.fn(),
  getHealth: vi.fn(),
  getSecurityStatistics: vi.fn(),
  getWafSettings: vi.fn(),
  getHardeningSettings: vi.fn(),
  getLogSettings: vi.fn(),
  getProtectedApps: vi.fn(),
  getReportSchedules: vi.fn(),
  createReportSchedule: vi.fn(),
  deleteReportSchedule: vi.fn(),
  getReportDeliveryHistory: vi.fn(),
  dispatchReportNow: vi.fn(),
}));

const MOCK_EXECUTIVE_SUMMARY = {
  report_id: 'CSR-TEST-24H',
  timeframe: '24h',
  hours: 24,
  generated_at: '2026-11-12 12:00:00 UTC',
  risk_level: 'LOW',
  risk_color: 'var(--success-color)',
  narrative: 'Over the monitored 24h timeframe, the CyberSentinel WAF Engine inspected 15,000 total HTTP requests, blocking 150 malicious attempts (1.00% block rate).',
  traffic_metrics: {
    total_requests: 15000,
    total_blocked: 150,
    block_rate: 1.0,
    clean_requests: 14850,
    unique_ips: 42,
    sqli_count: 55,
    xss_count: 28,
    top_attack_type: 'SQL Injection',
  },
  attack_distribution: [
    { attack_type: 'SQL Injection', count: 55 },
    { attack_type: 'XSS Injection', count: 28 },
  ],
  top_ips: [
    { ip: '198.51.100.4', country: 'Germany', count: 77 },
  ],
  api_posture: {
    discovered_endpoints: 12,
    documented_endpoints: 10,
    shadow_endpoints: 2,
    spec_loaded: true,
  },
  ml_posture: {
    sensitivity_preset: 'balanced',
    xgboost_version: 'v2.1',
    xgboost_accuracy: 0.985,
    drift_status: 'nominal',
    drift_breached: false,
  },
  ddos_posture: {
    challenge_mode: 'turnstile',
    jailed_ips_count: 3,
    blocked_asns_count: 1,
    rate_limit_rpm: 120,
  },
  compliance: {
    engine_enforcement: 'On',
    tls_hardening: true,
    anti_defacement: 'ACTIVE',
    audit_logging: true,
    api_inventory_control: 'ENFORCED',
    ml_anomaly_monitoring: 'ACTIVE',
    active_hosts: 2,
    total_hosts: 2,
  }
};

const MOCK_SCHEDULES = [
  {
    id: 1,
    name: 'Weekly CISO Briefing',
    template: 'executive',
    frequency: 'weekly',
    time_utc: '08:00',
    recipients_email: 'ciso@enterprise.org',
    webhook_url: 'https://hooks.slack.com/services/T00/B00/X00',
    is_active: 1,
    last_sent_at: '2026-11-10 08:00:00'
  }
];

const MOCK_HISTORY = [
  {
    id: 10,
    schedule_id: 1,
    schedule_name: 'Weekly CISO Briefing',
    template: 'executive',
    delivered_at: '2026-11-10 08:00:01',
    status: 'SUCCESS',
    destinations: 'Email: ciso@enterprise.org, Webhook: https://hooks.slack.com/...',
    error_message: null
  }
];

describe('SecurityReports Component (Phase 4)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getExecutiveReportSummary.mockResolvedValue(MOCK_EXECUTIVE_SUMMARY);
    api.getStats.mockResolvedValue({ total_requests: 15000, total_blocked: 150 });
    api.getAttackTypes.mockResolvedValue([{ attack_type: 'SQL Injection', count: 55 }]);
    api.getTopIPs.mockResolvedValue([{ ip: '198.51.100.4', country: 'Germany', count: 77 }]);
    api.getHealth.mockResolvedValue({ status: 'HEALTHY', anti_defacement: { status: 'ACTIVE' } });
    api.getSecurityStatistics.mockResolvedValue({ total_events: 5, by_type: { LOGIN_SUCCESS: 5 } });
    api.getWafSettings.mockResolvedValue({ secRuleEngine: 'On' });
    api.getHardeningSettings.mockResolvedValue({ hsts_enabled: 1 });
    api.getLogSettings.mockResolvedValue({ auditEnabled: true });
    api.getProtectedApps.mockResolvedValue([{ id: 1, is_active: true }, { id: 2, is_active: true }]);
    api.getReportSchedules.mockResolvedValue(MOCK_SCHEDULES);
    api.getReportDeliveryHistory.mockResolvedValue(MOCK_HISTORY);
    api.createReportSchedule.mockResolvedValue({ success: true, id: 2 });
    api.deleteReportSchedule.mockResolvedValue({ success: true });
    api.dispatchReportNow.mockResolvedValue({ success: true, results: [{ destination: 'ciso@enterprise.org', status: 'SUCCESS' }] });
  });

  it('renders executive summary with multi-vector defense posture cards', async () => {
    render(<SecurityReports />);

    // Check title and traffic metrics
    expect(await screen.findByRole('heading', { level: 1, name: /WAF Executive Summary/i })).toBeInTheDocument();
    expect(screen.getAllByText('15,000').length).toBeGreaterThan(0);
    expect(screen.getAllByText('150').length).toBeGreaterThan(0);

    // Multi-Vector Defense Posture section
    expect(screen.getAllByText(/Multi-Vector Defense Posture/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/API Protection/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AI Behavioral Engine/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/DDoS & Bot Defense/i).length).toBeGreaterThan(0);

    // Verification of multi-vector posture details
    expect(screen.getAllByText(/2 Shadow/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/TURNSTILE/i).length).toBeGreaterThan(0);
  });

  it('renders compliance table with multi-framework control mappings', async () => {
    const user = userEvent.setup();
    render(<SecurityReports />);

    // Select "System Audit & Compliance" template
    const templateSelect = await screen.findByLabelText(/Report Template/i);
    await user.selectOptions(templateSelect, 'compliance');

    expect(await screen.findByRole('heading', { level: 1, name: /System Audit & Compliance/i })).toBeInTheDocument();

    // Check framework citations in Compliance Table
    expect(screen.getAllByText(/PCI-DSS v4.0/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/API Inventory & Shadow Endpoint Control/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/OWASP API Top 10 2023/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/AI Behavioral Drift & Anomaly Monitoring/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/NIST SP 800-53 Rev. 5/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Layer-7 DDoS & Bot Challenge Mitigation/i).length).toBeGreaterThan(0);
  });

  it('opens automated delivery modal and manages schedules', async () => {
    const user = userEvent.setup();
    render(<SecurityReports />);

    const automatedDeliveryBtn = await screen.findByRole('button', { name: /Automated Delivery/i });
    await user.click(automatedDeliveryBtn);

    // Modal title appears
    expect(await screen.findByText(/Automated Report Schedules & Delivery/i)).toBeInTheDocument();
    expect(api.getReportSchedules).toHaveBeenCalled();
    expect(api.getReportDeliveryHistory).toHaveBeenCalled();

    // Check that existing schedule appears
    expect(screen.getByText('Weekly CISO Briefing')).toBeInTheDocument();
    expect(screen.getByTitle('ciso@enterprise.org')).toBeInTheDocument();

    // Toggle "New Schedule" form
    const newScheduleBtn = screen.getByRole('button', { name: /New Schedule/i });
    await user.click(newScheduleBtn);

    expect(screen.getByText(/Create Scheduled Security Dispatch/i)).toBeInTheDocument();

    // Switch to "Delivery History" tab
    const historyTab = screen.getByRole('button', { name: /Delivery History/i });
    await user.click(historyTab);

    expect(screen.getByText(/Immutable audit log of all automated and on-demand security report dispatches/i)).toBeInTheDocument();
    expect(screen.getByText('SUCCESS')).toBeInTheDocument();
  });

  it('dispatches report instantly via Instant Dispatch subtab', async () => {
    const user = userEvent.setup();
    render(<SecurityReports />);

    const automatedDeliveryBtn = await screen.findByRole('button', { name: /Automated Delivery/i });
    await user.click(automatedDeliveryBtn);

    // Switch to "Instant Dispatch" tab
    const instantTab = await screen.findByRole('button', { name: /Instant Dispatch/i });
    await user.click(instantTab);

    const emailInput = screen.getByPlaceholderText(/analyst@company.org/i);
    await user.type(emailInput, 'security-team@enterprise.org');

    const dispatchBtn = screen.getByRole('button', { name: /Dispatch Report Now/i });
    await user.click(dispatchBtn);

    await waitFor(() => {
      expect(api.dispatchReportNow).toHaveBeenCalledWith(expect.objectContaining({
        recipients_email: 'security-team@enterprise.org',
        template: 'executive',
        timeframe: '24h'
      }));
    });

    expect(await screen.findByText(/Report successfully dispatched/i)).toBeInTheDocument();
  });
});
