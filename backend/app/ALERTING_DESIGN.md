# CyberSentinel WAF - Enhanced Alerting System Design

## Overview
The Enhanced Alerting System provides real-time multi-channel notifications for security events, anomalies, and system health issues. It integrates seamlessly with existing security components (ModSecurity, ML Engine, DDoS detection) and provides flexible rule-based alerting with throttling and aggregation.

## Architecture Components

### 1. Database Schema

#### alert_channels
Stores notification channel configurations (Email, Slack, Webhooks)
```sql
CREATE TABLE alert_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    channel_type TEXT NOT NULL CHECK(channel_type IN ('email', 'slack', 'webhook', 'pagerduty')),
    config JSON NOT NULL,  -- Channel-specific configuration
    enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Config JSON Examples:**
- **Email**: `{"smtp_host": "smtp.gmail.com", "smtp_port": 587, "username": "alerts@example.com", "password": "***", "from_addr": "waf@example.com", "to_addrs": ["admin@example.com"], "use_tls": true}`
- **Slack**: `{"webhook_url": "https://hooks.slack.com/services/...", "channel": "#security-alerts", "username": "WAF Alert Bot"}`
- **Webhook**: `{"url": "https://api.example.com/alerts", "method": "POST", "headers": {"Authorization": "Bearer token"}, "timeout": 10}`

#### alert_rules
Defines when and how alerts should be triggered
```sql
CREATE TABLE alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    event_type TEXT NOT NULL CHECK(event_type IN (
        'attack_detected', 'high_threat_score', 'ddos_detected', 
        'rate_limit_exceeded', 'ml_anomaly', 'geo_violation',
        'system_error', 'health_check_failed', 'config_changed'
    )),
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    conditions JSON NOT NULL,  -- Rule evaluation criteria
    channels JSON NOT NULL,  -- Array of channel IDs to notify
    throttle_minutes INTEGER DEFAULT 5,  -- Minimum time between similar alerts
    enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Conditions JSON Examples:**
- **High Threat Score**: `{"threat_score_gt": 80, "min_occurrences": 3, "time_window_minutes": 5}`
- **DDoS Attack**: `{"rpm_gt": 100, "unique_ips_lt": 5, "duration_seconds_gt": 60}`
- **ML Anomaly**: `{"isolation_score_gt": 0.8, "xgb_prob_gt": 0.7}`
- **Geographic Violation**: `{"blocked_countries": ["CN", "RU"], "attack_count_gt": 10}`

#### alert_history
Logs all sent alerts for audit and analytics
```sql
CREATE TABLE alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    channels_notified JSON NOT NULL,  -- Array of channel names
    event_data JSON NOT NULL,  -- Original event that triggered the alert
    message TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('sent', 'failed', 'throttled', 'acknowledged')),
    error_message TEXT,
    acknowledged_by TEXT,
    acknowledged_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
);
```

#### alert_aggregations
Tracks recent alerts for deduplication and throttling
```sql
CREATE TABLE alert_aggregations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    event_signature TEXT NOT NULL,  -- Hash of key event fields
    first_occurrence DATETIME NOT NULL,
    last_occurrence DATETIME NOT NULL,
    occurrence_count INTEGER DEFAULT 1,
    last_notified_at DATETIME,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
);
CREATE INDEX idx_alert_agg_rule_sig ON alert_aggregations(rule_id, event_signature);
CREATE INDEX idx_alert_agg_last_notified ON alert_aggregations(last_notified_at);
```

### 2. Service Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Security Event Sources                      │
│  (ModSecurity, ML Engine, DDoS Monitor, System Health)      │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              AlertManager (Orchestrator)                     │
│  • Receives security events                                  │
│  • Evaluates events against alert rules                      │
│  • Manages alert lifecycle                                   │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ RuleEvaluator│ │ Throttler    │ │ Aggregator   │
│ • Condition  │ │ • Rate limit │ │ • Dedupe     │
│   matching   │ │   alerts     │ │   similar    │
│ • Severity   │ │ • Time-based │ │   events     │
│   assignment │ │   windows    │ │ • Batching   │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────┐
│           NotificationDispatcher                             │
│  • Routes alerts to appropriate channels                     │
│  • Handles failures and retries                              │
│  • Logs notification results                                 │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ EmailChannel │ │ SlackChannel │ │WebhookChannel│ │PagerDutyChannel│
│ • SMTP       │ │ • Webhook    │ │ • HTTP POST  │ │ • Events API │
│ • Templates  │ │ • Rich format│ │ • Custom fmt │ │ • Incidents  │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

### 3. Event Types and Default Rules

| Event Type | Description | Default Severity | Example Condition |
|-----------|-------------|------------------|-------------------|
| `attack_detected` | ModSecurity blocked request | HIGH | `crs_score >= 5` |
| `high_threat_score` | ML model detected high threat | CRITICAL | `threat_score >= 85` |
| `ddos_detected` | DDoS attack in progress | CRITICAL | `rpm > 200, duration > 60s` |
| `rate_limit_exceeded` | IP exceeded rate limits | MEDIUM | `rpm > 100, repeated violations` |
| `ml_anomaly` | Unusual behavior detected | HIGH | `isolation_score > 0.75` |
| `geo_violation` | Attack from blocked country | MEDIUM | `blocked_country + attack` |
| `system_error` | Backend/ML service error | HIGH | `service down > 30s` |
| `health_check_failed` | Component unhealthy | CRITICAL | `consecutive failures > 3` |
| `config_changed` | Security config modified | INFO | `settings.json modified` |

### 4. Alert Message Templates

**Email Template Structure:**
```html
<!DOCTYPE html>
<html>
<head>
    <style>
        .alert-critical { background: #dc2626; }
        .alert-high { background: #ea580c; }
        .alert-medium { background: #eab308; }
    </style>
</head>
<body>
    <div class="alert-{{severity}}">
        <h2>🚨 CyberSentinel WAF Alert</h2>
        <p><strong>Severity:</strong> {{severity}}</p>
        <p><strong>Event:</strong> {{event_type}}</p>
        <p><strong>Time:</strong> {{timestamp}}</p>
        <p><strong>Message:</strong> {{message}}</p>
        <h3>Details:</h3>
        <pre>{{event_data}}</pre>
    </div>
</body>
</html>
```

**Slack Message Format:**
```json
{
    "text": "🚨 CyberSentinel WAF Alert",
    "attachments": [{
        "color": "#dc2626",
        "fields": [
            {"title": "Severity", "value": "CRITICAL", "short": true},
            {"title": "Event Type", "value": "high_threat_score", "short": true},
            {"title": "Message", "value": "High threat score detected from IP 192.168.1.100"},
            {"title": "Details", "value": "```threat_score: 92, ip: 192.168.1.100, uri: /admin```"}
        ],
        "footer": "CyberSentinel WAF",
        "ts": 1721045529
    }]
}
```

### 5. API Endpoints

**Alert Channels:**
- `POST /api/alerts/channels` - Create notification channel
- `GET /api/alerts/channels` - List all channels
- `GET /api/alerts/channels/{id}` - Get channel details
- `PUT /api/alerts/channels/{id}` - Update channel
- `DELETE /api/alerts/channels/{id}` - Delete channel
- `POST /api/alerts/channels/{id}/test` - Test channel connectivity

**Alert Rules:**
- `POST /api/alerts/rules` - Create alert rule
- `GET /api/alerts/rules` - List all rules
- `GET /api/alerts/rules/{id}` - Get rule details
- `PUT /api/alerts/rules/{id}` - Update rule
- `DELETE /api/alerts/rules/{id}` - Delete rule
- `POST /api/alerts/rules/{id}/test` - Trigger test alert

**Alert History:**
- `GET /api/alerts/history` - List alert history (paginated, filterable)
- `GET /api/alerts/history/{id}` - Get alert details
- `POST /api/alerts/history/{id}/acknowledge` - Acknowledge alert
- `GET /api/alerts/stats` - Alert statistics and metrics

### 6. Integration Points

**ModSecurity Integration:**
- Hook: `backend/app/services/log_reader.py` - After parsing audit logs
- Trigger: `alert_manager.trigger_event('attack_detected', event_data)`

**ML Engine Integration:**
- Hook: `ml-waf/ml_server.py` - After threat score calculation
- Trigger: Check `threat_score >= threshold` and fire alert

**DDoS Detection Integration:**
- Hook: `ml-waf/ml_check.lua` - When rate limits exceeded
- Trigger: Call alerting API endpoint

**System Health Integration:**
- Hook: `backend/app/routes/health.py` - On health check failures
- Trigger: Alert on component failures

### 7. Configuration in settings.json

```json
{
  "alerting": {
    "enabled": true,
    "default_throttle_minutes": 5,
    "max_alerts_per_hour": 100,
    "aggregation_window_minutes": 10,
    "retention_days": 90,
    "test_mode": false
  }
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (Tasks 1-3)
- Database schema creation
- Alert manager service
- Rule evaluation engine

### Phase 2: Notification Channels (Tasks 4-6)
- Email channel implementation
- Slack channel implementation  
- Generic webhook channel

### Phase 3: Intelligence Layer (Tasks 7, 10)
- Alert throttling and aggregation
- Integration with security events

### Phase 4: User Interface (Tasks 8-9, 11-12)
- Backend APIs
- Frontend dashboard
- Testing and analytics

## Security Considerations

1. **Secrets Management**: Store SMTP passwords, webhook tokens encrypted
2. **Rate Limiting**: Prevent alert flooding attacks
3. **Input Validation**: Sanitize all channel configurations
4. **Audit Logging**: Log all alert configuration changes
5. **Access Control**: Only admin role can manage alerts

## Testing Strategy

1. **Unit Tests**: Test rule evaluation logic
2. **Integration Tests**: Test channel delivery
3. **Load Tests**: Verify throttling under high event volume
4. **E2E Tests**: Trigger alerts from actual security events
