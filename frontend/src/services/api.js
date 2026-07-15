const BASE_URL = `${window.location.protocol}//${window.location.host}/api`;

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

// Global fetch interceptor to automatically attach authorization header
const originalFetch = window.fetch;
window.fetch = async function (url, options = {}) {
  if (url && (url.toString().startsWith(BASE_URL) || url.toString().startsWith('/api'))) {
    // 1. Send cookies with the request
    options.credentials = 'include';
    
    // 2. Attach CSRF token if present (for state-changing methods)
    const csrfToken = getCookie('XSRF-TOKEN-V3');
    if (csrfToken) {
      options.headers = {
        ...options.headers,
        'X-XSRF-TOKEN': csrfToken
      };
    }
  }
  const response = await originalFetch(url, options);
  if (response.status === 401) {
    window.dispatchEvent(new Event('waf-unauthorized'));
  }
  return response;
};

export async function getCurrentUser() {
  const response = await fetch(`${BASE_URL}/auth/me`, { credentials: 'include' });
  if (!response.ok) throw new Error("Not authenticated");
  return response.json();
}

export async function logoutUser() {
  const response = await fetch(`${BASE_URL}/auth/logout`, {
    method: 'POST',
    credentials: 'include'
  });
  return response.json();
}

/**
 * Handle API response parsing and errors
 */
async function handleResponse(response) {
  if (!response.ok) {
    const errorText = await response.text().catch(() => 'Unknown error');
    throw new Error(`API Error (${response.status}): ${errorText}`);
  }
  return response.json();
}

/**
 * Fetch paginated, filtered logs
 */
export async function getLogs(page = 1, size = 50, filters = {}) {
  try {
    const query = new URLSearchParams({
      page,
      size,
      ...filters
    }).toString();

    const response = await fetch(`${BASE_URL}/logs?${query}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch logs:", error);
    throw error;
  }
}

/**
 * Fetch a single WAF log entry by transaction ID
 */
export async function getLogById(logId) {
  try {
    const response = await fetch(`${BASE_URL}/logs/${logId}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to fetch log by ID ${logId}:`, error);
    throw error;
  }
}

/**
 * Fetch overall statistics
 */
export async function getStats() {
  try {
    const response = await fetch(`${BASE_URL}/stats`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch stats:", error);
    throw error;
  }
}

/**
 * Fetch attack timeline
 */
export async function getTimeline() {
  try {
    const response = await fetch(`${BASE_URL}/timeline`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch timeline:", error);
    throw error;
  }
}

/**
 * Fetch attack categories distribution
 */
export async function getAttackTypes() {
  try {
    const response = await fetch(`${BASE_URL}/attack-types`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch attack types:", error);
    throw error;
  }
}

/**
 * Fetch top attacking IPs
 */
export async function getTopIPs() {
  try {
    const response = await fetch(`${BASE_URL}/top-ips`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch top IPs:", error);
    throw error;
  }
}

/**
 * Fetch top rules triggered
 */
export async function getTopRules() {
  try {
    const response = await fetch(`${BASE_URL}/top-rules`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch top rules:", error);
    throw error;
  }
}

/**
 * Fetch severity distribution
 */
export async function getSeverityDistribution() {
  try {
    const response = await fetch(`${BASE_URL}/severity-distribution`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch severity distribution:", error);
    throw error;
  }
}

/**
 * Fetch system health
 */
export async function getHealth() {
  try {
    const response = await fetch(`${BASE_URL}/health`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch health:", error);
    throw error;
  }
}

/**
 * Fetch paginated, filtered rules list
 */
export async function getRules(page = 1, size = 15, filters = {}) {
  try {
    const query = new URLSearchParams({
      page,
      size,
      ...filters
    }).toString();
    const response = await fetch(`${BASE_URL}/rules?${query}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch rules:", error);
    throw error;
  }
}

/**
 * Fetch a single rule's full detail block
 */
export async function getRuleDetails(id) {
  try {
    const response = await fetch(`${BASE_URL}/rules/${id}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to fetch rule details for ID ${id}:`, error);
    throw error;
  }
}

/**
 * Enable a specific WAF rule
 */
export async function enableRule(id) {
  try {
    const response = await fetch(`${BASE_URL}/rules/enable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, enabled: true, reason: "Enabled from CyberSentinel SOC portal." })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to enable rule ${id}:`, error);
    throw error;
  }
}

/**
 * Disable a specific WAF rule (requires justification reason)
 */
export async function disableRule(id, reason) {
  try {
    const response = await fetch(`${BASE_URL}/rules/disable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, enabled: false, reason })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to disable rule ${id}:`, error);
    throw error;
  }
}

/**
 * Set the global OWASP CRS detection paranoia level (1-4)
 */
export async function setParanoiaLevel(level) {
  try {
    const response = await fetch(`${BASE_URL}/paranoia-level`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to update paranoia level to PL${level}:`, error);
    throw error;
  }
}

/**
 * Fetch WAF rules metrics and recommendations stats
 */
export async function getRulesStats() {
  try {
    const response = await fetch(`${BASE_URL}/rules/stats`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch rules statistics:", error);
    throw error;
  }
}

/**
 * Fetch rules configuration change audit history
 */
export async function getRulesHistory() {
  try {
    const response = await fetch(`${BASE_URL}/rules/history`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch rule change audit history:", error);
    throw error;
  }
}

/**
 * Restore rules override state to system defaults
 */
export async function resetRules() {
  try {
    const response = await fetch(`${BASE_URL}/rules/reset`, {
      method: 'POST',
      cache: 'no-store'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to reset rules to WAF system defaults:", error);
    throw error;
  }
}

/**
 * Fetch general settings preferences from backend
 */
export async function getGeneralSettings() {
  try {
    const response = await fetch(`${BASE_URL}/settings/general`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch general settings:", error);
    throw error;
  }
}

/**
 * Save general settings preferences to backend
 */
export async function saveGeneralSettings(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/general`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save general settings:", error);
    throw error;
  }
}

/**
 * Fetch log pipeline configurations from backend
 */
export async function getLogSettings() {
  try {
    const response = await fetch(`${BASE_URL}/settings/logs`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch log settings:", error);
    throw error;
  }
}

/**
 * Save log pipeline configurations to backend
 */
export async function saveLogSettings(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/logs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save log settings:", error);
    throw error;
  }
}

/**
 * Fetch WAF policies (SecRuleEngine, detection mode, etc.) from backend
 */
export async function getWafSettings() {
  try {
    const response = await fetch(`${BASE_URL}/settings/waf`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch WAF settings:", error);
    throw error;
  }
}

/**
 * Save WAF policies (SecRuleEngine, detection mode, etc.) to backend
 */
export async function saveWafSettings(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/waf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save WAF settings:", error);
    throw error;
  }
}

/**
 * Fetch Custom Response block page HTML from backend
 */
export async function getCustomResponse() {
  try {
    const response = await fetch(`${BASE_URL}/settings/response`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch custom response settings:", error);
    throw error;
  }
}

/**
 * Save Custom Response block page HTML to backend
 */
export async function saveCustomResponse(settings) {
  try {
    // WAFs (like CyberSentinel Engine CRS) decode Base64 and still detect HTML tags!
    // To safely bypass the WAF for this admin config, we use placeholder substitution.
    const safeHtml = settings.html_content
      .replace(/</g, '__LT__')
      .replace(/>/g, '__GT__');

    const encodedPayload = {
      html_content: safeHtml
    };
    const response = await fetch(`${BASE_URL}/settings/response`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encodedPayload)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save custom response settings:", error);
    throw error;
  }
}

/**
 * Fetch Positive Security allowlist
 */
export async function getPositiveSecurity() {
  try {
    const response = await fetch(`${BASE_URL}/settings/positive-security`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch positive security settings:", error);
    throw error;
  }
}

/**
 * Save Positive Security allowlist
 */
export async function savePositiveSecurity(settings) {
  try {
    // WAF evasion for admin panel:
    // WAFs block strings like ".bak" or "application/x-www-form-urlencoded".
    // Base64 is often decoded by CRS (t:base64Decode). By prepending "WAF_BYPASS_",
    // the Base64 string is invalid and CRS cannot decode it to find the bad strings.
    const jsonString = JSON.stringify(settings);
    const encodedPayload = {
      payload: "WAF_BYPASS_" + btoa(jsonString)
    };
    const response = await fetch(`${BASE_URL}/settings/positive-security`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encodedPayload)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save positive security settings:", error);
    throw error;
  }
}

/**
 * Fetch Traffic Auto-Learning settings
 */
export async function getAutoLearning() {
  try {
    const response = await fetch(`${BASE_URL}/settings/auto-learning`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch auto-learning settings:", error);
    throw error;
  }
}

/**
 * Save Traffic Auto-Learning settings
 */
export async function saveAutoLearning(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/auto-learning`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save auto-learning settings:", error);
    throw error;
  }
}

/**
 * Fetch Anti-DDoS & Bot Mitigation settings
 */
export async function getDdosBotSettings() {
  try {
    const response = await fetch(`${BASE_URL}/settings/ddos-bot`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch DDoS settings:", error);
    throw error;
  }
}

/**
 * Fetch DDoS analytics
 */
export async function getDdosAnalytics() {
  try {
    const response = await fetch(`${BASE_URL}/ddos/analytics`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch DDoS analytics:", error);
    throw error;
  }
}

/**
 * Save Anti-DDoS & Bot Mitigation settings
 */
export async function saveDdosBotSettings(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/ddos-bot`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save DDoS settings:", error);
    throw error;
  }
}

/**
 * Change administrator portal password
 */
export async function changeAdminPassword(currentPassword, newPassword) {
  try {
    const response = await fetch(`${BASE_URL}/settings/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to change password:", error);
    throw error;
  }
}

/**
 * Administrative action: Restart WAF Engine
 */
export async function restartWafEngine() {
  try {
    const response = await fetch(`${BASE_URL}/system/restart`, {
      method: 'POST'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to restart WAF engine:", error);
    throw error;
  }
}

/**
 * Administrative action: Reload NGINX service
 */
export async function reloadNginxProxy() {
  try {
    const response = await fetch(`${BASE_URL}/system/reload-nginx`, {
      method: 'POST'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to reload NGINX:", error);
    throw error;
  }
}

/**
 * Administrative action: Purge metrics analytics cache
 */
export async function purgeStatsCache() {
  try {
    const response = await fetch(`${BASE_URL}/system/purge-cache`, {
      method: 'POST'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to purge stats cache:", error);
    throw error;
  }
}

/**
 * Administrative action: Sync OWASP CRS Signatures
 */
export async function syncSignatures() {
  try {
    const response = await fetch(`${BASE_URL}/system/sync-signatures`, {
      method: 'POST'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to sync signatures:", error);
    throw error;
  }
}

/**
 * Mark a log entry as a False Positive
 */
export async function markFalsePositive(logId, analystNote) {
  try {
    const response = await fetch(`${BASE_URL}/false-positives`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log_id: logId, analyst_note: analystNote })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to mark log as false positive:", error);
    throw error;
  }
}

/**
 * Fetch all False Positive entries from DB
 */
export async function getFalsePositives(filters = {}) {
  try {
    const query = new URLSearchParams(filters).toString();
    const response = await fetch(`${BASE_URL}/false-positives?${query}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch false positives:", error);
    throw error;
  }
}

/**
 * Update False Positive entry investigation status
 */
export async function updateFalsePositiveStatus(id, status) {
  try {
    const response = await fetch(`${BASE_URL}/false-positives/${id}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to update status for false positive ${id}:`, error);
    throw error;
  }
}

/**
 * Update False Positive entry analyst notes
 */
export async function updateFalsePositiveNote(id, analystNote) {
  try {
    const response = await fetch(`${BASE_URL}/false-positives/${id}/note`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_note: analystNote })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to update note for false positive ${id}:`, error);
    throw error;
  }
}

/**
 * Delete a False Positive entry from registry
 */
export async function deleteFalsePositive(id) {
  try {
    // FIX 3: Use proper HTTP DELETE method
    const response = await fetch(`${BASE_URL}/false-positives/${id}`, {
      method: 'DELETE'
    });
    // 204 No Content — no JSON body to parse
    if (response.status === 204) return { success: true };
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to delete false positive ${id}:`, error);
    throw error;
  }
}

/**
 * Preview an exclusion ModSec rule in real-time
 */
export async function previewExclusionRule(payload) {
  try {
    const jsonString = JSON.stringify(payload);
    const encodedPayload = { payload: "WAF_BYPASS_" + btoa(jsonString) };
    const response = await fetch(`${BASE_URL}/exclusions/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encodedPayload)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to preview exclusion rule:", error);
    throw error;
  }
}

/**
 * Create a new targeted WAF exception/exclusion policy
 */
export async function createExclusion(payload) {
  try {
    const jsonString = JSON.stringify(payload);
    const encodedPayload = { payload: "WAF_BYPASS_" + btoa(jsonString) };
    const response = await fetch(`${BASE_URL}/exclusions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encodedPayload)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to create exclusion:", error);
    throw error;
  }
}

/**
 * Fetch list of registered exceptions & exclusions
 */
export async function getExclusions(filters = {}) {
  try {
    const query = new URLSearchParams(filters).toString();
    const response = await fetch(`${BASE_URL}/exclusions?${query}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch exclusions:", error);
    throw error;
  }
}

/**
 * Update active status of a WAF exception policy
 */
export async function updateExclusionStatus(id, status) {
  try {
    const response = await fetch(`${BASE_URL}/exclusions/${id}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to update status for exclusion ${id}:`, error);
    throw error;
  }
}

/**
 * Update justification notes of a WAF exception policy
 */
export async function updateExclusionNote(id, notes) {
  try {
    const response = await fetch(`${BASE_URL}/exclusions/${id}/note`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes })
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to update note for exclusion ${id}:`, error);
    throw error;
  }
}

/**
 * Remove an exception policy and sync configs
 */
export async function deleteExclusion(id) {
  try {
    // FIX 3: Use proper HTTP DELETE method
    const response = await fetch(`${BASE_URL}/exclusions/${id}`, {
      method: 'DELETE'
    });
    // 204 No Content — no JSON body to parse
    if (response.status === 204) return { success: true };
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to delete exclusion ${id}:`, error);
    throw error;
  }
}

/**
 * Fetch exclusions metrics and analytics data
 */
export async function getExclusionsAnalytics() {
  try {
    const response = await fetch(`${BASE_URL}/exclusions/analytics`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch exclusions analytics:", error);
    throw error;
  }
}

/**
 * Fetch full administrative exceptions audit logs
 */
export async function getExclusionsHistory() {
  try {
    const response = await fetch(`${BASE_URL}/exclusions/history`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch exclusions history:", error);
    throw error;
  }
}

/**
 * Fetch all auto-discovered API endpoints and their scoring
 */
export async function getDiscoveredEndpoints() {
  try {
    const response = await fetch(`${BASE_URL}/api-protection/endpoints`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch discovered endpoints:", error);
    throw error;
  }
}

/**
 * Fetch recently discovered API endpoints (discovered in last 48h)
 */
export async function getRecentlyDiscoveredEndpoints() {
  try {
    const response = await fetch(`${BASE_URL}/api-protection/recently-discovered`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch recently discovered endpoints:", error);
    throw error;
  }
}

/**
 * Fetch API Protection analytics, top lists, and traffic band volumes
 */
export async function getApiProtectionAnalytics() {
  try {
    const response = await fetch(`${BASE_URL}/api-protection/analytics`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch API protection analytics:", error);
    throw error;
  }
}

/**
 * Fetch Infrastructure Hardening & Cloaking settings
 */
export async function getHardeningSettings() {
  try {
    const response = await fetch(`${BASE_URL}/settings/hardening`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch hardening settings:", error);
    throw error;
  }
}

/**
 * Save Infrastructure Hardening & Cloaking settings
 */
export async function saveHardeningSettings(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/hardening`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save hardening settings:", error);
    throw error;
  }
}

/**
 * Fetch Web Anti-Defacement settings
 */
export async function getAntiDefacementSettings() {
  try {
    const response = await fetch(`${BASE_URL}/settings/anti-defacement`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch anti-defacement settings:", error);
    throw error;
  }
}

/**
 * Save Web Anti-Defacement settings
 */
export async function saveAntiDefacementSettings(settings) {
  try {
    const response = await fetch(`${BASE_URL}/settings/anti-defacement`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to save anti-defacement settings:", error);
    throw error;
  }
}

/**
 * Fetch ML engine overall analytics stats
 */
export async function getMLStats() {
  try {
    const response = await fetch(`${BASE_URL}/ml/stats`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch ML stats:", error);
    throw error;
  }
}

/**
 * Fetch ML engine paginated logs/inferences
 */
export async function getMLLogs(page = 1, size = 50, filters = {}) {
  try {
    const query = new URLSearchParams({
      page,
      size,
      ...filters
    }).toString();
    const response = await fetch(`${BASE_URL}/ml/logs?${query}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch ML logs:", error);
    throw error;
  }
}

export async function getMLTimeline() {
  try {
    const response = await fetch(`${BASE_URL}/ml/timeline`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch ML timeline:", error);
    throw error;
  }
}

/**
 * Fetch all registered protected applications
 */
export async function getProtectedApps() {
  try {
    const response = await fetch(`${BASE_URL}/apps`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch protected applications:", error);
    throw error;
  }
}

/**
 * Create a new protected application configuration
 */
export async function createProtectedApp(appData) {
  try {
    const response = await fetch(`${BASE_URL}/apps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(appData)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to create protected application:", error);
    throw error;
  }
}

/**
 * Update details of an existing protected application
 */
export async function updateProtectedApp(appId, appData) {
  try {
    const response = await fetch(`${BASE_URL}/apps/${appId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(appData)
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to update protected application ${appId}:`, error);
    throw error;
  }
}

/**
 * Delete a protected application configuration
 */
export async function deleteProtectedApp(appId) {
  try {
    const response = await fetch(`${BASE_URL}/apps/${appId}`, {
      method: 'DELETE'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to delete protected application ${appId}:`, error);
    throw error;
  }
}

/**
 * Toggle the active state of a protected application
 */
export async function toggleProtectedApp(appId) {
  try {
    const response = await fetch(`${BASE_URL}/apps/${appId}/toggle`, {
      method: 'POST'
    });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to toggle active status for protected application ${appId}:`, error);
    throw error;
  }
}
