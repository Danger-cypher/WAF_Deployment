/**
 * Fetch security audit statistics
 */
export async function getSecurityStatistics(hours = 24) {
  try {
    const response = await fetch(`${BASE_URL}/security/statistics?hours=${hours}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch security statistics:", error);
    throw error;
  }
}

/**
 * Fetch all security events
 */
export async function getSecurityEvents(hours = 24, limit = 100, page = 1, page_size = 50) {
  try {
    const query = new URLSearchParams({
      hours,
      limit,
      page,
      page_size
    }).toString();
    const response = await fetch(`${BASE_URL}/security/events?${query}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch security events:", error);
    throw error;
  }
}

/**
 * Fetch authentication events
 */
export async function getAuthEvents(hours = 24, success = null) {
  try {
    const params = new URLSearchParams({ hours });
    if (success !== null) params.append('success', success);
    const response = await fetch(`${BASE_URL}/security/events/auth?${params}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch auth events:", error);
    throw error;
  }
}

/**
 * Fetch rate limit events
 */
export async function getRateLimitEvents(hours = 24) {
  try {
    const response = await fetch(`${BASE_URL}/security/events/rate-limits?hours=${hours}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch rate limit events:", error);
    throw error;
  }
}

/**
 * Fetch input validation events
 */
export async function getInputValidationEvents(hours = 24, violationType = null) {
  try {
    const params = new URLSearchParams({ hours });
    if (violationType) params.append('violation_type', violationType);
    const response = await fetch(`${BASE_URL}/security/events/input-validation?${params}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error("Failed to fetch input validation events:", error);
    throw error;
  }
}

/**
 * Get IP security profile
 */
export async function getIPSecurityProfile(ipAddress, hours = 24) {
  try {
    const response = await fetch(`${BASE_URL}/security/ip/${ipAddress}?hours=${hours}`, { cache: 'no-store' });
    return await handleResponse(response);
  } catch (error) {
    console.error(`Failed to fetch IP profile for ${ipAddress}:`, error);
    throw error;
  }
}
