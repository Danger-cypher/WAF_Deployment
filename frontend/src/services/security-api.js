const BASE_URL = `${window.location.protocol}//${window.location.host}/api`;

async function handleResponse(response) {
  if (!response.ok) {
    const errorText = await response.text().catch(() => 'Unknown error');
    throw new Error(`API Error (${response.status}): ${errorText}`);
  }
  return response.json();
}

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
