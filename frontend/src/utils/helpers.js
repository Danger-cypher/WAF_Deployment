export function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

export const formatLocalTime = (utcString) => {
  if (!utcString) return '-';
  try {
    let cleanStr = String(utcString).trim();
    cleanStr = cleanStr.replace('T', ' ').replace('Z', '');

    // Parse as UTC and convert to local timezone
    const date = new Date(cleanStr + 'Z'); // Add Z to indicate UTC
    if (isNaN(date.getTime())) {
      // Fallback: if parsing fails, just remove Z and return
      return cleanStr;
    }

    // Convert to local time string
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }).replace(/,/g, '').replace(/\//g, '-');
  } catch {
    // Final fallback - just clean up the string
    let cleanStr = String(utcString).trim();
    cleanStr = cleanStr.replace('T', ' ').replace('Z', '');
    return cleanStr.split('.')[0];
  }
};
