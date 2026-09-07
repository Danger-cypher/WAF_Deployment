// `displayName` (e.g. "Jane Doe") is optional — when present, initials
// follow the first+last-name convention every reference product (GitHub,
// Slack, Linear) uses, instead of just the first two characters of the
// account's login handle, which reads oddly for anything but a single-word
// username (e.g. "jane.doe" → "JA" instead of "JD").
export function initialsFor(username, displayName) {
  const name = (displayName || '').trim();
  if (name) {
    const words = name.split(/\s+/).filter(Boolean);
    if (words.length >= 2) {
      return (words[0][0] + words[words.length - 1][0]).toUpperCase();
    }
    return words[0].slice(0, 2).toUpperCase();
  }
  if (!username) return '?';
  return username.trim().slice(0, 2).toUpperCase();
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
