export interface NormalizedUrlResult {
  isValid: boolean;
  normalizedUrl: string;
  error?: string;
}

const MAX_URL_LENGTH = 2048;

/**
 * Parses non-standard IPv4 representations:
 * - Decimal DWORD: e.g. 2130706433 -> 127.0.0.1
 * - Hexadecimal: e.g. 0x7f000001 -> 127.0.0.1
 * - Octal: e.g. 0177.0.0.1 -> 127.0.0.1
 */
export function normalizeIpHost(hostname: string): string {
  const trimmed = hostname.trim().toLowerCase();

  // Single integer dword decimal IP (e.g. 2130706433)
  if (/^\d+$/.test(trimmed)) {
    const num = parseInt(trimmed, 10);
    if (num >= 0 && num <= 0xffffffff) {
      return [
        (num >>> 24) & 0xff,
        (num >>> 16) & 0xff,
        (num >>> 8) & 0xff,
        num & 0xff,
      ].join('.');
    }
  }

  // Single hex DWORD (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(trimmed)) {
    const num = parseInt(trimmed, 16);
    if (num >= 0 && num <= 0xffffffff) {
      return [
        (num >>> 24) & 0xff,
        (num >>> 16) & 0xff,
        (num >>> 8) & 0xff,
        num & 0xff,
      ].join('.');
    }
  }

  // Dotted octal/hex/decimal parts (e.g. 0177.0.0.1 or 0x7f.0.0.1)
  const parts = trimmed.split('.');
  if (parts.length === 4) {
    const parsedParts: number[] = [];
    for (const part of parts) {
      let val: number;
      if (/^0x[0-9a-f]+$/i.test(part)) {
        val = parseInt(part, 16);
      } else if (/^0[0-7]+$/.test(part)) {
        val = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        return hostname;
      }
      if (isNaN(val) || val < 0 || val > 255) return hostname;
      parsedParts.push(val);
    }
    return parsedParts.join('.');
  }

  return hostname;
}

/**
 * Sanitizes and normalizes incoming raw URLs into a canonical representation for analysis.
 */
export function sanitizeAndNormalizeUrl(rawInput: string): NormalizedUrlResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      isValid: false,
      normalizedUrl: '',
      error: 'Please enter a valid URL to analyze.',
    };
  }

  let trimmed = rawInput.trim();

  // Strip enclosing quotes, brackets, or trailing punctuation
  trimmed = trimmed.replace(/^["'<(\[]+|["'>)\]]+$/g, '');

  if (trimmed.length === 0) {
    return {
      isValid: false,
      normalizedUrl: '',
      error: 'URL cannot be empty.',
    };
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      isValid: false,
      normalizedUrl: '',
      error: `URL exceeds maximum allowable length of ${MAX_URL_LENGTH} characters.`,
    };
  }

  // Prepend https:// if protocol is missing
  if (!/^https?:\/\//i.test(trimmed)) {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(trimmed)) {
      // Non-HTTP protocol (e.g. ftp://, file://, data://)
    } else {
      trimmed = 'https://' + trimmed;
    }
  }

  try {
    const parsed = new URL(trimmed);

    // Strip credentials (user:pass@)
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }

    let hostname = parsed.hostname.toLowerCase();

    // Strip trailing dot from FQDN (e.g., google.com. -> google.com)
    if (hostname.endsWith('.') && hostname.length > 1) {
      hostname = hostname.slice(0, -1);
    }

    // Normalize IPv4 representations
    const normalizedHost = normalizeIpHost(hostname);
    if (normalizedHost !== hostname) {
      parsed.hostname = normalizedHost;
    } else {
      parsed.hostname = hostname;
    }

    // Hostname must exist and not be empty
    if (!parsed.hostname || parsed.hostname.trim() === '') {
      return {
        isValid: false,
        normalizedUrl: '',
        error: 'URL does not contain a valid hostname.',
      };
    }

    // Remove default ports (80 for http, 443 for https)
    if ((parsed.protocol === 'http:' && parsed.port === '80') ||
        (parsed.protocol === 'https:' && parsed.port === '443')) {
      parsed.port = '';
    }

    return {
      isValid: true,
      normalizedUrl: parsed.toString(),
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Invalid URL syntax';
    return {
      isValid: false,
      normalizedUrl: '',
      error: `Malformed URL: ${msg}`,
    };
  }
}
