import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import { normalizeIpHost } from '@/lib/security/sanitize';

export interface SsrfValidationResult {
  isSafe: boolean;
  reason?: string;
  resolvedIps?: string[];
  protocol?: string;
  hostname?: string;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '::',
  'metadata.google.internal',
  'metadata.google',
  'metadata',
  'instance-data',
  'kubernetes.default',
  'kubernetes.default.svc',
]);

const BLOCKED_HOSTNAME_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.corp',
  '.home',
  '.intranet',
  '.arpa',
  '.invalid',
  '.test',
];

/**
 * Checks if an IPv4 address is in a private, loopback, link-local, cloud metadata,
 * or reserved range.
 */
export function isPrivateOrBlockedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private)
  if (a === 10) return true;

  // 100.64.0.0/10 (Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-local & AWS/Azure/GCP metadata e.g. 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF protocol assignments)
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Network benchmark tests)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast 224.0.0.0 - 239.255.255.255)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved / Future use)
  if (a >= 240) return true;

  // 255.255.255.255 (Broadcast)
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;

  return false;
}

/**
 * Checks if an IPv6 address is loopback, unique local, link-local, multicast,
 * or an IPv4-mapped IPv6 address pointing to a private IPv4.
 */
export function isPrivateOrBlockedIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase().replace(/^\[|\]$/g, '').trim();

  // ::1 / :: (Loopback & unspecified)
  if (normalized === '::1' || normalized === '::') return true;

  // IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.substring(7);
    if (net.isIPv4(v4Part)) {
      return isPrivateOrBlockedIpv4(v4Part);
    }
  }

  // fe80::/10 (Link-local unicast)
  if (/^fe[89ab]/i.test(normalized)) return true;

  // fc00::/7 (Unique local address fc00:: - fdff::)
  if (/^f[cd]/i.test(normalized)) return true;

  // ff00::/8 (Multicast)
  if (normalized.startsWith('ff')) return true;

  // 64:ff9b::/96 (IPv4-IPv6 translation)
  if (normalized.startsWith('64:ff9b:')) return true;

  // 2001:db8::/32 (Documentation)
  if (normalized.startsWith('2001:db8:') || normalized.startsWith('2001:0db8:')) return true;

  return false;
}

/**
 * Checks any IP address (IPv4 or IPv6), including decimal, octal, and hex representations.
 */
export function isPrivateOrBlockedIp(rawIp: string): boolean {
  const clean = rawIp.replace(/^\[|\]$/g, '').trim();
  const ip = normalizeIpHost(clean);

  if (net.isIPv4(ip)) {
    return isPrivateOrBlockedIpv4(ip);
  }
  if (net.isIPv6(ip)) {
    return isPrivateOrBlockedIpv6(ip);
  }
  return true; // Not a valid IP format, block by default
}

/**
 * Comprehensive SSRF validator for user-submitted URLs.
 * Revalidates protocol, hostnames, and resolves DNS to prevent internal network scanning.
 */
export async function validateUrlSsrf(urlString: string): Promise<SsrfValidationResult> {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return {
      isSafe: false,
      reason: 'Invalid URL format.',
    };
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    return {
      isSafe: false,
      protocol,
      reason: `Unsupported protocol '${protocol}'. Only HTTP and HTTPS are permitted for security scanning.`,
    };
  }

  let rawHostname = parsed.hostname.toLowerCase().trim();
  let hostname = rawHostname.replace(/^\[|\]$/g, '');

  // Strip trailing dot if present
  if (hostname.endsWith('.') && hostname.length > 1) {
    hostname = hostname.slice(0, -1);
  }

  if (!hostname) {
    return {
      isSafe: false,
      reason: 'Missing hostname.',
    };
  }

  // Normalize decimal/octal/hex IP host representation
  const normalizedHostIp = normalizeIpHost(hostname);

  // 1. Check known blocked hostnames
  if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_HOSTNAMES.has(normalizedHostIp)) {
    return {
      isSafe: false,
      hostname,
      reason: `Blocked target: Hostname '${hostname}' points to a local or internal system.`,
    };
  }

  // 2. Check blocked domain suffixes (.local, .internal, etc.)
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (hostname.endsWith(suffix)) {
      return {
        isSafe: false,
        hostname,
        reason: `Blocked target: Internal network top-level domain '${suffix}' is not permitted.`,
      };
    }
  }

  // 3. Direct IP address verification
  if (net.isIP(normalizedHostIp)) {
    if (isPrivateOrBlockedIp(normalizedHostIp)) {
      return {
        isSafe: false,
        hostname,
        reason: `Blocked target: IP address '${hostname}' is a private, loopback, or cloud-internal address.`,
      };
    }
    return {
      isSafe: true,
      protocol,
      hostname,
      resolvedIps: [normalizedHostIp],
    };
  }

  // 4. DNS resolution and verification of all resolved IP records
  try {
    const resolvedIps: string[] = [];

    // Attempt IPv4 resolution
    try {
      const v4Addresses = await dns.resolve4(hostname);
      resolvedIps.push(...v4Addresses);
    } catch {
      // IPv4 may not exist
    }

    // Attempt IPv6 resolution
    try {
      const v6Addresses = await dns.resolve6(hostname);
      resolvedIps.push(...v6Addresses);
    } catch {
      // IPv6 may not exist
    }

    if (resolvedIps.length === 0) {
      return {
        isSafe: true,
        protocol,
        hostname,
        resolvedIps: [],
      };
    }

    // Ensure NONE of the resolved IPs are in private/internal ranges
    for (const ip of resolvedIps) {
      if (isPrivateOrBlockedIp(ip)) {
        return {
          isSafe: false,
          hostname,
          resolvedIps,
          reason: `DNS rebinding / SSRF protection triggered: '${hostname}' resolved to private/internal IP address '${ip}'.`,
        };
      }
    }

    return {
      isSafe: true,
      protocol,
      hostname,
      resolvedIps,
    };
  } catch {
    // DNS resolution failure is not an SSRF threat; allow downstream analysis
    return {
      isSafe: true,
      protocol,
      hostname,
      resolvedIps: [],
    };
  }
}
