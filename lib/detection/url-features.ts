import * as net from 'node:net';
import { UrlFeatures, MatchedKeyword } from '@/types/security';
import { SUSPICIOUS_KEYWORDS } from '@/lib/constants/keywords';
import { isRiskyTld } from '@/lib/constants/tlds';
import { getShortenerInfo } from '@/lib/constants/shorteners';
import { detectHomoglyphs } from '@/lib/constants/homoglyphs';
import { detectBrandImpersonation } from '@/lib/detection/brand-analyzer';
import { normalizeIpHost } from '@/lib/security/sanitize';

/**
 * Calculates Shannon entropy of a string (measures randomness).
 * Phishing/DGA domains often have high entropy (e.g., > 4.2).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Extracts comprehensive lexical, structural, and linguistic features from a URL.
 */
export function extractUrlFeatures(rawUrl: string, normalizedUrl: string): UrlFeatures {
  const parsed = new URL(normalizedUrl);
  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname || '/';
  const queryString = parsed.search ? parsed.search.substring(1) : '';
  const fragment = parsed.hash ? parsed.hash.substring(1) : '';

  // Host components
  const hostParts = hostname.split('.');
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
  const subdomains = hostParts.length > 2 ? hostParts.slice(0, -2) : [];

  // IP address detection (including decimal/octal/hex IP hosts)
  const normalizedHost = normalizeIpHost(hostname);
  const isIp = net.isIP(hostname) !== 0 || net.isIP(normalizedHost) !== 0;
  const isIpv6 = net.isIPv6(hostname) || net.isIPv6(normalizedHost);

  // Character counts
  const hyphenCount = (rawUrl.match(/-/g) || []).length;
  const dotCount = (rawUrl.match(/\./g) || []).length;
  const percentEncodedCount = (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
  const hasAtSymbol = rawUrl.includes('@');

  // Punycode & IDN Homoglyph detection
  const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  let punycodeDecoded: string | undefined;
  if (hasPunycode) {
    try {
      punycodeDecoded = decodeURI(hostname);
    } catch {
      punycodeDecoded = hostname;
    }
  }

  const homoglyphCheck = detectHomoglyphs(rawUrl);

  // Entropy calculation on hostname and path
  const entropy = calculateShannonEntropy(hostname + path);

  // Suspicious keywords spotting
  const matchedKeywords: MatchedKeyword[] = [];
  const lowerPath = path.toLowerCase();
  const lowerQuery = queryString.toLowerCase();
  const lowerHost = hostname.toLowerCase();

  for (const item of SUSPICIOUS_KEYWORDS) {
    const word = item.word.toLowerCase();

    if (lowerHost.includes(word)) {
      matchedKeywords.push({
        category: item.category,
        keyword: item.word,
        location: 'host',
      });
    } else if (lowerPath.includes(word)) {
      matchedKeywords.push({
        category: item.category,
        keyword: item.word,
        location: 'path',
      });
    } else if (lowerQuery.includes(word)) {
      matchedKeywords.push({
        category: item.category,
        keyword: item.word,
        location: 'query',
      });
    }
  }

  // Extended structural heuristics (Section 3.A & 3.B)
  const pathSegments = path.split('/').filter(Boolean);
  const pathSegmentCount = pathSegments.length;

  // Nested URL in query/path check (e.g., ?url=https://..., ?dest=http://...)
  const hasNestedUrl = /https?:\/\//i.test(queryString) || /https?:\/\//i.test(path);

  // Suspicious query parameters (open-redirect & phishing parameter patterns)
  const suspiciousParamsList = ['url', 'redirect', 'goto', 'target', 'dest', 'next', 'return', 'link', 'callback', 'to', 'out', 'r'];
  const suspiciousQueryParams: string[] = [];
  if (parsed.searchParams) {
    for (const key of Array.from(parsed.searchParams.keys())) {
      if (suspiciousParamsList.includes(key.toLowerCase())) {
        suspiciousQueryParams.push(key);
      }
    }
  }

  // Suspicious file extension
  let suspiciousFileExtension: string | null = null;
  const lastSegment = pathSegments.length > 0 ? pathSegments[pathSegments.length - 1] : '';
  const extMatch = lastSegment.match(/\.([a-zA-Z0-9]+)$/);
  if (extMatch) {
    const ext = extMatch[1].toLowerCase();
    if (['exe', 'scr', 'bat', 'vbs', 'cmd', 'ps1', 'cgi', 'php', 'asp', 'aspx'].includes(ext)) {
      suspiciousFileExtension = ext;
    }
  }

  // Non-standard unusual port check
  const portNum = parsed.port ? parseInt(parsed.port, 10) : null;
  const isStandardPort = portNum === null || portNum === 80 || portNum === 443;
  const unusualPort = !isStandardPort;

  // Shortener & TLD checks
  const shortenerInfo = getShortenerInfo(hostname);
  const riskyTld = isRiskyTld(tld);
  const brandImpersonation = detectBrandImpersonation(hostname);

  return {
    rawUrl,
    normalizedUrl,
    protocol: parsed.protocol.replace(':', ''),
    hostname,
    port: portNum,
    path,
    queryString,
    fragment,
    length: rawUrl.length,
    paramCount: parsed.searchParams ? Array.from(parsed.searchParams.keys()).length : 0,
    subdomainCount: subdomains.length,
    subdomains,
    tld,
    hasIpHost: isIp,
    isIpv6,
    hasAtSymbol,
    hasPunycode,
    punycodeDecoded,
    hasHomoglyphs: homoglyphCheck.hasHomoglyphs,
    homoglyphsFound: homoglyphCheck.characters,
    hyphenCount,
    dotCount,
    percentEncodedCount,
    entropy,
    matchedKeywords,
    isKnownShortener: shortenerInfo.isShortener,
    shortenerName: shortenerInfo.name,
    isRiskyTld: riskyTld,
    brandImpersonation,
    pathSegmentCount,
    hasNestedUrl,
    suspiciousQueryParams,
    suspiciousFileExtension,
    unusualPort,
  };
}
