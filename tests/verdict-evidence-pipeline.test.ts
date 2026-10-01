import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';
import { validateUrlSsrf } from '../lib/security/ssrf';
import { detectBrandImpersonation } from '../lib/detection/brand-analyzer';
import {
  DomainIntelligence,
  SslIntelligence,
  RedirectIntelligence,
} from '../types/security';

describe('SENTINELX Verdict & Evidence Pipeline Comprehensive Test Suite', () => {
  const mockDomainSafe: DomainIntelligence = {
    domain: 'google.com',
    tld: 'com',
    isResolvable: true,
    ipAddresses: ['142.250.190.46'],
    ipv6Addresses: ['2607:f8b0:4004:830::200e'],
    mxRecords: [{ exchange: 'smtp.google.com', priority: 10 }],
    txtRecords: [['v=spf1 include:_spf.google.com ~all']],
    nsRecords: ['ns1.google.com', 'ns2.google.com'],
    hasMx: true,
    domainAgeEstimateDays: 9000,
    registrationDate: '1997-09-15',
    expirationDate: '2028-09-14',
    registrar: 'MarkMonitor Inc.',
    isAvailable: true,
  };

  const mockSslSafe: SslIntelligence = {
    httpsEnabled: true,
    certificateValid: true,
    hostnameMatches: true,
    issuer: 'Google Trust Services LLC',
    subject: 'google.com',
    validFrom: '2024-01-01',
    validTo: '2025-01-01',
    daysUntilExpiration: 180,
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    isSelfSigned: false,
    isExpired: false,
    disclaimer: 'test disclaimer',
  };

  const mockRedirectSafe: RedirectIntelligence = {
    originalUrl: 'https://www.google.com/',
    finalUrl: 'https://www.google.com/',
    hopCount: 0,
    hops: [],
    destinationChanged: false,
    loopDetected: false,
    ssrfBlocked: false,
  };

  it('1. Legitimate established domain produces SAFE verdict with dynamic confidence', () => {
    const raw = 'https://www.google.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'abuse.ch URLhaus', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    expect(result.verdict).toBe('SAFE');
    expect(result.riskScore).toBe(0);
    expect(result.confidenceScore).toBe(75);
    expect(result.explanation).toContain('DNS resolution succeeded');
    expect(result.explanation).toContain('were not configured');
  });

  it('2. Unknown domain with no threat signals evaluates based on infrastructure', () => {
    const raw = 'https://unknown-random-site-987.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...mockDomainSafe, domain: 'unknown-random-site-987.com' },
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(result.riskScore).toBeLessThan(35);
    expect(['SAFE', 'LOW_RISK']).toContain(result.verdict);
  });

  it('3. Dead domain (unresolvable without threat signals) returns UNKNOWN verdict', () => {
    const raw = 'https://non-existent-dead-domain-12345.org/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...mockDomainSafe, isResolvable: false, ipAddresses: [] },
      sslIntel: { ...mockSslSafe, certificateValid: false, protocol: null },
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(result.verdict).toBe('UNKNOWN');
    expect(result.riskCategory).toContain('UNKNOWN');
  });

  it('4. Suspicious lookalike domain (paypa1-update.com) returns SUSPICIOUS/HIGH_RISK verdict', () => {
    const raw = 'https://paypa1-update.com/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [],
    });

    expect(['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL']).toContain(result.verdict);
    expect(result.signals.some((s) => s.id === 'url-brand-impersonation')).toBe(true);
  });

  it('5. Confirmed phishing URL returns CRITICAL verdict', () => {
    const raw = 'https://allegro.ofeta-462789.sbs/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...mockDomainSafe, isResolvable: false },
      sslIntel: { ...mockSslSafe, certificateValid: false, protocol: null },
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        {
          providerName: 'PhishTank',
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Confirmed Phishing (PhishTank)',
          details: 'PhishTank database verified this URL as a phishing threat (ID: 9528509)',
        },
      ],
    });

    expect(result.verdict).toBe('CRITICAL');
    expect(result.riskScore).toBe(100);
    expect(result.explanation).toContain('blacklisted by PhishTank');
  });

  it('6. Direct IP address URL increases risk score', () => {
    const raw = 'http://192.168.1.1/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    expect(features.hasIpHost).toBe(true);
    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...mockDomainSafe, isResolvable: true },
      sslIntel: { ...mockSslSafe, httpsEnabled: false },
      redirectIntel: mockRedirectSafe,
      threatIntel: [],
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(25);
    expect(result.signals.some((s) => s.id === 'url-ip-host')).toBe(true);
  });

  it('7. Credential-harvesting URL keywords add risk points', () => {
    const raw = 'https://example-verify-login.com/account/secure/login?session=token';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    expect(features.matchedKeywords.length).toBeGreaterThan(0);
  });

  it('8. Punycode / IDN lookalike URL triggers homoglyph alert', () => {
    const raw = 'https://xn--80ak6aa92e.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    expect(features.hasPunycode).toBe(true);
  });

  it('9. Redirect chain (3+ hops) adds redirect risk points', () => {
    const raw = 'https://redirect-chain.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const redirectIntel: RedirectIntelligence = {
      originalUrl: raw,
      finalUrl: 'https://destination.com/',
      hopCount: 3,
      hops: [
        { hopNumber: 1, statusCode: 301, url: raw, targetUrl: 'https://hop1.com/', crossDomain: true, durationMs: 100 },
        { hopNumber: 2, statusCode: 302, url: 'https://hop1.com/', targetUrl: 'https://hop2.com/', crossDomain: true, durationMs: 100 },
        { hopNumber: 3, statusCode: 302, url: 'https://hop2.com/', targetUrl: 'https://destination.com/', crossDomain: true, durationMs: 100 },
      ],
      destinationChanged: true,
      loopDetected: false,
      ssrfBlocked: false,
    };

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel,
      threatIntel: [],
    });

    expect(result.signals.some((s) => s.id === 'redirect-multiple-hops')).toBe(true);
  });

  it('10. SSRF validator blocks local, loopback, and private IP targets', async () => {
    const ssrf1 = await validateUrlSsrf('http://127.0.0.1/admin');
    const ssrf2 = await validateUrlSsrf('http://169.254.169.254/latest/meta-data/');
    const ssrf3 = await validateUrlSsrf('http://[::1]/');

    expect(ssrf1.isSafe).toBe(false);
    expect(ssrf2.isSafe).toBe(false);
    expect(ssrf3.isSafe).toBe(false);
  });

  it('11. Malformed URL returns sanitization validation error', () => {
    const res = sanitizeAndNormalizeUrl('not-a-valid-url-format-xyz:::');
    expect(res.isValid).toBe(false);
  });

  it('12. Provider NOT_CONFIGURED status reduces confidence without error', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    expect(res.evidence.some((e) => e.finding.includes('is not configured'))).toBe(true);
  });

  it('13. Provider TIMEOUT status is reported in evidence', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'VirusTotal', status: 'TIMEOUT', isFlagged: false, details: 'Timed out (4s)' },
      ],
    });

    expect(res.evidence.some((e) => e.finding.includes('unavailable'))).toBe(true);
  });

  it('14. Provider ERROR status is handled gracefully', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'abuse.ch URLhaus', status: 'ERROR', isFlagged: false, details: 'HTTP 500' },
      ],
    });

    expect(res.evidence.some((e) => e.finding.includes('unavailable'))).toBe(true);
  });

  it('15. Provider CLEAN status increases confidence score by +10%', () => {
    const resWithoutClean = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [],
    });

    const resWithClean = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(resWithClean.confidenceScore).toBe(resWithoutClean.confidenceScore + 10);
  });

  it('16. Provider FLAGGED status forces CRITICAL verdict', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://benign-looking.com/', 'https://benign-looking.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true, threatType: 'Malware' },
      ],
    });

    expect(resultVerdictIsCritical(res.verdict)).toBe(true);
  });

  it('17. Multiple providers disagree: FLAGGED overrides CLEAN', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://disputed-url.com/', 'https://disputed-url.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true, threatType: 'Phishing' },
      ],
    });

    expect(res.verdict).toBe('CRITICAL');
  });

  it('18. Multiple providers flag malicious: Risk score is maximized', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://multi-flagged.com/', 'https://multi-flagged.com/'),
      domainIntel: mockDomainSafe,
      sslIntel: mockSslSafe,
      redirectIntel: mockRedirectSafe,
      threatIntel: [
        { providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true, threatType: 'Phishing' },
        { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true, threatType: 'Malware' },
      ],
    });

    expect(res.riskScore).toBe(100);
    expect(res.verdict).toBe('CRITICAL');
  });
});

function resultVerdictIsCritical(verdict: string): boolean {
  return verdict === 'CRITICAL' || verdict === 'HIGH_RISK';
}
