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
  ThreatIntelResult,
} from '../types/security';

describe('SENTINELX Evidence-Based URL Threat Detection & Dynamic Confidence Engine', () => {
  const benignDomainIntel: DomainIntelligence = {
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

  const benignSslIntel: SslIntelligence = {
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

  const benignRedirectIntel: RedirectIntelligence = {
    originalUrl: 'https://google.com/',
    finalUrl: 'https://google.com/',
    hopCount: 0,
    hops: [],
    destinationChanged: false,
    loopDetected: false,
    ssrfBlocked: false,
  };

  it('1. Verifies 5 distinct URLs produce DIFFERENT, DYNAMIC confidence scores based on evidence', () => {
    // URL 1: Google with full configured threat intel feeds (All 4 CLEAN)
    const res1 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'abuse.ch URLhaus', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'CLEAN', isFlagged: false },
        { providerName: 'VirusTotal', status: 'CLEAN', isFlagged: false },
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
      ],
    });

    // URL 2: Legitimate domain with only 1 active provider (3 NOT_CONFIGURED)
    const res2 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://example.com/', 'https://example.com/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'abuse.ch URLhaus', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'PhishTank', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    // URL 3: Unencrypted HTTP website without DNS MX records
    const res3 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('http://my-insecure-site.org/info', 'http://my-insecure-site.org/info'),
      domainIntel: { ...benignDomainIntel, hasMx: false, nsRecords: [] },
      sslIntel: { ...benignSslIntel, httpsEnabled: false, certificateValid: false, protocol: null },
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'abuse.ch URLhaus', status: 'CLEAN', isFlagged: false },
      ],
    });

    // URL 4: Unresolvable dead domain with timeout
    const res4 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://dead-domain-999.xyz/', 'https://dead-domain-999.xyz/'),
      domainIntel: { ...benignDomainIntel, isResolvable: false, ipAddresses: [] },
      sslIntel: { ...benignSslIntel, protocol: null },
      redirectIntel: { ...benignRedirectIntel, error: 'Connection timeout' },
      threatIntel: [
        { providerName: 'abuse.ch URLhaus', status: 'TIMEOUT', isFlagged: false },
      ],
    });

    // URL 5: Blacklisted phishing target with VT 14 detections
    const res5 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://paypa1-update-security.com/login', 'https://paypa1-update-security.com/login'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        {
          providerName: 'VirusTotal',
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Phishing',
          stats: { maliciousEngineCount: 14, totalEngineCount: 72 },
        },
      ],
    });

    // Print confidence and evidence summary for each scan
    console.log('--- SCAN CONFIDENCE & EVIDENCE COMPARISON ---');
    console.log(`URL 1 (Full Threat Feeds): Confidence=${res1.confidenceScore}%, Verdict=${res1.verdict}`);
    console.log(`URL 2 (Partial Feeds): Confidence=${res2.confidenceScore}%, Verdict=${res2.verdict}`);
    console.log(`URL 3 (HTTP/No MX): Confidence=${res3.confidenceScore}%, Verdict=${res3.verdict}`);
    console.log(`URL 4 (Unresolvable): Confidence=${res4.confidenceScore}%, Verdict=${res4.verdict}`);
    console.log(`URL 5 (VT 14 Detections): Confidence=${res5.confidenceScore}%, Verdict=${res5.verdict}`);

    // Assert that confidence is DYNAMIC and NOT fixed to 90% for all scans
    expect(res1.confidenceScore).toBe(100);
    expect(res2.confidenceScore).toBe(75);
    expect(res3.confidenceScore).toBe(70);
    expect(res4.confidenceScore).toBe(20);
    expect(res5.confidenceScore).toBe(80);
  });

  it('2. Generates REAL URL-specific explanations containing exact provider counts and domain findings', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://paypa1-verify-account.com/login', 'https://paypa1-verify-account.com/login'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        {
          providerName: 'VirusTotal',
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Phishing',
          stats: { maliciousEngineCount: 12, totalEngineCount: 70 },
        },
      ],
    });

    expect(res.explanation).toContain('VirusTotal (12/70 engines flagged)');
    expect(res.explanation).toContain('paypa1'); // Domain name finding
    expect(res.explanation).toContain('login'); // Keyword finding
    expect(res.evidence.some((e) => e.source === 'VirusTotal')).toBe(true);
    expect(res.evidence.some((e) => e.source === 'Brand Analysis')).toBe(true);
  });

  it('3. Explicitly mentions missing/unconfigured providers in the explanation when API keys are absent', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'abuse.ch URLhaus', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'PhishTank', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    expect(res.explanation).toContain('Google Safe Browsing');
    expect(res.explanation).toContain('were not configured for this server deployment');
    expect(res.explanation).toContain('75%');
  });

  it('4. Typosquatting brand impersonation (g00gle.com, paypa1.com) is dynamically detected', () => {
    const brand1 = detectBrandImpersonation('g00gle.com');
    const brand2 = detectBrandImpersonation('paypa1.com');

    expect(brand1.detected).toBe(true);
    expect(brand1.brandFound).toBe('google');
    expect(brand2.detected).toBe(true);
    expect(brand2.brandFound).toBe('paypal');
  });

  it('5. SSRF protection blocks private IPv4, IPv6 [::1], and decimal DWORD IP (2130706433)', async () => {
    const res1 = await validateUrlSsrf('http://127.0.0.1/admin');
    const res2 = await validateUrlSsrf('http://[::1]/');
    const res3 = await validateUrlSsrf('http://2130706433/'); // 127.0.0.1 in decimal

    expect(res1.isSafe).toBe(false);
    expect(res2.isSafe).toBe(false);
    expect(res3.isSafe).toBe(false);
  });
});
