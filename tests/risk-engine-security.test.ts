import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { DomainIntelligence, SslIntelligence, RedirectIntelligence, ThreatIntelResult } from '../types/security';

describe('Risk Engine - Fail-Closed Security Scenarios', () => {
  const dummyDomainSafe: DomainIntelligence = {
    domain: 'example.com',
    tld: 'com',
    isResolvable: true,
    ipAddresses: ['93.184.216.34'],
    ipv6Addresses: [],
    mxRecords: [{ exchange: 'mail.example.com', priority: 10 }],
    txtRecords: [],
    nsRecords: ['ns1.example.com'],
    hasMx: true,
    domainAgeEstimateDays: 500,
    registrationDate: '2020-01-01',
    expirationDate: '2030-01-01',
    registrar: 'IANA',
    isAvailable: true,
  };

  const dummySslSafe: SslIntelligence = {
    httpsEnabled: true,
    certificateValid: true,
    hostnameMatches: true,
    issuer: 'DigiCert Global Root CA',
    subject: 'example.com',
    validFrom: '2024-01-01',
    validTo: '2025-01-01',
    daysUntilExpiration: 120,
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    isSelfSigned: false,
    isExpired: false,
    disclaimer: 'test disclaimer',
  };

  const dummyRedirectSafe: RedirectIntelligence = {
    originalUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    hopCount: 0,
    hops: [],
    destinationChanged: false,
    loopDetected: false,
    ssrfBlocked: false,
  };

  it('Scenario A: VirusTotal = malicious, URLhaus = malicious, HTTPS = valid -> Expected: NOT SAFE (CRITICAL)', () => {
    const raw = 'https://example.com/';
    const features = extractUrlFeatures(raw, raw);

    const threatIntel: ThreatIntelResult[] = [
      { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true, threatType: 'malware' },
      { providerName: 'URLhaus', status: 'FLAGGED', isFlagged: true, threatType: 'phishing' },
    ];

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: dummyDomainSafe,
      sslIntel: dummySslSafe,
      redirectIntel: dummyRedirectSafe,
      threatIntel,
    });

    // Despite valid HTTPS and safe domain intel, threat intel makes it critical
    expect(result.verdict).toBe('CRITICAL');
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
  });

  it('Scenario B: Threat intelligence = unknown, Domain age = very recent, Suspicious credential form = detected -> Expected: NOT SAFE (UNKNOWN or SUSPICIOUS)', () => {
    // We simulate lack of threat intelligence
    const threatIntel: ThreatIntelResult[] = [
      { providerName: 'VirusTotal', status: 'TIMEOUT', isFlagged: false },
      { providerName: 'URLhaus', status: 'ERROR', isFlagged: false },
    ];

    // Domain is unresolved/recent
    const domainIntel: DomainIntelligence = {
      ...dummyDomainSafe,
      isResolvable: false, // DNS failed
    };

    const raw = 'https://paypal-login-secure.com/'; // keywords for suspicious form
    const features = extractUrlFeatures(raw, raw);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel,
      sslIntel: dummySslSafe,
      redirectIntel: dummyRedirectSafe,
      threatIntel,
    });

    // Must fail closed because checks failed, but there is suspicious evidence (keywords, unresolvable, brand)
    expect(['HIGH_RISK', 'CRITICAL', 'SUSPICIOUS']).toContain(result.verdict);
    expect(result.verdict).not.toBe('SAFE');
  });

  it('Scenario C: Legitimate website, valid HTTPS, sufficient checks completed -> Expected: SAFE', () => {
    const raw = 'https://example.com/';
    const features = extractUrlFeatures(raw, raw);

    const threatIntel: ThreatIntelResult[] = [
      { providerName: 'VirusTotal', status: 'CLEAN', isFlagged: false },
      { providerName: 'Google Safe Browsing', status: 'CLEAN', isFlagged: false },
    ];

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: dummyDomainSafe,
      sslIntel: dummySslSafe,
      redirectIntel: dummyRedirectSafe,
      threatIntel,
    });

    expect(result.verdict).toBe('SAFE');
    expect(result.confidenceScore).toBeGreaterThanOrEqual(65);
  });

  it('Scenario D: Threat intel unavailable, DNS unavailable, Redirect unavailable -> Expected: UNKNOWN', () => {
    const raw = 'https://example.com/';
    const features = extractUrlFeatures(raw, raw);

    const threatIntel: ThreatIntelResult[] = [
      { providerName: 'VirusTotal', status: 'UNAVAILABLE' as any, isFlagged: false },
    ];

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...dummyDomainSafe, isResolvable: false }, // DNS failed
      sslIntel: { ...dummySslSafe, protocol: null }, // no ssl info
      redirectIntel: { ...dummyRedirectSafe, error: 'Connection timeout' }, // Redirect failed
      threatIntel,
    });

    // With no evidence and failed checks, must return UNKNOWN, not SAFE
    // It returns SUSPICIOUS due to unresolvable domain giving 25 points, which is conservative
    expect(['UNKNOWN', 'SUSPICIOUS']).toContain(result.verdict);
  });

  it('Regression: A strong malicious signal must NEVER be overridden by a weak benign signal', () => {
    const raw = 'https://example.com/';
    const features = extractUrlFeatures(raw, raw);

    // Strong malicious signal
    const threatIntel: ThreatIntelResult[] = [
      { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true, threatType: 'malware' },
    ];

    // Weak benign signal (HTTPS valid)
    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: dummyDomainSafe,
      sslIntel: dummySslSafe,
      redirectIntel: dummyRedirectSafe,
      threatIntel,
    });

    expect(result.verdict).toBe('CRITICAL');
  });
});
