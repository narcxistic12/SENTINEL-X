import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { DomainIntelligence, SslIntelligence, RedirectIntelligence } from '../types/security';

describe('Risk Scoring Engine', () => {
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

  it('assigns SAFE / LOW_RISK verdict to benign domains with valid SSL and DNS', () => {
    const raw = 'https://example.com/';
    const features = extractUrlFeatures(raw, raw);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: dummyDomainSafe,
      sslIntel: dummySslSafe,
      redirectIntel: dummyRedirectSafe,
      threatIntel: [{ providerName: 'Test', status: 'CLEAN', isFlagged: false }],
    });

    expect(result.riskScore).toBeLessThanOrEqual(25);
    expect(result.verdict === 'SAFE' || result.verdict === 'LOW_RISK').toBe(true);
    expect(result.confidenceScore).toBeGreaterThanOrEqual(60);
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it('assigns HIGH_RISK or CRITICAL to lookalike domains with multiple phishing signals', () => {
    const raw = 'http://198.51.100.25/login/banking/verify-account?token=123';
    const features = extractUrlFeatures(raw, raw);

    const unencryptedSsl: SslIntelligence = {
      ...dummySslSafe,
      httpsEnabled: false,
      certificateValid: false,
      hostnameMatches: false,
    };

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...dummyDomainSafe, hasMx: false },
      sslIntel: unencryptedSsl,
      redirectIntel: dummyRedirectSafe,
      threatIntel: [],
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(50);
    expect(['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL']).toContain(result.verdict);
    expect(result.signals.some((s) => s.id === 'url-ip-host')).toBe(true);
    expect(result.signals.some((s) => s.id === 'url-suspicious-keywords')).toBe(true);
  });

  it('elevates risk to Critical immediately if flagged in threat intelligence feeds', () => {
    const raw = 'https://suspicious-target.com/';
    const features = extractUrlFeatures(raw, raw);

    const result = calculateRiskScore({
      urlFeatures: features,
      domainIntel: dummyDomainSafe,
      sslIntel: dummySslSafe,
      redirectIntel: dummyRedirectSafe,
      threatIntel: [
        {
          providerName: 'abuse.ch URLhaus',
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Malware Distribution Site',
          details: 'Active malicious payload host',
        },
      ],
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.verdict).toBe('CRITICAL');
  });
});
