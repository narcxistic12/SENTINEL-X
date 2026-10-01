import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';
import {
  DomainIntelligence,
  SslIntelligence,
  RedirectIntelligence,
  DomainRegistrationIntelligence,
} from '../types/security';

describe('SENTINELX Final Explanation & Evidence Consistency Audit', () => {
  const benignDomain: DomainIntelligence = {
    domain: 'example.com',
    tld: 'com',
    isResolvable: true,
    ipAddresses: ['93.184.216.34'],
    ipv6Addresses: [],
    mxRecords: [{ exchange: 'mail.example.com', priority: 10 }],
    txtRecords: [],
    nsRecords: ['ns.example.com'],
    hasMx: true,
    domainAgeEstimateDays: 5000,
    registrationDate: '2010-01-01',
    expirationDate: '2030-01-01',
    registrar: 'Example Registrar',
    isAvailable: true,
  };

  const benignSsl: SslIntelligence = {
    httpsEnabled: true,
    certificateValid: true,
    hostnameMatches: true,
    issuer: 'DigiCert',
    subject: 'example.com',
    validFrom: '2024-01-01',
    validTo: '2025-01-01',
    daysUntilExpiration: 200,
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    isSelfSigned: false,
    isExpired: false,
    disclaimer: 'test',
  };

  const benignRedirect: RedirectIntelligence = {
    originalUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    hopCount: 0,
    hops: [],
    destinationChanged: false,
    loopDetected: false,
    ssrfBlocked: false,
  };

  const newDomainReg: DomainRegistrationIntelligence = {
    status: 'CHECKED',
    domainAgeDays: 5,
    registrationDate: '2026-09-21',
    expirationDate: '2027-09-21',
    registrar: 'NameCheap',
    isNewlyRegistered: true,
    isYoungDomain: true,
    nameservers: ['ns1.dns.com'],
  };

  // Case 1: Known malicious URL with threat-intelligence FLAGGED result.
  it('1. Known malicious URL with threat-intelligence FLAGGED result mentions actual provider in explanation', () => {
    const raw = 'https://offixclean.lol/index.php';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        {
          providerName: 'VirusTotal',
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Phishing',
          stats: { maliciousEngineCount: 18, totalEngineCount: 70 },
        },
      ],
    });

    expect(res.verdict).toBe('CRITICAL');
    expect(res.explanation).toContain('VirusTotal (18/70 engines flagged)');
    expect(res.summary).toContain('VirusTotal');
  });

  // Case 2: New phishing-style URL with zero threat-intelligence matches.
  it('2. New phishing-style URL with zero threat-intel matches mentions heuristic evidence (brand, new domain, keywords)', () => {
    const raw = 'https://paypa1-verify-account-security.com/login/session';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newDomainReg,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'URLhaus', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(['HIGH_RISK', 'CRITICAL']).toContain(res.verdict);
    expect(res.explanation).toContain('paypa1');
    expect(res.explanation).toContain('credential-related keywords');
    expect(res.explanation).toContain('newly registered');
    expect(res.summary).not.toContain('No threat intelligence matches were reported by PhishTank');
  });

  // Case 3: Safe official domain.
  it('3. Safe official domain describes actual positive evidence', () => {
    const raw = 'https://example.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(res.verdict).toBe('SAFE');
    expect(res.explanation).toContain('DNS resolution succeeded');
    expect(res.explanation).toContain('TLS certificate is valid');
    expect(res.explanation).toContain('No threat intelligence matches were reported by PhishTank');
    expect(res.summary).toContain('SAFE: DNS and TLS infrastructure verified');
  });

  // Case 4: High-risk IP URL with no threat-intelligence match.
  it('4. High-risk IP URL with no threat-intel match does NOT claim PhishTank caused the risk', () => {
    const raw = 'http://192.168.1.1:8080/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: { ...benignDomain, isResolvable: true, ipAddresses: ['192.168.1.1'] },
      sslIntel: { ...benignSsl, httpsEnabled: false },
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(['HIGH_RISK', 'CRITICAL']).toContain(res.verdict);
    expect(res.explanation).toContain('raw IP address');
    expect(res.summary).not.toContain('PhishTank');
    expect(res.summary).toContain('raw IP address');
  });

  // Case 5: PhishTank CLEAN + URLhaus FLAGGED.
  it('5. PhishTank CLEAN + URLhaus FLAGGED prioritizes URLhaus FLAGGED threat evidence', () => {
    const raw = 'https://malicious-site-example.com/payload.exe';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'URLhaus', status: 'FLAGGED', isFlagged: true, threatType: 'Malware host' },
      ],
    });

    expect(res.verdict).toBe('CRITICAL');
    expect(res.explanation).toContain('URLhaus');
    expect(res.explanation).toContain('blacklisted');
    expect(res.summary).toContain('URLhaus');
  });

  // Case 6: All providers unavailable but strong local evidence exists.
  it('6. All providers unavailable but strong local evidence exists describes local evidence and states limited coverage', () => {
    const raw = 'https://g00gle-login-verify.com/auth';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newDomainReg,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'VirusTotal', status: 'UNAVAILABLE', isFlagged: false },
      ],
    });

    expect(['HIGH_RISK', 'CRITICAL']).toContain(res.verdict);
    expect(res.explanation).toContain('g00gle');
    expect(res.explanation).toContain('Threat intelligence coverage was limited');
    expect(res.explanation).toContain('were not configured for this server deployment');
  });
});
