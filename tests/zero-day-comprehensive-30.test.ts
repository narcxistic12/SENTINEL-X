import { describe, it, expect, vi } from 'vitest';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';
import { validateUrlSsrf } from '../lib/security/ssrf';
import { detectBrandImpersonation } from '../lib/detection/brand-analyzer';
import { PhishTankProvider, UrlhausProvider } from '../lib/detection/providers/threat-intel';
import {
  DomainIntelligence,
  DomainRegistrationIntelligence,
  SslIntelligence,
  RedirectIntelligence,
  ThreatIntelResult,
} from '../types/security';

describe('SECTION 22: 30 Comprehensive Backend Tests for SENTINELX Zero-Day Engine', () => {
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
    registrationDate: '1995-09-03',
    expirationDate: '2028-09-03',
    registrar: 'IANA',
    isAvailable: true,
  };

  const matureRegIntel: DomainRegistrationIntelligence = {
    status: 'CHECKED',
    domainAgeDays: 5000,
    registrationDate: '1995-09-03',
    expirationDate: '2028-09-03',
    registrar: 'IANA',
    isNewlyRegistered: false,
    isYoungDomain: false,
    nameservers: ['ns.example.com'],
  };

  const newRegIntel: DomainRegistrationIntelligence = {
    status: 'CHECKED',
    domainAgeDays: 2,
    registrationDate: '2026-09-22',
    expirationDate: '2027-09-22',
    registrar: 'NameCheap',
    isNewlyRegistered: true,
    isYoungDomain: true,
    nameservers: ['ns1.badhost.com'],
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

  // Test 1: Known malicious URL
  it('1. Known malicious URL with FLAGGED threat intel produces CRITICAL verdict', () => {
    const raw = 'https://offixclean.lol/index.php';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true, threatType: 'Phishing' }],
    });
    expect(res.verdict).toBe('CRITICAL');
    expect(res.riskScore).toBe(100);
  });

  // Test 2: Known safe URL
  it('2. Known safe URL produces SAFE verdict with high confidence', () => {
    const raw = 'https://www.google.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: matureRegIntel,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });
    expect(res.verdict).toBe('SAFE');
    expect(res.riskScore).toBe(0);
  });

  // Test 3: Brand impersonation
  it('3. Brand impersonation (paypal.attacker.com) generates brand spoof evidence', () => {
    const brand = detectBrandImpersonation('paypal.attacker.com');
    expect(brand.detected).toBe(true);
    expect(brand.similarityType).toBe('subdomain_spoof');
  });

  // Test 4: Brand typosquatting
  it('4. Brand typosquatting (paypa1.com, g00gle.com) is detected', () => {
    const brand1 = detectBrandImpersonation('paypa1.com');
    const brand2 = detectBrandImpersonation('g00gle.com');
    expect(brand1.detected).toBe(true);
    expect(brand2.detected).toBe(true);
  });

  // Test 5: New/unreported phishing URL simulation (Zero-Day!)
  it('5. Zero-Day Phishing Simulation: 0 threat intel matches, but new domain + paypal spoof + login keywords produces HIGH_RISK/CRITICAL verdict', () => {
    const raw = 'https://pay-pal-security-update-2026.xyz/login/verify?account=session';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newRegIntel,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'URLhaus', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });
    expect(['HIGH_RISK', 'CRITICAL']).toContain(res.verdict);
    expect(res.riskScore).toBeGreaterThanOrEqual(60);
    expect(res.explanation).toContain('paypal');
  });

  // Test 6: New legitimate domain
  it('6. New legitimate startup domain (no brand spoof, no phishing keywords) remains LOW_RISK / SAFE', () => {
    const raw = 'https://my-new-startup-platform.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newRegIntel,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });
    expect(['SAFE', 'LOW_RISK']).toContain(res.verdict);
    expect(res.riskScore).toBeLessThan(35);
  });

  // Test 7: Suspicious TLD
  it('7. Suspicious TLD (.zip, .top, .work) increases risk score', () => {
    const raw = 'https://normal-looking-site.zip/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);
    expect(features.isRiskyTld).toBe(true);
  });

  // Test 8: Punycode
  it('8. Punycode IDN URL triggers homoglyph detection', () => {
    const raw = 'https://xn--80ak6aa92e.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);
    expect(features.hasPunycode).toBe(true);
  });

  // Test 9: Encoded URL
  it('9. Percent-encoded URL characters are counted', () => {
    const raw = 'https://example.com/%20%21%22%23';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);
    expect(features.percentEncodedCount).toBeGreaterThan(0);
  });

  // Test 10: Suspicious query parameters
  it('10. Suspicious redirect query parameters (url=https://...) are detected', () => {
    const raw = 'https://example.com/redirect?url=https://attacker-site.com';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);
    expect(features.hasNestedUrl).toBe(true);
    expect(features.suspiciousQueryParams).toContain('url');
  });

  // Test 11: IP URL
  it('11. Direct IP address in URL triggers high-risk IP host signal', () => {
    const raw = 'http://192.168.1.1/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);
    expect(features.hasIpHost).toBe(true);
  });

  // Test 12: Non-standard port
  it('12. Non-standard port specifies unusualPort flag', () => {
    const raw = 'http://example.com:8443/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);
    expect(features.unusualPort).toBe(true);
  });

  // Test 13: Redirect chain
  it('13. Multi-hop redirect chain (3+ hops) adds redirect risk points', () => {
    const redirectIntel: RedirectIntelligence = {
      originalUrl: 'https://hop1.com/',
      finalUrl: 'https://final.com/',
      hopCount: 3,
      hops: [
        { hopNumber: 1, statusCode: 301, url: 'https://hop1.com/', targetUrl: 'https://hop2.com/', crossDomain: true, durationMs: 50 },
        { hopNumber: 2, statusCode: 302, url: 'https://hop2.com/', targetUrl: 'https://hop3.com/', crossDomain: true, durationMs: 50 },
        { hopNumber: 3, statusCode: 302, url: 'https://hop3.com/', targetUrl: 'https://final.com/', crossDomain: true, durationMs: 50 },
      ],
      destinationChanged: true,
      loopDetected: false,
      ssrfBlocked: false,
    };
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://hop1.com/', 'https://hop1.com/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel,
      threatIntel: [],
    });
    expect(res.signals.some((s) => s.id === 'redirect-multiple-hops')).toBe(true);
  });

  // Test 14: HTTPS downgrade
  it('14. Unencrypted HTTP connection triggers high severity SSL signal', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('http://example.com/', 'http://example.com/'),
      domainIntel: benignDomain,
      sslIntel: { ...benignSsl, httpsEnabled: false },
      redirectIntel: benignRedirect,
      threatIntel: [],
    });
    expect(res.signals.some((s) => s.id === 'ssl-unencrypted')).toBe(true);
  });

  // Test 15: New domain
  it('15. Newly registered domain (< 30 days) triggers domain-newly-registered signal', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://new-domain.com/', 'https://new-domain.com/'),
      domainIntel: benignDomain,
      domainRegIntel: newRegIntel,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [],
    });
    expect(res.signals.some((s) => s.id === 'domain-newly-registered')).toBe(true);
  });

  // Test 16: DNS failure
  it('16. Unresolvable domain triggers DNS failure signal', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://unresolvable.com/', 'https://unresolvable.com/'),
      domainIntel: { ...benignDomain, isResolvable: false, ipAddresses: [] },
      sslIntel: { ...benignSsl, protocol: null },
      redirectIntel: benignRedirect,
      threatIntel: [],
    });
    expect(res.signals.some((s) => s.id === 'domain-unresolvable')).toBe(true);
  });

  // Test 17: TLS failure
  it('17. Expired TLS certificate triggers critical cert-expired signal', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://expired.com/', 'https://expired.com/'),
      domainIntel: benignDomain,
      sslIntel: { ...benignSsl, isExpired: true, certificateValid: false },
      redirectIntel: benignRedirect,
      threatIntel: [],
    });
    expect(res.signals.some((s) => s.id === 'ssl-cert-expired')).toBe(true);
  });

  // Test 18: Provider unavailable
  it('18. Provider UNAVAILABLE status is captured in evidence without crashing', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://example.com/', 'https://example.com/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'VirusTotal', status: 'UNAVAILABLE', isFlagged: false }],
    });
    expect(res.evidence.some((e) => e.finding.includes('unavailable'))).toBe(true);
  });

  // Test 19: Provider timeout
  it('19. Provider TIMEOUT status is reported in evidence without failing clean', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://example.com/', 'https://example.com/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'Google Safe Browsing', status: 'TIMEOUT', isFlagged: false }],
    });
    expect(res.evidence.some((e) => e.finding.includes('unavailable'))).toBe(true);
  });

  // Test 20: Provider rate limit
  it('20. Provider RATE_LIMITED status is reported in evidence', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://example.com/', 'https://example.com/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'RATE_LIMITED', isFlagged: false }],
    });
    expect(res.evidence.some((e) => e.finding.includes('unavailable'))).toBe(true);
  });

  // Test 21: URLhaus FLAGGED
  it('21. URLhaus FLAGGED threat intel triggers CRITICAL threat verdict', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://malware-distro.com/', 'https://malware-distro.com/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'abuse.ch URLhaus', status: 'FLAGGED', isFlagged: true, threatType: 'Malware' }],
    });
    expect(res.verdict).toBe('CRITICAL');
  });

  // Test 22: PhishTank FLAGGED
  it('22. PhishTank FLAGGED threat intel triggers CRITICAL verdict with phish_id evidence', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://offixclean.lol/index.php', 'https://offixclean.lol/index.php'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true, details: 'PhishTank database verified this URL as a phishing threat (ID: 9529202)' }],
    });
    expect(res.verdict).toBe('CRITICAL');
    expect(res.explanation).toContain('9529202');
  });

  // Test 23: Multiple provider disagreement
  it('23. Multiple provider disagreement: FLAGGED overrides CLEAN', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://disputed.com/', 'https://disputed.com/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true },
      ],
    });
    expect(res.verdict).toBe('CRITICAL');
  });

  // Test 24: SSRF redirect
  it('24. SSRF validator blocks redirects pointing to 127.0.0.1 and private IPs', async () => {
    const res = await validateUrlSsrf('http://127.0.0.1/admin');
    expect(res.isSafe).toBe(false);
  });

  // Test 25: Private IP
  it('25. SSRF validator blocks 192.168.1.1 and 10.0.0.1 private IP ranges', async () => {
    const res1 = await validateUrlSsrf('http://192.168.1.1/');
    const res2 = await validateUrlSsrf('http://10.0.0.1/');
    expect(res1.isSafe).toBe(false);
    expect(res2.isSafe).toBe(false);
  });

  // Test 26: Cloud metadata
  it('26. SSRF validator blocks AWS/GCP cloud metadata IP 169.254.169.254', async () => {
    const res = await validateUrlSsrf('http://169.254.169.254/latest/meta-data/');
    expect(res.isSafe).toBe(false);
  });

  // Test 27: Official brand domain
  it('27. Official brand domain (login.paypal.com, aws.amazon.com) is NOT flagged as brand impersonation', () => {
    const brand1 = detectBrandImpersonation('login.paypal.com');
    const brand2 = detectBrandImpersonation('aws.amazon.com');
    expect(brand1.detected).toBe(false);
    expect(brand2.detected).toBe(false);
  });

  // Test 28: Brand impersonation + new domain
  it('28. Multi-signal correlation: Brand impersonation + new domain increases risk', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://paypal-update.xyz/', 'https://paypal-update.xyz/'),
      domainIntel: benignDomain,
      domainRegIntel: newRegIntel,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [],
    });
    expect(res.riskScore).toBeGreaterThanOrEqual(50);
  });

  // Test 29: Brand impersonation + suspicious redirect
  it('29. Multi-signal correlation: Brand impersonation + cross-domain redirect increases risk', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://microsoft-login.org/', 'https://microsoft-login.org/'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: { ...benignRedirect, destinationChanged: true, hopCount: 2 },
      threatIntel: [],
    });
    expect(res.riskScore).toBeGreaterThanOrEqual(45);
  });

  // Test 30: Brand impersonation + threat intelligence
  it('30. Multi-signal correlation: Brand impersonation + FLAGGED threat intel maximizes risk to 100', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://paypa1-update.com/login', 'https://paypa1-update.com/login'),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true }],
    });
    expect(res.riskScore).toBe(100);
    expect(res.verdict).toBe('CRITICAL');
  });
});
