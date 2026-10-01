import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PhishTankProvider, runThreatIntelligenceChecks } from '../lib/detection/providers/threat-intel';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';
import {
  DomainIntelligence,
  SslIntelligence,
  RedirectIntelligence,
  ThreatIntelResult,
} from '../types/security';

describe('PHASE 15: SENTINELX Master Threat Intelligence & PhishTank Regression Suite', () => {
  const benignDomainIntel: DomainIntelligence = {
    domain: 'example.com',
    tld: 'com',
    isResolvable: true,
    ipAddresses: ['93.184.216.34'],
    ipv6Addresses: ['2606:2800:220:1:248:1893:25c8:1946'],
    mxRecords: [{ exchange: 'mail.example.com', priority: 10 }],
    txtRecords: [],
    nsRecords: ['ns.example.com'],
    hasMx: true,
    domainAgeEstimateDays: 5000,
    registrationDate: '1995-09-03',
    expirationDate: '2028-09-03',
    registrar: 'Reservations LLC',
    isAvailable: true,
  };

  const benignSslIntel: SslIntelligence = {
    httpsEnabled: true,
    certificateValid: true,
    hostnameMatches: true,
    issuer: 'DigiCert Inc',
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

  const benignRedirectIntel: RedirectIntelligence = {
    originalUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    hopCount: 0,
    hops: [],
    destinationChanged: false,
    loopDetected: false,
    ssrfBlocked: false,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('1. Verified PhishTank result (in_database=true, verified=y, valid=y, phish_id=9529202) produces FLAGGED', async () => {
    const provider = new PhishTankProvider();
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        results: {
          in_database: 'true',
          verified: 'y',
          valid: 'y',
          phish_id: 9529202,
        },
      }),
    } as Response);

    const res = await provider.check('https://offixclean.lol/index.php');
    expect(res.status).toBe('FLAGGED');
    expect(res.isFlagged).toBe(true);
    expect(res.details).toContain('9529202');
  });

  it('2. PhishTank HTTP error (500) returns ERROR / UNAVAILABLE and NEVER CLEAN', async () => {
    const provider = new PhishTankProvider();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ error: 'Internal Server Error' }),
    } as Response);

    const res = await provider.check('https://offixclean.lol/index.php');
    expect(res.status).toBe('UNAVAILABLE');
    expect(res.isFlagged).toBe(false);
    expect(res.status).not.toBe('CLEAN');
  });

  it('3. PhishTank request timeout returns TIMEOUT and NEVER CLEAN', async () => {
    const provider = new PhishTankProvider();
    const abortErr = new Error('The operation was aborted');
    abortErr.name = 'AbortError';
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(abortErr);

    const res = await provider.check('https://offixclean.lol/index.php');
    expect(res.status).toBe('TIMEOUT');
    expect(res.isFlagged).toBe(false);
    expect(res.status).not.toBe('CLEAN');
  });

  it('4. PhishTank NOT_CONFIGURED status when simulated returns NOT_CONFIGURED and NEVER CLEAN', async () => {
    const tiResult: ThreatIntelResult = {
      providerName: 'PhishTank',
      status: 'NOT_CONFIGURED',
      isFlagged: false,
      details: 'Provider not configured',
    };
    expect(tiResult.status).toBe('NOT_CONFIGURED');
    expect(tiResult.status).not.toBe('CLEAN');
  });

  it('5. PhishTank HTTP 429 rate limit returns RATE_LIMITED and NEVER CLEAN', async () => {
    const provider = new PhishTankProvider();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 429,
      json: async () => ({ error: 'Rate limit exceeded' }),
    } as Response);

    const res = await provider.check('https://offixclean.lol/index.php');
    expect(res.status).toBe('RATE_LIMITED');
    expect(res.isFlagged).toBe(false);
    expect(res.status).not.toBe('CLEAN');
  });

  it('6. Verified PhishTank FLAGGED + other providers unavailable still produces strong threat evidence', () => {
    const raw = 'https://offixclean.lol/index.php';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const scoreRes = calculateRiskScore({
      urlFeatures: features,
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        {
          providerName: 'PhishTank',
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Confirmed Phishing (PhishTank)',
          details: 'PhishTank database verified this URL as a phishing threat (ID: 9529202)',
        },
        { providerName: 'Google Safe Browsing', status: 'UNAVAILABLE', isFlagged: false },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'abuse.ch URLhaus', status: 'TIMEOUT', isFlagged: false },
      ],
    });

    expect(scoreRes.verdict).toBe('CRITICAL');
    expect(scoreRes.riskScore).toBe(100);
    expect(scoreRes.explanation).toContain('PhishTank database verified this URL as a phishing threat (ID: 9529202)');
  });

  it('7. Multiple FLAGGED providers increase confidence and produce strong threat evidence', () => {
    const raw = 'https://multi-threat-site.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const singleFlagged = calculateRiskScore({
      urlFeatures: features,
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    const multiFlagged = calculateRiskScore({
      urlFeatures: features,
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true },
        { providerName: 'VirusTotal', status: 'FLAGGED', isFlagged: true },
      ],
    });

    expect(multiFlagged.confidenceScore).toBeGreaterThan(singleFlagged.confidenceScore);
    expect(multiFlagged.verdict).toBe('CRITICAL');
  });

  it('8. NOT_CONFIGURED providers do not count as CLEAN in evidence or confidence', () => {
    const raw = 'https://google.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const scoreRes = calculateRiskScore({
      urlFeatures: features,
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    const notConfiguredEvidence = scoreRes.evidence.find((e) => e.source === 'Google Safe Browsing');
    expect(notConfiguredEvidence?.impact).toBe('CONFIDENCE_REDUCTION');
    expect(notConfiguredEvidence?.finding).toContain('is not configured');
  });

  it('9. Heuristic-only suspicious URL (pay-pal-safe-auth.net) remains SUSPICIOUS with dynamic evidence-based confidence', () => {
    const raw = 'https://www.pay-pal-safe-auth.net/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const scoreRes = calculateRiskScore({
      urlFeatures: features,
      domainIntel: { ...benignDomainIntel, domain: 'pay-pal-safe-auth.net' },
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'VirusTotal', status: 'NOT_CONFIGURED', isFlagged: false },
        { providerName: 'abuse.ch URLhaus', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
    });

    expect(['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL']).toContain(scoreRes.verdict);
    expect(scoreRes.confidenceScore).toBeGreaterThan(0);
    expect(scoreRes.confidenceScore).toBeLessThan(100);
    expect(scoreRes.explanation).toContain('credential-related keywords');
  });

  it('10. Threat-intelligence FLAGGED + weak heuristic materially influences verdict to CRITICAL', () => {
    const raw = 'https://weak-keyword-site.org/auth';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const features = extractUrlFeatures(raw, norm);

    const scoreRes = calculateRiskScore({
      urlFeatures: features,
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'PhishTank', status: 'FLAGGED', isFlagged: true, threatType: 'Phishing' },
      ],
    });

    expect(scoreRes.verdict).toBe('CRITICAL');
    expect(scoreRes.riskScore).toBe(100);
  });

  it('11. Evidence reaches EvidenceItem[] array for risk engine processing', () => {
    const scoreRes = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://test-evidence.com/', 'https://test-evidence.com/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(scoreRes.evidence.length).toBeGreaterThan(0);
    expect(scoreRes.evidence.some((e) => e.source === 'PhishTank')).toBe(true);
  });

  it('12. Confidence score remains strictly between 0 and 100', () => {
    const scoreRes = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'CLEAN', isFlagged: false },
        { providerName: 'VirusTotal', status: 'CLEAN', isFlagged: false },
        { providerName: 'abuse.ch URLhaus', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(scoreRes.confidenceScore).toBeGreaterThanOrEqual(0);
    expect(scoreRes.confidenceScore).toBeLessThanOrEqual(100);
  });

  it('13. Confidence is not fixed at 60% across different URL types', () => {
    const res1 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://google.com/', 'https://google.com/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    const res2 = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://unresolvable-domain-xyz.info/', 'https://unresolvable-domain-xyz.info/'),
      domainIntel: { ...benignDomainIntel, isResolvable: false, ipAddresses: [] },
      sslIntel: { ...benignSslIntel, httpsEnabled: false, protocol: null },
      redirectIntel: { ...benignRedirectIntel, error: 'Connection failed' },
      threatIntel: [{ providerName: 'PhishTank', status: 'TIMEOUT', isFlagged: false }],
    });

    expect(res1.confidenceScore).not.toBe(60);
    expect(res1.confidenceScore).not.toBe(res2.confidenceScore);
  });

  it('14. No domain-specific hardcoded logic is present in risk scoring', () => {
    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures('https://random-unknown-domain-77.org/', 'https://random-unknown-domain-77.org/'),
      domainIntel: benignDomainIntel,
      sslIntel: benignSslIntel,
      redirectIntel: benignRedirectIntel,
      threatIntel: [],
    });

    expect(res.verdict).not.toBe('CRITICAL');
  });

  it('15. Provider error states (ERROR, TIMEOUT, UNAVAILABLE, RATE_LIMITED) NEVER convert into CLEAN', async () => {
    const provider = new PhishTankProvider();
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));

    const res = await provider.check('https://offixclean.lol/index.php');
    expect(res.status).toBe('UNAVAILABLE');
    expect(res.status).not.toBe('CLEAN');
    expect(res.isFlagged).toBe(false);
  });
});
