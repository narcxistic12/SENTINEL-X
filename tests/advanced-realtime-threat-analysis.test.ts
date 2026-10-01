import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CloudflareUrlScannerProvider } from '../lib/detection/providers/cloudflare-url-scanner';
import { UrlscansProvider } from '../lib/detection/providers/urlscans';
import { VirusTotalFreshProvider } from '../lib/detection/providers/virustotal-fresh';
import { EvidenceAggregator } from '../lib/detection/evidence-aggregator';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';
import { validateUrlSsrf } from '../lib/security/ssrf';
import { detectBrandImpersonation } from '../lib/detection/brand-analyzer';
import {
  DomainIntelligence,
  SslIntelligence,
  RedirectIntelligence,
  DomainRegistrationIntelligence,
  ExternalAnalysisResult,
} from '../types/security';

describe('SENTINELX Advanced Real-Time Threat Analysis Test Suite', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

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
    domainAgeDays: 3,
    registrationDate: '2026-09-23',
    expirationDate: '2027-09-23',
    registrar: 'NameCheap',
    isNewlyRegistered: true,
    isYoungDomain: true,
    nameservers: ['ns1.dns.com'],
  };

  // A. All providers not configured
  it('A. Returns NOT_CONFIGURED status when provider API tokens are missing', async () => {
    delete process.env.CLOUDFLARE_ACCOUNT_ID;
    delete process.env.CLOUDFLARE_URLSCANNER_API_TOKEN;
    delete process.env.URLSCANS_API_KEY;
    delete process.env.VIRUSTOTAL_API_KEY;

    const cf = new CloudflareUrlScannerProvider();
    const us = new UrlscansProvider();
    const vtf = new VirusTotalFreshProvider();

    expect(cf.isConfigured()).toBe(false);
    expect(us.isConfigured()).toBe(false);
    expect(vtf.isConfigured()).toBe(false);

    const resCF = await cf.analyze('https://example.com');
    const resUS = await us.analyze('https://example.com');
    const resVTF = await vtf.analyze('https://example.com');

    expect(resCF.status).toBe('NOT_CONFIGURED');
    expect(resUS.status).toBe('NOT_CONFIGURED');
    expect(resVTF.status).toBe('NOT_CONFIGURED');
  });

  // B. Cloudflare CLEAN
  it('B. Cloudflare URL Scanner returns CLEAN for benign scans', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-456';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/v2/scan')) {
        return new Response(JSON.stringify({ result: { uuid: 'cf-scan-001' } }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          result: {
            verdicts: { malicious: false },
            page: { title: 'Clean Site', domain: 'example.com' },
          },
        }),
        { status: 200 }
      );
    });

    const cf = new CloudflareUrlScannerProvider();
    const res = await cf.analyze('https://example.com');
    expect(res.status).toBe('CLEAN');
    expect(res.isFlagged).toBe(false);
  });

  // C. Cloudflare FLAGGED
  it('C. Cloudflare URL Scanner returns FLAGGED for malicious verdicts', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-456';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/v2/scan')) {
        return new Response(JSON.stringify({ result: { uuid: 'cf-scan-999' } }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          result: {
            verdicts: { malicious: true, overall: 'malicious' },
            page: { title: 'Phishing', domain: 'bad.com' },
          },
        }),
        { status: 200 }
      );
    });

    const cf = new CloudflareUrlScannerProvider();
    const res = await cf.analyze('https://bad.com');
    expect(res.status).toBe('FLAGGED');
    expect(res.isFlagged).toBe(true);
  });

  // D. Cloudflare TIMEOUT
  it('D. Cloudflare handles fetch timeout gracefully', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-456';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      const err = new Error('Aborted');
      err.name = 'AbortError';
      throw err;
    });

    const cf = new CloudflareUrlScannerProvider();
    const res = await cf.analyze('https://example.com');
    expect(res.status).toBe('TIMEOUT');
  });

  // E. Cloudflare 429
  it('E. Cloudflare handles HTTP 429 rate limit correctly', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-456';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Rate limit exceeded', { status: 429 });
    });

    const cf = new CloudflareUrlScannerProvider();
    const res = await cf.analyze('https://example.com');
    expect(res.status).toBe('RATE_LIMITED');
  });

  // F. Cloudflare 401/403
  it('F. Cloudflare handles HTTP 401/403 authorization error safely', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-invalid';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Unauthorized', { status: 401 });
    });

    const cf = new CloudflareUrlScannerProvider();
    const res = await cf.analyze('https://example.com');
    expect(res.status).toBe('ERROR');
    expect(res.status).not.toBe('CLEAN');
  });

  // G. URLScans CLEAN
  it('G. URLScans returns CLEAN status when risk score is low', async () => {
    process.env.URLSCANS_API_KEY = 'urlscans-key-100';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response(JSON.stringify({ riskScore: 0, isPhishing: false, isMalware: false }), { status: 200 });
    });

    const us = new UrlscansProvider();
    const res = await us.analyze('https://example.com');
    expect(res.status).toBe('CLEAN');
  });

  // H. URLScans FLAGGED
  it('H. URLScans returns FLAGGED when phishing or malware is detected', async () => {
    process.env.URLSCANS_API_KEY = 'urlscans-key-100';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response(JSON.stringify({ riskScore: 90, isPhishing: true, categories: ['phishing'] }), { status: 200 });
    });

    const us = new UrlscansProvider();
    const res = await us.analyze('https://phishing-site.xyz');
    expect(res.status).toBe('FLAGGED');
    expect(res.isFlagged).toBe(true);
  });

  // I. URLScans ERROR
  it('I. URLScans handles HTTP 500 error safely', async () => {
    process.env.URLSCANS_API_KEY = 'urlscans-key-100';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Server Error', { status: 500 });
    });

    const us = new UrlscansProvider();
    const res = await us.analyze('https://example.com');
    expect(res.status).toBe('ERROR');
    expect(res.status).not.toBe('CLEAN');
  });

  // J. VirusTotal fresh scan
  it('J. VirusTotal Fresh Analysis submits new URL for analysis', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'vt-key-888';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/urls')) {
        return new Response(JSON.stringify({ data: { id: 'vt-analysis-001' } }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          data: {
            attributes: {
              status: 'completed',
              stats: { malicious: 15, suspicious: 2, harmless: 0, undetected: 50 },
            },
          },
        }),
        { status: 200 }
      );
    });

    const vtf = new VirusTotalFreshProvider();
    const res = await vtf.analyze('https://fresh-malicious.com');
    expect(res.status).toBe('FLAGGED');
    expect(res.isFlagged).toBe(true);
  });

  // K. VirusTotal re-analysis & caching
  it('K. VirusTotal Fresh Analysis reuses cached result for same URL', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'vt-key-888';

    let fetchCount = 0;
    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      fetchCount++;
      const urlStr = String(url);
      if (urlStr.endsWith('/urls')) {
        return new Response(JSON.stringify({ data: { id: `vt-analysis-${fetchCount}` } }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          data: {
            attributes: {
              status: 'completed',
              stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 0 },
            },
          },
        }),
        { status: 200 }
      );
    });

    const vtf = new VirusTotalFreshProvider();
    const url = 'https://cached-url-test.com';
    const res1 = await vtf.analyze(url);
    const initialFetchCount = fetchCount;

    const res2 = await vtf.analyze(url);
    expect(fetchCount).toBe(initialFetchCount); // Cache hit, no additional network request
    expect(res2.status).toBe('CLEAN');
  });

  // L. VirusTotal pending analysis
  it('L. VirusTotal Fresh Analysis returns PENDING when scan status is processing', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'vt-key-888';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/urls')) {
        return new Response(JSON.stringify({ data: { id: 'vt-analysis-pending' } }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          data: {
            attributes: {
              status: 'queued',
            },
          },
        }),
        { status: 200 }
      );
    });

    const vtf = new VirusTotalFreshProvider();
    const res = await vtf.analyze('https://pending-url.com');
    expect(res.status).toBe('PENDING');
    expect(res.isFlagged).toBe(false);
  });

  // M. VirusTotal 429
  it('M. VirusTotal Fresh Analysis handles HTTP 429 rate limit correctly', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'vt-key-888';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Quota Exceeded', { status: 429 });
    });

    const vtf = new VirusTotalFreshProvider();
    const res = await vtf.analyze('https://example.com');
    expect(res.status).toBe('RATE_LIMITED');
  });

  // N. Provider disagreement
  it('N. Handles provider disagreement: Cloudflare FLAGGED overrides PhishTank CLEAN', () => {
    const raw = 'https://disagreed-threat.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const cloudflareResult: ExternalAnalysisResult = {
      providerName: 'Cloudflare URL Scanner',
      status: 'FLAGGED',
      isFlagged: true,
      threatType: 'Phishing',
      evidence: [
        {
          source: 'Cloudflare URL Scanner',
          finding: 'Cloudflare URL Scanner reported page as malicious.',
          impact: 'HIGH_RISK',
          actual: true,
          category: 'THREAT_INTELLIGENCE',
        },
      ],
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
      cloudflareResult,
    });

    expect(res.verdict).toBe('CRITICAL');
    expect(res.explanation).toContain('Cloudflare URL Scanner');
  });

  // O. New phishing site with zero threat-intelligence matches
  it('O. New phishing URL with 0 threat intel matches produces HIGH/CRITICAL verdict from dynamic analysis', () => {
    const raw = 'https://paypa1-security-auth-2026.xyz/verify';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const cloudflareResult: ExternalAnalysisResult = {
      providerName: 'Cloudflare URL Scanner',
      status: 'FLAGGED',
      isFlagged: true,
      evidence: [],
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newDomainReg,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'URLhaus', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'CLEAN', isFlagged: false },
        { providerName: 'VirusTotal', status: 'CLEAN', isFlagged: false },
      ],
      cloudflareResult,
    });

    expect(res.verdict).toBe('CRITICAL');
  });

  // P. Brand impersonation + login page
  it('P. Brand impersonation combined with login page keywords elevates risk score', () => {
    const raw = 'https://paypal-security-auth-check.xyz/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newDomainReg,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(['HIGH_RISK', 'CRITICAL']).toContain(res.verdict);
  });

  // Q. Brand impersonation + cross-domain form
  it('Q. Brand impersonation + cross-domain form submission triggers HIGH_RISK correlation', () => {
    const raw = 'https://paypal-verify-secure.com/signin';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const urlscanResult: ExternalAnalysisResult = {
      providerName: 'URLscan',
      status: 'CLEAN',
      isFlagged: false,
      evidence: [],
      metadata: {
        crossDomainFormSubmission: true,
        formTargetDomain: 'evil-data-collector.com',
      },
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
      urlscanResult,
    });

    expect(res.riskScore).toBeGreaterThanOrEqual(60);
    expect(res.evidence.some((e) => e.category === 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION')).toBe(true);
  });

  // R. Legitimate Google login
  it('R. Legitimate Google login page (accounts.google.com) remains SAFE', () => {
    const raw = 'https://accounts.google.com/ServiceLogin?service=mail';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const brandCheck = detectBrandImpersonation(raw);

    expect(brandCheck.isOfficialDomainMatch).toBe(true);
    expect(brandCheck.detected).toBe(false);

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: { ...benignDomain, domain: 'google.com' },
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(res.verdict).toBe('SAFE');
    expect(res.riskScore).toBeLessThan(35);
  });

  // S. Legitimate Microsoft login
  it('S. Legitimate Microsoft login page (login.microsoftonline.com) remains SAFE', () => {
    const raw = 'https://login.microsoftonline.com/common/oauth2/authorize';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;
    const brandCheck = detectBrandImpersonation(raw);

    expect(brandCheck.isOfficialDomainMatch).toBe(true);
    expect(brandCheck.detected).toBe(false);

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: { ...benignDomain, domain: 'microsoftonline.com' },
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(['SAFE', 'LOW_RISK']).toContain(res.verdict);
  });

  // T. Legitimate GitHub login
  it('T. Legitimate GitHub login page (github.com/login) remains SAFE', () => {
    const raw = 'https://github.com/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: { ...benignDomain, domain: 'github.com' },
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(res.verdict).toBe('SAFE');
  });

  // U. Legitimate PayPal domain
  it('U. Legitimate PayPal domain (www.paypal.com) remains SAFE', () => {
    const raw = 'https://www.paypal.com/signin';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: { ...benignDomain, domain: 'paypal.com' },
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(res.verdict).toBe('SAFE');
  });

  // V. Redirect chain
  it('V. Redirect chain cross-domain hop contributes to risk score', () => {
    const raw = 'https://redirecter.com/goto';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const redirectIntel: RedirectIntelligence = {
      originalUrl: raw,
      finalUrl: 'https://final-dest.com/login',
      hopCount: 3,
      hops: [
        { hopNumber: 1, url: raw, statusCode: 302, targetUrl: 'https://intermediate.com', crossDomain: true, durationMs: 100 },
        { hopNumber: 2, url: 'https://intermediate.com', statusCode: 301, targetUrl: 'https://final-dest.com/login', crossDomain: true, durationMs: 100 },
      ],
      destinationChanged: true,
      loopDetected: false,
      ssrfBlocked: false,
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
    });

    expect(res.riskScore).toBeGreaterThan(0);
    expect(res.evidence.some((e) => e.category === 'REDIRECT')).toBe(true);
  });

  // W. SSRF blocked URL
  it('W. SSRF validation blocks internal loopback and private IP requests', async () => {
    const localhostResult = await validateUrlSsrf('http://127.0.0.1:8080/admin');
    const metadataResult = await validateUrlSsrf('http://169.254.169.254/latest/meta-data/');

    expect(localhostResult.isSafe).toBe(false);
    expect(metadataResult.isSafe).toBe(false);
  });

  // X. Private IP
  it('X. Private IPv4 addresses are rejected by SSRF guard', async () => {
    const privateIpResult = await validateUrlSsrf('http://192.168.1.100/status');
    expect(privateIpResult.isSafe).toBe(false);
  });

  // Y. Metadata IP
  it('Y. AWS/Cloud metadata IP address is rejected by SSRF guard', async () => {
    const metaResult = await validateUrlSsrf('http://169.254.169.254/');
    expect(metaResult.isSafe).toBe(false);
  });

  // Z. Sensitive URL query parameter privacy redaction
  it('Z. Cloudflare provider redacts sensitive query parameters prior to external submission', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-456';

    let submittedUrl = '';
    vi.spyOn(global, 'fetch').mockImplementation(async (url: any, init?: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/v2/scan') && init?.body) {
        const body = JSON.parse(init.body);
        submittedUrl = body.url;
        return new Response(JSON.stringify({ result: { uuid: 'cf-redact-01' } }), { status: 200 });
      }
      return new Response(JSON.stringify({ result: { verdicts: { malicious: false } } }), { status: 200 });
    });

    const cf = new CloudflareUrlScannerProvider();
    await cf.analyze('https://example.com/login?user=john&password=SecretPassword123&token=abc123xyz');

    expect(submittedUrl).toContain('password=[REDACTED]');
    expect(submittedUrl).toContain('token=[REDACTED]');
    expect(submittedUrl).not.toContain('SecretPassword123');
  });

  // AA. Evidence deduplication
  it('AA. EvidenceAggregator deduplicates identical evidence from same provider/finding', () => {
    const aggregator = new EvidenceAggregator();

    aggregator.addEvidence([
      { source: 'PhishTank', finding: 'Blacklisted threat', impact: 'HIGH_RISK', actual: true, category: 'THREAT_INTELLIGENCE' },
      { source: 'PhishTank', finding: 'Blacklisted threat', impact: 'HIGH_RISK', actual: true, category: 'THREAT_INTELLIGENCE' },
      { source: 'URLhaus', finding: 'Blacklisted threat', impact: 'HIGH_RISK', actual: true, category: 'THREAT_INTELLIGENCE' },
    ]);

    const items = aggregator.getEvidence();
    expect(items.length).toBe(2); // PhishTank deduplicated, URLhaus distinct
  });

  // AB. Confidence calculation
  it('AB. Risk and confidence scores remain separate and dynamic', () => {
    const raw = 'https://example.com/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'URLhaus', status: 'CLEAN', isFlagged: false },
      ],
    });

    expect(res.riskScore).toBe(0);
    expect(res.confidenceScore).toBe(85); // Dynamic calculation, not hardcoded 60% or 90%
  });

  // AC. Explanation correctness
  it('AC. Explanation engine describes actual threat reasons and does not blame clean providers', () => {
    const raw = 'https://paypa1-verify-account.com/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const cloudflareResult: ExternalAnalysisResult = {
      providerName: 'Cloudflare URL Scanner',
      status: 'FLAGGED',
      isFlagged: true,
      evidence: [],
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newDomainReg,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
      cloudflareResult,
    });

    expect(res.explanation).toContain('Cloudflare URL Scanner');
    expect(res.summary).not.toContain('No threat intelligence matches were reported by PhishTank');
  });

  // AD. Provider failure must never become CLEAN
  it('AD. Provider error or timeout status must never be converted to CLEAN', async () => {
    process.env.CLOUDFLARE_ACCOUNT_ID = 'cf-acc-123';
    process.env.CLOUDFLARE_URLSCANNER_API_TOKEN = 'cf-token-456';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Service Unavailable', { status: 503 });
    });

    const cf = new CloudflareUrlScannerProvider();
    const res = await cf.analyze('https://example.com');

    expect(res.status).toBe('ERROR');
    expect(res.status).not.toBe('CLEAN');
    expect(res.isFlagged).toBe(false);
  });
});
