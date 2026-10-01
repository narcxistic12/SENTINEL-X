import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { URLScanProvider } from '../lib/detection/providers/urlscan';
import { AnyRunProvider } from '../lib/detection/providers/anyrun';
import { calculateRiskScore } from '../lib/scoring/risk-engine';
import { extractUrlFeatures } from '../lib/detection/url-features';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';
import {
  DomainIntelligence,
  SslIntelligence,
  RedirectIntelligence,
  DomainRegistrationIntelligence,
  ExternalAnalysisResult,
} from '../types/security';

describe('SENTINELX Real Web Threat Analysis Integration (URLscan.io & ANY.RUN)', () => {
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
    domainAgeDays: 4,
    registrationDate: '2026-09-22',
    expirationDate: '2027-09-22',
    registrar: 'NameCheap',
    isNewlyRegistered: true,
    isYoungDomain: true,
    nameservers: ['ns1.dns.com'],
  };

  // Test 1: URLScan not configured
  it('1. URLScan returns NOT_CONFIGURED status when URLSCAN_API_KEY is absent', async () => {
    delete process.env.URLSCAN_API_KEY;
    const provider = new URLScanProvider();
    expect(provider.isConfigured()).toBe(false);

    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('NOT_CONFIGURED');
    expect(result.isFlagged).toBe(false);
  });

  // Test 2: URLScan submission success
  it('2. URLScan successfully submits URL and receives UUID', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(
          JSON.stringify({
            message: 'Submission successful',
            uuid: 'test-uuid-001',
            result: 'https://urlscan.io/result/test-uuid-001/',
            api: 'https://urlscan.io/api/v1/result/test-uuid-001/',
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ page: { domain: 'example.com', title: 'Example Domain' }, verdicts: { overall: { score: 0 } } }), { status: 200 });
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.scanUuid).toBe('test-uuid-001');
  });

  // Test 3: URLScan pending
  it('3. URLScan returns PENDING when scan result remains unready after polling', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'pending-uuid-99' }), { status: 200 });
      }
      return new Response(JSON.stringify({ message: 'Scan is not finished yet' }), { status: 404 });
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('PENDING');
    expect(result.isFlagged).toBe(false);
    expect(result.scanUuid).toBe('pending-uuid-99');
  });

  // Test 4: URLScan completed
  it('4. URLScan returns completed result details after successful poll', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'complete-uuid-77' }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          task: { uuid: 'complete-uuid-77' },
          page: { domain: 'example.com', title: 'Home Page' },
          verdicts: { overall: { score: 0, malicious: false } },
        }),
        { status: 200 }
      );
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('CLEAN');
    expect(result.metadata?.pageTitle).toBe('Home Page');
  });

  // Test 5: URLScan timeout
  it('5. URLScan handles fetch timeout gracefully', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      throw err;
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('TIMEOUT');
  });

  // Test 6: URLScan HTTP 429
  it('6. URLScan handles HTTP 429 rate limit correctly', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Rate limit exceeded', { status: 429 });
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('RATE_LIMITED');
  });

  // Test 7: URLScan HTTP error
  it('7. URLScan handles HTTP 500 error gracefully', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Internal Server Error', { status: 500 });
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('ERROR');
  });

  // Test 8: URLScan malformed response
  it('8. URLScan handles malformed JSON submission response safely', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('{ invalid json', { status: 200 });
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('ERROR');
  });

  // Test 9: URLScan phishing verdict
  it('9. URLScan extracts FLAGGED status when overall verdict is malicious', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'phish-uuid-100' }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          page: { domain: 'paypa1-fake.com', title: 'PayPal Verification' },
          verdicts: { overall: { score: 100, malicious: true, tags: ['phishing'] } },
        }),
        { status: 200 }
      );
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://paypa1-fake.com');
    expect(result.status).toBe('FLAGGED');
    expect(result.isFlagged).toBe(true);
    expect(result.evidence.some((e) => e.finding.includes('urlscan.io explicit threat detection'))).toBe(true);
  });

  // Test 10: URLScan clean result
  it('10. URLScan returns CLEAN status when scan verdict is benign', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'clean-uuid-200' }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          page: { domain: 'wikipedia.org', title: 'Wikipedia' },
          verdicts: { overall: { score: 0, malicious: false, tags: [] } },
        }),
        { status: 200 }
      );
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://wikipedia.org');
    expect(result.status).toBe('CLEAN');
    expect(result.isFlagged).toBe(false);
  });

  // Test 11: URLScan page with password form
  it('11. URLScan DOM snapshot detects password input field', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'pass-uuid-300' }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          page: { domain: 'my-login.com', title: 'Login Page' },
          verdicts: { overall: { score: 0 } },
          data: {
            dom: '<html><body><form><input type="text" name="user"><input type="password" name="pass"></form></body></html>',
          },
        }),
        { status: 200 }
      );
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://my-login.com');
    expect(result.metadata?.hasPasswordField).toBe(true);
    expect(result.evidence.some((e) => e.finding.includes('password input field'))).toBe(true);
  });

  // Test 12: URLScan cross-domain form
  it('12. URLScan detects cross-domain form target destination', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'form-uuid-400' }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          page: { domain: 'phishing.xyz', title: 'Verify Account' },
          verdicts: { overall: { score: 0 } },
          data: {
            dom: '<html><body><form action="https://data-collector.com/steal.php"><input type="password"></form></body></html>',
          },
        }),
        { status: 200 }
      );
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://phishing.xyz');
    expect(result.metadata?.crossDomainFormSubmission).toBe(true);
    expect(result.metadata?.formTargetDomain).toBe('data-collector.com');
    expect(result.evidence.some((e) => e.finding.includes('Cross-domain credential form submission'))).toBe(true);
  });

  // Test 13: URLScan brand impersonation
  it('13. URLScan detects brand impersonation in page title on non-official domain', async () => {
    process.env.URLSCAN_API_KEY = 'test-key-123';

    vi.spyOn(global, 'fetch').mockImplementation(async (url: any) => {
      const urlStr = String(url);
      if (urlStr.includes('/api/v1/scan/')) {
        return new Response(JSON.stringify({ uuid: 'brand-uuid-500' }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          page: { domain: 'secure-update-session-99.xyz', title: 'PayPal Account Verification' },
          verdicts: { overall: { score: 0 } },
        }),
        { status: 200 }
      );
    });

    const provider = new URLScanProvider();
    const result = await provider.analyze('https://secure-update-session-99.xyz');
    expect(result.metadata?.detectedBrand).toBe('PayPal');
    expect(result.evidence.some((e) => e.finding.includes("Brand impersonation detected: Page title 'PayPal Account Verification'"))).toBe(true);
  });

  // Test 14: ANY.RUN not configured
  it('14. ANY.RUN returns NOT_CONFIGURED when ANYRUN_API_KEY is missing', async () => {
    delete process.env.ANYRUN_API_KEY;
    const provider = new AnyRunProvider();
    expect(provider.isConfigured()).toBe(false);

    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('NOT_CONFIGURED');
  });

  // Test 15: ANY.RUN successful result
  it('15. ANY.RUN returns sandbox behavioral verdict when configured', async () => {
    process.env.ANYRUN_API_KEY = 'anyrun-key-999';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response(
        JSON.stringify({
          data: {
            taskid: 'anyrun-task-123',
            verdict: 'malicious',
            threat_level: 'critical',
          },
        }),
        { status: 200 }
      );
    });

    const provider = new AnyRunProvider();
    const result = await provider.analyze('https://malicious-sample.com');
    expect(result.status).toBe('FLAGGED');
    expect(result.isFlagged).toBe(true);
    expect(result.evidence.some((e) => e.finding.includes('ANY.RUN interactive sandbox flagged'))).toBe(true);
  });

  // Test 16: ANY.RUN timeout
  it('16. ANY.RUN handles abort timeout cleanly', async () => {
    process.env.ANYRUN_API_KEY = 'anyrun-key-999';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      const err = new Error('Aborted');
      err.name = 'AbortError';
      throw err;
    });

    const provider = new AnyRunProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('TIMEOUT');
  });

  // Test 17: ANY.RUN API error
  it('17. ANY.RUN handles HTTP error response safely', async () => {
    process.env.ANYRUN_API_KEY = 'anyrun-key-999';

    vi.spyOn(global, 'fetch').mockImplementation(async () => {
      return new Response('Unauthorized key', { status: 401 });
    });

    const provider = new AnyRunProvider();
    const result = await provider.analyze('https://example.com');
    expect(result.status).toBe('ERROR');
  });

  // Test 18: URLScan + PhishTank disagreement
  it('18. URLScan FLAGGED overrides PhishTank CLEAN', () => {
    const raw = 'https://fresh-phish.xyz/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const urlscanResult: ExternalAnalysisResult = {
      providerName: 'URLscan',
      status: 'FLAGGED',
      isFlagged: true,
      threatType: 'Phishing',
      evidence: [
        {
          source: 'URLscan',
          finding: 'urlscan.io explicit threat detection (Score: 100, Tags: phishing).',
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
      urlscanResult,
    });

    expect(res.verdict).toBe('CRITICAL');
    expect(res.explanation).toContain('URLscan');
    expect(res.summary).toContain('URLscan');
  });

  // Test 19: URLScan + URLhaus disagreement
  it('19. URLhaus FLAGGED overrides URLScan CLEAN', () => {
    const raw = 'https://malware-distributor.lol/';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const urlscanResult: ExternalAnalysisResult = {
      providerName: 'URLscan',
      status: 'CLEAN',
      isFlagged: false,
      evidence: [],
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'URLhaus', status: 'FLAGGED', isFlagged: true, threatType: 'Malware Host' }],
      urlscanResult,
    });

    expect(res.verdict).toBe('CRITICAL');
    expect(res.explanation).toContain('URLhaus');
    expect(res.summary).toContain('URLhaus');
  });

  // Test 20: Multiple providers + local heuristic correlation
  it('20. Multiple providers + local heuristic correlation produces CRITICAL verdict', () => {
    const raw = 'https://paypa1-update-security.com/login';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const urlscanResult: ExternalAnalysisResult = {
      providerName: 'URLscan',
      status: 'CLEAN',
      isFlagged: false,
      evidence: [],
      metadata: {
        detectedBrand: 'PayPal',
        hasPasswordField: true,
        crossDomainFormSubmission: true,
        formTargetDomain: 'evil-collector.com',
      },
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: benignDomain,
      domainRegIntel: newDomainReg,
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [
        { providerName: 'PhishTank', status: 'CLEAN', isFlagged: false },
        { providerName: 'Google Safe Browsing', status: 'NOT_CONFIGURED', isFlagged: false },
      ],
      urlscanResult,
    });

    expect(res.verdict).toBe('CRITICAL');
    expect(res.riskScore).toBeGreaterThanOrEqual(80);
    expect(res.evidence.some((e) => e.category === 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION')).toBe(true);
  });

  // Test 21: New phishing URL with zero threat-intel matches
  it('21. Brand new zero-day phishing URL with 0 threat intel matches produces HIGH/CRITICAL verdict', () => {
    const raw = 'https://microsoft-login-auth-verify.xyz/signin';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const urlscanResult: ExternalAnalysisResult = {
      providerName: 'URLscan',
      status: 'CLEAN',
      isFlagged: false,
      evidence: [],
      metadata: {
        hasPasswordField: true,
        crossDomainFormSubmission: true,
        formTargetDomain: 'data-stealer.xyz',
      },
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
        { providerName: 'VirusTotal', status: 'CLEAN', isFlagged: false },
      ],
      urlscanResult,
    });

    expect(['HIGH_RISK', 'CRITICAL']).toContain(res.verdict);
    expect(res.explanation).not.toContain('No threat intelligence matches were reported by PhishTank as main reason');
    expect(res.explanation).toContain('cross-domain');
  });

  // Test 22: Legitimate login page
  it('22. Legitimate login page (official brand domain) remains SAFE / LOW_RISK', () => {
    const raw = 'https://www.paypal.com/signin';
    const norm = sanitizeAndNormalizeUrl(raw).normalizedUrl;

    const urlscanResult: ExternalAnalysisResult = {
      providerName: 'URLscan',
      status: 'CLEAN',
      isFlagged: false,
      evidence: [],
      metadata: {
        pageTitle: 'Log in to your PayPal account',
        hasPasswordField: true,
        crossDomainFormSubmission: false,
      },
    };

    const res = calculateRiskScore({
      urlFeatures: extractUrlFeatures(raw, norm),
      domainIntel: { ...benignDomain, domain: 'paypal.com' },
      sslIntel: benignSsl,
      redirectIntel: benignRedirect,
      threatIntel: [{ providerName: 'PhishTank', status: 'CLEAN', isFlagged: false }],
      urlscanResult,
    });

    expect(res.verdict).toBe('SAFE');
    expect(res.riskScore).toBeLessThan(35);
  });
});
