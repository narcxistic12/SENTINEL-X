import { ThreatIntelResult, ThreatIntelStatus } from '@/types/security';

export interface ThreatIntelProvider {
  name: string;
  isConfigured(): boolean;
  check(url: string, hostname?: string): Promise<ThreatIntelResult>;
}

function isPhishtankTrue(val: unknown): boolean {
  if (val === true || val === 1) return true;
  if (typeof val === 'string') {
    const lower = val.toLowerCase().trim();
    return lower === 'y' || lower === 'yes' || lower === 'true' || lower === '1';
  }
  return false;
}

/**
 * Google Safe Browsing API v4 Provider
 */
export class GoogleSafeBrowsingProvider implements ThreatIntelProvider {
  public name = 'Google Safe Browsing';

  public isConfigured(): boolean {
    return Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY);
  }

  public async check(url: string): Promise<ThreatIntelResult> {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'Provider not configured (Requires GOOGLE_SAFE_BROWSING_API_KEY).',
      };
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
      const payload = {
        client: {
          clientId: 'sentinelx',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (res.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'Google Safe Browsing API rate limit exceeded.',
        };
      }

      if (!res.ok) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `Google Safe Browsing HTTP ${res.status}`,
        };
      }

      const data = await res.json();
      const matches = data.matches || [];

      if (matches.length > 0) {
        const threatType = matches[0].threatType;
        return {
          providerName: this.name,
          status: 'FLAGGED',
          isFlagged: true,
          threatType,
          details: `Identified as malicious threat: ${threatType}`,
          lastChecked: new Date().toISOString(),
        };
      }

      return {
        providerName: this.name,
        status: 'CLEAN',
        isFlagged: false,
        details: 'No known malicious patterns found in Google Safe Browsing database.',
        lastChecked: new Date().toISOString(),
      };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return {
          providerName: this.name,
          status: 'TIMEOUT',
          isFlagged: false,
          details: 'Google Safe Browsing request timed out (4s).',
        };
      }
      return {
        providerName: this.name,
        status: 'UNAVAILABLE',
        isFlagged: false,
        details: err instanceof Error ? err.message : 'Lookup failed',
      };
    }
  }
}

/**
 * VirusTotal API v3 Provider
 */
export class VirusTotalProvider implements ThreatIntelProvider {
  public name = 'VirusTotal';

  public isConfigured(): boolean {
    return Boolean(process.env.VIRUSTOTAL_API_KEY);
  }

  public async check(url: string): Promise<ThreatIntelResult> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'Provider not configured (Requires VIRUSTOTAL_API_KEY).',
      };
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      // VirusTotal URL identifier is base64url representation without padding
      const urlId = Buffer.from(url).toString('base64url').replace(/=/g, '');
      const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

      const res = await fetch(endpoint, {
        headers: { 'x-apikey': apiKey },
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (res.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'VirusTotal API rate limit exceeded.',
        };
      }

      if (res.status === 404) {
        return {
          providerName: this.name,
          status: 'CLEAN',
          isFlagged: false,
          details: 'URL has no malicious history reported in VirusTotal dataset.',
          lastChecked: new Date().toISOString(),
          stats: {
            maliciousEngineCount: 0,
            suspiciousEngineCount: 0,
            harmlessEngineCount: 0,
            undetectedEngineCount: 0,
            totalEngineCount: 0,
          },
        };
      }

      if (!res.ok) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `VirusTotal HTTP ${res.status}`,
        };
      }

      const data = await res.json();
      const rawStats = data.data?.attributes?.last_analysis_stats || {};
      const malicious = rawStats.malicious || 0;
      const suspicious = rawStats.suspicious || 0;
      const harmless = rawStats.harmless || 0;
      const undetected = rawStats.undetected || 0;
      const total = malicious + suspicious + harmless + undetected;

      const vtStats = {
        maliciousEngineCount: malicious,
        suspiciousEngineCount: suspicious,
        harmlessEngineCount: harmless,
        undetectedEngineCount: undetected,
        totalEngineCount: total,
      };

      if (malicious > 0 || suspicious > 1) {
        return {
          providerName: this.name,
          status: 'FLAGGED',
          isFlagged: true,
          threatType: 'Malicious / Suspicious (VirusTotal)',
          details: `Flagged by ${malicious} security vendor(s) out of ${total} engines on VirusTotal.`,
          lastChecked: new Date().toISOString(),
          stats: vtStats,
        };
      }

      return {
        providerName: this.name,
        status: 'CLEAN',
        isFlagged: false,
        details: `Clean analysis: 0 malicious vendor detections out of ${total} engines.`,
        lastChecked: new Date().toISOString(),
        stats: vtStats,
      };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return {
          providerName: this.name,
          status: 'TIMEOUT',
          isFlagged: false,
          details: 'VirusTotal API request timed out (4s).',
        };
      }
      return {
        providerName: this.name,
        status: 'UNAVAILABLE',
        isFlagged: false,
        details: err instanceof Error ? err.message : 'Lookup failed',
      };
    }
  }
}

/**
 * URLhaus Open Threat Intelligence Provider (abuse.ch)
 */
export class UrlhausProvider implements ThreatIntelProvider {
  public name = 'abuse.ch URLhaus';

  public isConfigured(): boolean {
    return Boolean(process.env.URLHAUS_API_KEY);
  }

  public async check(url: string): Promise<ThreatIntelResult> {
    const apiKey = process.env.URLHAUS_API_KEY;
    if (!apiKey) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'Provider not configured (Requires URLHAUS_API_KEY).',
      };
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);

      const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'phishtank/sentinelx',
          'Auth-Key': apiKey,
        },
        body: new URLSearchParams({ url }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (res.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'URLhaus API rate limit exceeded.',
        };
      }

      if (!res.ok) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `URLhaus API returned HTTP ${res.status}`,
        };
      }

      const data = await res.json();

      if (data.query_status === 'ok') {
        return {
          providerName: this.name,
          status: 'FLAGGED',
          isFlagged: true,
          threatType: data.threat || 'Malware / Phishing Distribution',
          details: `Active URLhaus listing: ${data.url_status || 'online'} (${data.threat || 'malicious'})`,
          lastChecked: new Date().toISOString(),
        };
      }

      if (data.query_status === 'no_results') {
        return {
          providerName: this.name,
          status: 'CLEAN',
          isFlagged: false,
          details: 'No records found in active URLhaus malware & phishing dataset.',
          lastChecked: new Date().toISOString(),
        };
      }

      return {
        providerName: this.name,
        status: 'CHECKED',
        isFlagged: false,
        details: `Query status: ${data.query_status}`,
        lastChecked: new Date().toISOString(),
      };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return {
          providerName: this.name,
          status: 'TIMEOUT',
          isFlagged: false,
          details: 'URLhaus API request timed out (3.5s limit).',
        };
      }
      return {
        providerName: this.name,
        status: 'UNAVAILABLE',
        isFlagged: false,
        details: 'Service temporarily unreachable.',
      };
    }
  }
}

/**
 * PhishTank Provider
 */
export class PhishTankProvider implements ThreatIntelProvider {
  public name = 'PhishTank';

  public isConfigured(): boolean {
    return true;
  }

  public async check(url: string): Promise<ThreatIntelResult> {
    const apiKey = process.env.PHISHTANK_API_KEY;

    // Build targeted lookup variants
    const candidates: string[] = [url];
    const rawNoSlash = url.replace(/\/$/, '');
    if (rawNoSlash !== url) candidates.push(rawNoSlash);

    if (url.startsWith('https://')) {
      const httpVariant = url.replace(/^https:\/\//i, 'http://').replace(/\/$/, '');
      candidates.push(httpVariant);
    } else if (url.startsWith('http://')) {
      const httpsVariant = url.replace(/^http:\/\//i, 'https://').replace(/\/$/, '');
      candidates.push(httpsVariant);
    }

    const uniqueCandidates = Array.from(new Set(candidates));

    let hasHttpError = false;
    let hasRateLimit = false;
    let lastErrorDetails = '';
    let hasSuccessfulCleanCheck = false;

    try {
      for (let i = 0; i < uniqueCandidates.length; i++) {
        const targetUrl = uniqueCandidates[i];

        if (i > 0) {
          await new Promise((resolve) => setTimeout(resolve, 200));
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);

        const bodyParams: Record<string, string> = {
          url: targetUrl,
          format: 'json',
        };
        if (apiKey) {
          bodyParams.app_key = apiKey;
        }

        const res = await fetch('https://checkurl.phishtank.com/checkurl/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'phishtank/sentinelx',
            'Accept': 'application/json, text/plain, */*',
          },
          body: new URLSearchParams(bodyParams),
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (res.status === 429) {
          hasRateLimit = true;
          lastErrorDetails = 'PhishTank rate limit exceeded';
          continue;
        }

        if (!res.ok) {
          hasHttpError = true;
          lastErrorDetails = `PhishTank HTTP ${res.status}`;
          continue;
        }

        let data: any;
        try {
          data = await res.json();
        } catch {
          hasHttpError = true;
          lastErrorDetails = 'Invalid JSON response';
          continue;
        }

        const results = data?.results;
        if (!results) {
          hasHttpError = true;
          lastErrorDetails = 'PhishTank response missing results payload';
          continue;
        }

        hasSuccessfulCleanCheck = true;
        const inDb = isPhishtankTrue(results.in_database);
        const isValid = isPhishtankTrue(results.valid);
        const isVerified = isPhishtankTrue(results.verified);

        const isPhish = inDb && isVerified && isValid;

        if (isPhish) {
          const phishId = results.phish_id ? String(results.phish_id) : undefined;
          return {
            providerName: this.name,
            status: 'FLAGGED',
            isFlagged: true,
            threatType: 'Confirmed Phishing (PhishTank)',
            details: `PhishTank database verified this URL as a phishing threat${phishId ? ` (ID: ${phishId})` : ''}`,
            lastChecked: new Date().toISOString(),
          };
        }
      }

      if (hasSuccessfulCleanCheck) {
        return {
          providerName: this.name,
          status: 'CLEAN',
          isFlagged: false,
          details: 'No records found in PhishTank active phishing database.',
          lastChecked: new Date().toISOString(),
        };
      }

      if (hasRateLimit) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'PhishTank API rate limit exceeded.',
        };
      }

      if (hasHttpError) {
        return {
          providerName: this.name,
          status: 'UNAVAILABLE',
          isFlagged: false,
          details: `PhishTank lookup failed (${lastErrorDetails}).`,
        };
      }

      return {
        providerName: this.name,
        status: 'CLEAN',
        isFlagged: false,
        details: 'No threat detections reported.',
        lastChecked: new Date().toISOString(),
      };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return {
          providerName: this.name,
          status: 'TIMEOUT',
          isFlagged: false,
          details: 'PhishTank API request timed out (4s).',
        };
      }
      return {
        providerName: this.name,
        status: 'UNAVAILABLE',
        isFlagged: false,
        details: err instanceof Error ? err.message : 'Lookup failed',
      };
    }
  }
}

/**
 * Aggregate runner for all threat intelligence providers.
 * Evaluates all URLs in redirect chain and preserves explicit status per provider.
 */
export async function runThreatIntelligenceChecks(
  urls: string[]
): Promise<ThreatIntelResult[]> {
  const providers: ThreatIntelProvider[] = [
    new UrlhausProvider(),
    new GoogleSafeBrowsingProvider(),
    new VirusTotalProvider(),
    new PhishTankProvider(),
  ];

  const results = await Promise.all(
    providers.map(async (provider): Promise<ThreatIntelResult> => {
      let candidateCleanResult: ThreatIntelResult | null = null;
      let hasError = false;
      let hasTimeout = false;
      let hasRateLimit = false;
      let errorDetails = '';

      for (const url of urls) {
        let hostname = 'unknown';
        try {
          hostname = new URL(url).hostname;
        } catch {
          // ignore
        }

        const res = await provider.check(url, hostname);

        if (res.status === 'FLAGGED') {
          return res;
        } else if (res.status === 'NOT_CONFIGURED') {
          return res;
        } else if (res.status === 'TIMEOUT') {
          hasTimeout = true;
          errorDetails = res.details || 'Timeout';
        } else if (res.status === 'RATE_LIMITED') {
          hasRateLimit = true;
          errorDetails = res.details || 'Rate limit exceeded';
        } else if (res.status === 'ERROR' || res.status === 'UNAVAILABLE') {
          hasError = true;
          errorDetails = res.details || 'Error';
        } else if (res.status === 'CLEAN') {
          if (!candidateCleanResult) {
            candidateCleanResult = res;
          }
        }
      }

      if (candidateCleanResult) {
        return candidateCleanResult;
      }
      if (hasRateLimit) {
        return {
          providerName: provider.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: errorDetails || 'Rate limit exceeded',
        };
      }
      if (hasTimeout) {
        return {
          providerName: provider.name,
          status: 'TIMEOUT',
          isFlagged: false,
          details: errorDetails || 'Timeout',
        };
      }
      if (hasError) {
        return {
          providerName: provider.name,
          status: 'ERROR',
          isFlagged: false,
          details: errorDetails || 'Lookup error',
        };
      }

      return {
        providerName: provider.name,
        status: 'UNAVAILABLE',
        isFlagged: false,
        details: 'No result available.',
      };
    })
  );

  return results;
}

