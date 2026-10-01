import {
  ExternalAnalysisProvider,
  ExternalAnalysisResult,
  ExternalAnalysisStatus,
  EvidenceItem,
} from '@/types/security';

interface FreshScanCacheEntry {
  result: ExternalAnalysisResult;
  timestamp: number;
}

const freshScanCache = new Map<string, FreshScanCacheEntry>();

export class VirusTotalFreshProvider implements ExternalAnalysisProvider {
  public readonly name = 'VirusTotal Fresh Analysis';

  public isConfigured(): boolean {
    return Boolean(process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY.trim().length > 0);
  }

  public async analyze(url: string): Promise<ExternalAnalysisResult> {
    if (!this.isConfigured()) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'VIRUSTOTAL_API_KEY is not configured.',
        evidence: [
          {
            source: this.name,
            finding: 'VirusTotal Fresh Analysis API key is not configured.',
            impact: 'CONFIDENCE_REDUCTION',
            actual: true,
            category: 'EXTERNAL_ANALYSIS',
          },
        ],
      };
    }

    const ttlMinutes = parseInt(process.env.VIRUSTOTAL_FRESH_SCAN_TTL_MINUTES || '30', 10);
    const ttlMs = ttlMinutes * 60 * 1000;
    const now = Date.now();

    // Check cache deduplication
    const cached = freshScanCache.get(url);
    if (cached && now - cached.timestamp < ttlMs) {
      return cached.result;
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY!.trim();

    try {
      // Step 1: Submit URL to VirusTotal v3 for fresh analysis
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);

      const resp = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ url }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'VirusTotal API rate limit exceeded.',
          evidence: [],
        };
      }

      if (!resp.ok) {
        const errText = await resp.text().catch(() => '');
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `VirusTotal URL submission error (HTTP ${resp.status}): ${errText.substring(0, 100)}`,
          evidence: [],
        };
      }

      const data = await resp.json().catch(() => null);
      const analysisId = data?.data?.id;

      if (!analysisId) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: 'VirusTotal fresh submission returned missing analysis ID.',
          evidence: [],
        };
      }

      // Step 2: Poll analysis status (up to 3 retries)
      const freshResult = await this.pollAnalysis(analysisId, apiKey, url);

      // Cache result if valid
      if (freshResult.status === 'CLEAN' || freshResult.status === 'FLAGGED') {
        freshScanCache.set(url, { result: freshResult, timestamp: now });
      }

      return freshResult;
    } catch (err: unknown) {
      const isAbort = err instanceof Error && err.name === 'AbortError';
      const status: ExternalAnalysisStatus = isAbort ? 'TIMEOUT' : 'UNAVAILABLE';
      return {
        providerName: this.name,
        status,
        isFlagged: false,
        details: isAbort ? 'VirusTotal fresh analysis request timed out.' : (err instanceof Error ? err.message : 'VirusTotal fresh analysis error'),
        evidence: [],
      };
    }
  }

  private async pollAnalysis(analysisId: string, apiKey: string, originalUrl: string): Promise<ExternalAnalysisResult> {
    const delay = process.env.NODE_ENV === 'test' || process.env.VITEST ? 5 : 1200;
    const maxAttempts = 3;

    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, delay));
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);

        const resp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          method: 'GET',
          headers: { 'x-apikey': apiKey },
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (resp.status === 200) {
          const data = await resp.json().catch(() => null);
          const attributes = data?.data?.attributes || {};
          const statusStr = String(attributes.status || '').toLowerCase();

          if (statusStr === 'completed') {
            const stats = attributes.stats || {};
            const malicious = Number(stats.malicious || 0);
            const suspicious = Number(stats.suspicious || 0);
            const total = Number(stats.malicious || 0) + Number(stats.suspicious || 0) + Number(stats.harmless || 0) + Number(stats.undetected || 0);

            const isFlagged = malicious > 0 || suspicious > 1;
            const status: ExternalAnalysisStatus = isFlagged ? 'FLAGGED' : 'CLEAN';

            const evidence: EvidenceItem[] = [];
            if (isFlagged) {
              evidence.push({
                source: this.name,
                finding: `VirusTotal fresh analysis completed: ${malicious} malicious detection(s) out of ${total} engines.`,
                impact: 'HIGH_RISK',
                actual: true,
                category: 'THREAT_INTELLIGENCE',
              });
            } else {
              evidence.push({
                source: this.name,
                finding: `VirusTotal fresh analysis completed with 0 malicious detections out of ${total} engines.`,
                impact: 'NEUTRAL',
                actual: true,
                category: 'EXTERNAL_ANALYSIS',
              });
            }

            return {
              providerName: this.name,
              status,
              isFlagged,
              threatType: isFlagged ? 'Fresh Threat Analysis' : undefined,
              scanUuid: analysisId,
              evidence,
              metadata: {
                maliciousEngineCount: malicious,
                totalEngineCount: total,
                freshScanTimestamp: new Date().toISOString(),
              },
            };
          }
        }
      } catch {
        // Retry loop
      }
    }

    return {
      providerName: this.name,
      status: 'PENDING',
      isFlagged: false,
      scanUuid: analysisId,
      details: 'VirusTotal fresh re-analysis request submitted, processing is pending on VirusTotal engines.',
      evidence: [
        {
          source: this.name,
          finding: `VirusTotal fresh URL re-analysis submitted (ID: ${analysisId}), result pending.`,
          impact: 'CONFIDENCE_REDUCTION',
          actual: true,
          category: 'EXTERNAL_ANALYSIS',
        },
      ],
    };
  }
}
