import {
  ExternalAnalysisProvider,
  ExternalAnalysisResult,
  ExternalAnalysisStatus,
  EvidenceItem,
} from '@/types/security';

export class UrlscansProvider implements ExternalAnalysisProvider {
  public readonly name = 'URLScans';

  public isConfigured(): boolean {
    return Boolean(process.env.URLSCANS_API_KEY && process.env.URLSCANS_API_KEY.trim().length > 0);
  }

  public async analyze(url: string): Promise<ExternalAnalysisResult> {
    if (!this.isConfigured()) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'URLSCANS_API_KEY is not configured on server deployment.',
        evidence: [
          {
            source: this.name,
            finding: 'URLScans API key is not configured.',
            impact: 'CONFIDENCE_REDUCTION',
            actual: true,
            category: 'EXTERNAL_ANALYSIS',
          },
        ],
      };
    }

    const apiKey = process.env.URLSCANS_API_KEY!.trim();

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);

      const endpoint = `https://urlscans.com/api/scan?url=${encodeURIComponent(url)}`;
      const resp = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'X-API-Key': apiKey,
          'Accept': 'application/json',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.status === 401 || resp.status === 403) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `URLScans API authorization failed (HTTP ${resp.status}).`,
          evidence: [],
        };
      }

      if (resp.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'URLScans API rate limit exceeded (HTTP 429).',
          evidence: [
            {
              source: this.name,
              finding: 'URLScans API rate limit exceeded.',
              impact: 'CONFIDENCE_REDUCTION',
              actual: true,
              category: 'EXTERNAL_ANALYSIS',
            },
          ],
        };
      }

      if (!resp.ok) {
        const errText = await resp.text().catch(() => '');
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `URLScans scan error (HTTP ${resp.status}): ${errText.substring(0, 100)}`,
          evidence: [],
        };
      }

      const data = await resp.json().catch(() => null);
      if (!data) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: 'URLScans returned malformed JSON response.',
          evidence: [],
        };
      }

      return this.parseResult(data);
    } catch (err: unknown) {
      const isAbort = err instanceof Error && err.name === 'AbortError';
      const status: ExternalAnalysisStatus = isAbort ? 'TIMEOUT' : 'UNAVAILABLE';
      return {
        providerName: this.name,
        status,
        isFlagged: false,
        details: isAbort ? 'URLScans request timed out.' : (err instanceof Error ? err.message : 'URLScans provider failure'),
        evidence: [],
      };
    }
  }

  private parseResult(data: Record<string, unknown>): ExternalAnalysisResult {
    const evidence: EvidenceItem[] = [];
    const isPhishing = Boolean(data.isPhishing || data.phishing || data.is_phishing);
    const isMalware = Boolean(data.isMalware || data.malware || data.is_malware);
    const riskScore = Number(data.riskScore || data.risk_score || data.score || 0);

    const isFlagged = isPhishing || isMalware || riskScore >= 70;
    const status: ExternalAnalysisStatus = isFlagged ? 'FLAGGED' : 'CLEAN';

    if (isFlagged) {
      evidence.push({
        source: this.name,
        finding: `URLScans flagged URL (Phishing: ${isPhishing}, Malware: ${isMalware}, Risk Score: ${riskScore}).`,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    } else {
      evidence.push({
        source: this.name,
        finding: `URLScans dynamic lookup completed with zero threat detections (Score: ${riskScore}).`,
        impact: 'NEUTRAL',
        actual: true,
        category: 'EXTERNAL_ANALYSIS',
      });
    }

    const categories = Array.isArray(data.categories) ? (data.categories as string[]) : [];
    const spfValid = data.spfValid !== undefined ? Boolean(data.spfValid) : undefined;
    const dmarcValid = data.dmarcValid !== undefined ? Boolean(data.dmarcValid) : undefined;

    return {
      providerName: this.name,
      status,
      isFlagged,
      threatType: isFlagged ? 'URLScans Threat Detection' : undefined,
      scanUuid: data.id ? String(data.id) : undefined,
      resultUrl: data.reportUrl ? String(data.reportUrl) : undefined,
      evidence,
      metadata: {
        providerRiskScore: riskScore,
        categories,
        spfValid,
        dmarcValid,
      },
    };
  }
}
