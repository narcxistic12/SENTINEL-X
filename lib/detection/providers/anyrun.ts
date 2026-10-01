import {
  ExternalAnalysisProvider,
  ExternalAnalysisResult,
  ExternalAnalysisStatus,
  EvidenceItem,
} from '@/types/security';

export class AnyRunProvider implements ExternalAnalysisProvider {
  public readonly name = 'ANY.RUN';

  public isConfigured(): boolean {
    return Boolean(process.env.ANYRUN_API_KEY && process.env.ANYRUN_API_KEY.trim().length > 0);
  }

  public async analyze(url: string): Promise<ExternalAnalysisResult> {
    if (!this.isConfigured()) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'ANYRUN_API_KEY is not configured on server deployment.',
        evidence: [
          {
            source: this.name,
            finding: 'ANY.RUN API key is not configured.',
            impact: 'CONFIDENCE_REDUCTION',
            actual: true,
            category: 'EXTERNAL_ANALYSIS',
          },
        ],
      };
    }

    const apiKey = process.env.ANYRUN_API_KEY!.trim();

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);

      // Official ANY.RUN task submission endpoint
      const resp = await fetch('https://api.any.run/v1/user/task', {
        method: 'POST',
        headers: {
          Authorization: `API-Key ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          obj_type: 'url',
          obj_url: url,
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'ANY.RUN API rate limit exceeded (HTTP 429).',
          evidence: [],
        };
      }

      if (!resp.ok) {
        const errorText = await resp.text().catch(() => '');
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `ANY.RUN API error (HTTP ${resp.status}): ${errorText.substring(0, 100)}`,
          evidence: [],
        };
      }

      const data = await resp.json().catch(() => null);
      if (!data || data.error) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `ANY.RUN returned error: ${data?.msg || 'Malformed response'}`,
          evidence: [],
        };
      }

      // Check verdict or task status if returned immediately
      const taskData = data.data || data;
      const verdict = String(taskData.verdict || taskData.threat_level || '').toLowerCase();
      const isFlagged = verdict.includes('malicious') || verdict.includes('phishing') || verdict.includes('suspicious');
      const status: ExternalAnalysisStatus = isFlagged ? 'FLAGGED' : 'CLEAN';

      const evidence: EvidenceItem[] = [];
      if (isFlagged) {
        evidence.push({
          source: this.name,
          finding: `ANY.RUN interactive sandbox flagged URL behavior as ${verdict.toUpperCase()}.`,
          impact: 'HIGH_RISK',
          actual: true,
          category: 'BEHAVIOR',
        });
      } else {
        evidence.push({
          source: this.name,
          finding: 'ANY.RUN sandbox analysis completed without detecting malicious behavior.',
          impact: 'NEUTRAL',
          actual: true,
          category: 'EXTERNAL_ANALYSIS',
        });
      }

      return {
        providerName: this.name,
        status,
        isFlagged,
        threatType: isFlagged ? 'Sandbox Behavioral Threat' : undefined,
        scanUuid: taskData.taskid || taskData.uuid,
        evidence,
        metadata: {
          verdict,
        },
      };
    } catch (err: unknown) {
      const isAbort = err instanceof Error && err.name === 'AbortError';
      const status: ExternalAnalysisStatus = isAbort ? 'TIMEOUT' : 'UNAVAILABLE';
      return {
        providerName: this.name,
        status,
        isFlagged: false,
        details: isAbort ? 'ANY.RUN request timed out.' : (err instanceof Error ? err.message : 'ANY.RUN provider failure'),
        evidence: [],
      };
    }
  }
}
